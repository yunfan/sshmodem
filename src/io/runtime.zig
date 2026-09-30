//! POSIX 运行时（链接 libc）：把通用 Tunnel + socks5 报文层接到真实 fd 上。
//! 单线程 poll(2) 循环（决策 D10）。两种模式：
//!   - local：本地起 SOCKS5 监听，拉起 ssh 传输，作 Tunnel client。
//!   - serve：远端用 stdin/stdout 作传输，作 Tunnel server，按需 connect 目标。
//!
//! sans-io 的 Tunnel/ socks5 不在这里；这里只搬字节、管 fd、做背压。

const std = @import("std");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const net = @import("net.zig");
const child = @import("child.zig");
const smodem = @import("smodem");
const Tunnel = smodem.Tunnel;
const socks5 = smodem.socks5.wire;
const address = smodem.codec.address;

const POLLIN = posix.POLL.IN;
const POLLOUT = posix.POLL.OUT;

fn nowMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}

pub const Mode = enum { local, serve };

/// 静态 UDP 端口转发（协议 §9 之上）：本地 local_port 的 UDP 全部经隧道
/// 送到服务端解析并发往固定的 host:port。类似 ssh -L 但走 UDP、目标固定。
pub const UdpForward = struct {
    local_port: u16,
    host: []const u8, // IPv4 或域名（域名在服务端解析）
    port: u16,
};

pub const Config = struct {
    mode: Mode = .local,
    listen_ip: [4]u8 = .{ 127, 0, 0, 1 },
    listen_port: u16 = 1080,
    /// 传输命令 argv（local 模式）。默认由 CLI 拼 "ssh -T <target> smodem serve"。
    transport_argv: []const [:0]const u8 = &.{},
    tunnel: smodem.tunnel.Config = .{},
    udp_forwards: []const UdpForward = &.{},
    verbose: bool = true,
};

pub const RunError = error{ SetupFailed, TransportFailed } || net.IoError || Allocator.Error || smodem.tunnel.Error;

const ConnPhase = enum { greeting, request, awaiting, connecting, piping, closing, udp_control };

/// 一个 UDP 关联（协议 §9）。local：relay socket + curl 的 UDP 源；
/// serve：连目标的 UDP socket。生命周期绑到 TCP 控制流（local 由 ctrl 关闭触发）。
const UdpAssoc = struct {
    stream_id: u32,
    fd: net.fd_t,
    ctrl: ?*Conn = null, // local：TCP 控制连接
    peer_set: bool = false, // local：是否已学到 curl 的 UDP 源
    peer_ip: [4]u8 = .{ 0, 0, 0, 0 },
    peer_port: u16 = 0,
    open: bool = false, // 隧道数据报通道是否已被对端接受
    pending: std.ArrayList(u8) = .empty, // 通道就绪前暂存（[u16 len][payload]…）
};

/// 一条静态 UDP 转发的本地监听（跨重连保持，由 runLocal 拥有）。
const Forward = struct {
    fd: net.fd_t, // 绑定 127.0.0.1:local_port 的 UDP socket
    local_port: u16,
    addr_block: [262]u8 = undefined, // 目标 ATYP+ADDR+PORT
    addr_len: usize,
};

/// 某个客户端源在某条转发上的数据报关联（每会话；idle 超时回收）。
const FwdAssoc = struct {
    stream_id: u32,
    fwd: *Forward,
    cli_ip: [4]u8,
    cli_port: u16,
    last_ms: i64,
    open: bool = false, // 隧道数据报通道是否已被对端接受
    pending: std.ArrayList(u8) = .empty, // 通道就绪前暂存的载荷（[u16 len][payload]…）
};

const Conn = struct {
    fd: net.fd_t,
    stream_id: u32 = 0,
    phase: ConnPhase,
    hs_buf: [1024]u8 = undefined,
    hs_len: usize = 0,
    t2s: std.ArrayList(u8) = .empty, // 待写给 socket 的字节（tunnel→socket 或握手应答）
    s2t: std.ArrayList(u8) = .empty, // 从 socket 读到但隧道尚未接受的字节（背压暂存）
    want_read: bool = true, // 是否还想从 socket 读（背压时关掉）
    sock_eof: bool = false,
    dead: bool = false,

    fn deinit(self: *Conn, alloc: Allocator) void {
        self.t2s.deinit(alloc);
        self.s2t.deinit(alloc);
    }
};

const Runtime = struct {
    alloc: Allocator,
    cfg: Config,
    tunnel: Tunnel,
    wire_in: net.fd_t,
    wire_out: net.fd_t,
    listen_fd: ?net.fd_t = null,
    wire_obuf: std.ArrayList(u8) = .empty, // tunnel.send 出来但还没写进 wire 的字节
    conns: std.ArrayList(*Conn) = .empty,
    by_stream: std.AutoHashMap(u32, *Conn),
    udp: std.ArrayList(*UdpAssoc) = .empty,
    udp_by_stream: std.AutoHashMap(u32, *UdpAssoc),
    forwards: []Forward = &.{}, // 跨重连保持，由 runLocal 拥有
    fwd_assocs: std.ArrayList(*FwdAssoc) = .empty,
    fwd_by_stream: std.AutoHashMap(u32, *FwdAssoc),
    io_buf: [65536]u8 = undefined,
    running: bool = true,
    ever_ready: bool = false, // 本次会话是否握手成功过（用于重连退避）

    fn log(self: *Runtime, comptime fmt: []const u8, args: anytype) void {
        if (self.cfg.verbose) std.debug.print("smodem: " ++ fmt ++ "\n", args);
    }

    fn addConn(self: *Runtime, conn: *Conn) !void {
        try self.conns.append(self.alloc, conn);
    }

    fn dropConn(self: *Runtime, conn: *Conn) void {
        if (conn.stream_id != 0) _ = self.by_stream.remove(conn.stream_id);
        net.close(conn.fd);
        for (self.conns.items, 0..) |cptr, i| {
            if (cptr == conn) {
                _ = self.conns.swapRemove(i);
                break;
            }
        }
        conn.deinit(self.alloc);
        self.alloc.destroy(conn);
    }

    // 把 tunnel 要发的字节抽到 wire_obuf。
    fn pumpTunnelOut(self: *Runtime) !void {
        while (true) {
            const n = self.tunnel.send(&self.io_buf);
            if (n == 0) break;
            try self.wire_obuf.appendSlice(self.alloc, self.io_buf[0..n]);
        }
    }

    fn flushWire(self: *Runtime) void {
        if (self.wire_obuf.items.len == 0) return;
        switch (net.writeFd(self.wire_out, self.wire_obuf.items)) {
            .n => |w| {
                if (w > 0) {
                    const rem = self.wire_obuf.items.len - w;
                    if (rem > 0) std.mem.copyForwards(u8, self.wire_obuf.items[0..rem], self.wire_obuf.items[w..]);
                    self.wire_obuf.shrinkRetainingCapacity(rem);
                }
            },
            .again => {},
            .eof, .err => self.running = false,
        }
    }

    fn queueToSock(self: *Runtime, conn: *Conn, bytes: []const u8) !void {
        try conn.t2s.appendSlice(self.alloc, bytes);
    }

    fn flushSock(self: *Runtime, conn: *Conn) void {
        if (conn.t2s.items.len == 0) return;
        switch (net.writeFd(conn.fd, conn.t2s.items)) {
            .n => |w| {
                if (w > 0) {
                    const rem = conn.t2s.items.len - w;
                    if (rem > 0) std.mem.copyForwards(u8, conn.t2s.items[0..rem], conn.t2s.items[w..]);
                    conn.t2s.shrinkRetainingCapacity(rem);
                    if (conn.phase == .piping and conn.stream_id != 0) {
                        self.tunnel.consume(conn.stream_id, @intCast(w)) catch {};
                    }
                }
            },
            .again => {},
            .eof, .err => conn.dead = true,
        }
    }
};

// ===================== 处理隧道事件 =====================

fn handleTunnelEvents(rt: *Runtime) !void {
    while (rt.tunnel.nextEvent()) |ev| switch (ev) {
        .ready => {
            rt.ever_ready = true;
            rt.log("ready (send={s} recv={s})", .{ @tagName(rt.tunnel.txEncoding()), @tagName(rt.tunnel.rxEncoding()) });
        },
        .log => |l| if (rt.cfg.verbose) rt.log("[{s}] {s}", .{ @tagName(l.level), l.msg }),
        .stream_open => |x| try onStreamOpen(rt, x.id, x.metadata), // serve 侧：对端要开流
        .stream_accept => |x| try onStreamAccept(rt, x.id), // local 侧：远端接受了 CONNECT
        .stream_reject => |x| try onStreamReject(rt, x.id, x.code),
        .stream_data => |x| try onStreamData(rt, x.id, x.bytes),
        .stream_writable => {}, // 背压恢复：下一轮 poll 会重新尝试读 socket
        .stream_eof => |id| try onStreamEof(rt, id),
        .stream_reset => |x| onStreamReset(rt, x.id),
        .datagram_open => |x| try onDatagramOpen(rt, x.id, x.metadata), // serve 侧：对端要开 UDP 关联
        .datagram_accept => |x| try onDatagramAccept(rt, x.id, x.metadata), // local 侧：远端已绑 UDP
        .datagram_reject => |x| onDatagramReject(rt, x.id, x.code),
        .datagram => |x| try onDatagram(rt, x.id, x.payload),
        .closed => rt.running = false,
    };
}

fn connByStream(rt: *Runtime, id: u32) ?*Conn {
    return rt.by_stream.get(id);
}

// serve 侧：对端开流，metadata 是地址块 → 解析 → connect 目标。
fn onStreamOpen(rt: *Runtime, id: u32, metadata: []const u8) !void {
    const dec = address.decode(metadata) catch {
        try rt.tunnel.reject(id, @intFromEnum(socks5.Rep.general));
        return;
    };
    var ip4: [4]u8 = undefined;
    switch (dec.addr.host) {
        .ipv4 => |a| ip4 = a,
        .domain => |d| {
            var hostbuf: [256]u8 = undefined;
            if (d.len >= hostbuf.len) {
                try rt.tunnel.reject(id, @intFromEnum(socks5.Rep.general));
                return;
            }
            @memcpy(hostbuf[0..d.len], d);
            hostbuf[d.len] = 0;
            ip4 = net.resolve4(hostbuf[0..d.len :0], dec.addr.port) catch {
                try rt.tunnel.reject(id, @intFromEnum(socks5.Rep.host_unreach));
                return;
            };
        },
        .ipv6 => {
            try rt.tunnel.reject(id, @intFromEnum(socks5.Rep.atyp_unsupported));
            return;
        },
    }
    const cr = net.connectTcp4(ip4, dec.addr.port) catch {
        try rt.tunnel.reject(id, @intFromEnum(socks5.Rep.general));
        return;
    };
    const fd = switch (cr) {
        .fd => |f| f,
        .failed => |e| {
            try rt.tunnel.reject(id, @intFromEnum(mapErrno(e)));
            return;
        },
    };
    const conn = try rt.alloc.create(Conn);
    conn.* = .{ .fd = fd, .stream_id = id, .phase = .connecting };
    try rt.addConn(conn);
    try rt.by_stream.put(id, conn);
}

// local 侧：远端接受了 CONNECT → 给浏览器回 SOCKS5 成功。
fn onStreamAccept(rt: *Runtime, id: u32) !void {
    const conn = connByStream(rt, id) orelse return;
    var rep: [32]u8 = undefined;
    const n = socks5.buildReply(&rep, .success, socks5.null_bind);
    try rt.queueToSock(conn, rep[0..n]);
    conn.phase = .piping;
}

fn onStreamReject(rt: *Runtime, id: u32, code: u8) !void {
    const conn = connByStream(rt, id) orelse return;
    var rep: [32]u8 = undefined;
    const n = socks5.buildError(&rep, @enumFromInt(code));
    try rt.queueToSock(conn, rep[0..n]);
    conn.phase = .closing; // 冲刷完应答后关闭
}

fn onStreamData(rt: *Runtime, id: u32, bytes: []const u8) !void {
    const conn = connByStream(rt, id) orelse return;
    rt.queueToSock(conn, bytes) catch {
        conn.dead = true;
        return;
    };
    rt.flushSock(conn);
}

fn onStreamEof(rt: *Runtime, id: u32) !void {
    const conn = connByStream(rt, id) orelse return;
    // 对端不再发数据：待 t2s 冲刷完，关闭 socket 写端。
    net.shutdownWrite(conn.fd);
}

fn onStreamReset(rt: *Runtime, id: u32) void {
    if (rt.udp_by_stream.get(id)) |ua| {
        closeUdp(rt, ua); // 对端结束了 UDP 关联
        return;
    }
    if (rt.fwd_by_stream.get(id)) |fa| {
        closeFwdAssoc(rt, fa);
        return;
    }
    const conn = connByStream(rt, id) orelse return;
    conn.dead = true;
}

// —— UDP 关联（协议 §9）——
// serve 侧：对端要开 UDP 关联 → 建目标 UDP socket，接受。
fn onDatagramOpen(rt: *Runtime, id: u32, metadata: []const u8) !void {
    _ = metadata;
    const fd = net.udpSocket() catch {
        try rt.tunnel.rejectDatagram(id, @intFromEnum(socks5.Rep.general));
        return;
    };
    const ua = try rt.alloc.create(UdpAssoc);
    ua.* = .{ .stream_id = id, .fd = fd };
    try rt.udp.append(rt.alloc, ua);
    try rt.udp_by_stream.put(id, ua);
    try rt.tunnel.acceptDatagram(id, "\x01\x00\x00\x00\x00\x00\x00");
}

// local 侧：远端已绑 UDP（通道被接受）→ 冲刷通道就绪前暂存的数据报。
fn onDatagramAccept(rt: *Runtime, id: u32, metadata: []const u8) !void {
    _ = metadata;
    if (rt.udp_by_stream.get(id)) |ua| {
        ua.open = true;
        dgramFlush(rt, id, &ua.pending);
    } else if (rt.fwd_by_stream.get(id)) |fa| {
        fa.open = true;
        dgramFlush(rt, id, &fa.pending);
    }
}

fn onDatagramReject(rt: *Runtime, id: u32, code: u8) void {
    _ = code;
    if (rt.udp_by_stream.get(id)) |ua| closeUdp(rt, ua);
}

// 收到一个数据报。payload = 地址块 + 数据（socks5 层语义，协议 §9.2）。
fn onDatagram(rt: *Runtime, id: u32, payload: []const u8) !void {
    if (rt.cfg.mode == .serve) {
        const ua = rt.udp_by_stream.get(id) orelse return;
        try serveSendDatagram(rt, ua, payload);
        return;
    }
    // local：可能是 SOCKS5 UDP 关联，或静态转发关联。
    if (rt.udp_by_stream.get(id)) |ua| {
        localReturnDatagram(rt, ua, payload);
    } else if (rt.fwd_by_stream.get(id)) |fa| {
        localReturnForward(rt, fa, payload);
    }
}

fn closeUdp(rt: *Runtime, ua: *UdpAssoc) void {
    _ = rt.udp_by_stream.remove(ua.stream_id);
    net.close(ua.fd);
    for (rt.udp.items, 0..) |p, i| {
        if (p == ua) {
            _ = rt.udp.swapRemove(i);
            break;
        }
    }
    ua.pending.deinit(rt.alloc);
    rt.alloc.destroy(ua);
}

fn findUdpByFd(rt: *Runtime, fd: net.fd_t) ?*UdpAssoc {
    for (rt.udp.items) |ua| if (ua.fd == fd) return ua;
    return null;
}

// serve 侧：payload = 目标地址块 + 数据 → 解析地址 → sendto 目标。
fn serveSendDatagram(rt: *Runtime, ua: *UdpAssoc, payload: []const u8) !void {
    const dec = address.decode(payload) catch return;
    const data = payload[dec.consumed..];
    var ip4: [4]u8 = undefined;
    switch (dec.addr.host) {
        .ipv4 => |a| ip4 = a,
        .domain => |d| {
            var hb: [256]u8 = undefined;
            if (d.len >= hb.len) return;
            @memcpy(hb[0..d.len], d);
            hb[d.len] = 0;
            ip4 = net.resolve4(hb[0..d.len :0], dec.addr.port) catch return;
        },
        .ipv6 => return,
    }
    net.sendTo4(ua.fd, data, ip4, dec.addr.port);
    _ = rt;
}

// local 侧：payload = 源地址块 + 数据 → 加 SOCKS5 UDP 头 → 发回 curl。
fn localReturnDatagram(rt: *Runtime, ua: *UdpAssoc, payload: []const u8) void {
    if (!ua.peer_set) return; // 还没学到 curl 的 UDP 源
    var buf: [70000]u8 = undefined;
    if (payload.len + 3 > buf.len) return;
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0; // RSV RSV FRAG
    @memcpy(buf[3 .. 3 + payload.len], payload);
    net.sendTo4(ua.fd, buf[0 .. 3 + payload.len], ua.peer_ip, ua.peer_port);
    _ = rt;
}

// local 侧：relay socket 可读 → 收 curl 的 UDP → 剥 SOCKS5 头 → sendDatagram。
fn localRelayReadable(rt: *Runtime, ua: *UdpAssoc) !void {
    var buf: [70000]u8 = undefined;
    while (net.recvFrom4(ua.fd, &buf)) |r| {
        // 来源校验（协议 §9.4）：只认第一包学到的那个 IP。
        if (!ua.peer_set) {
            ua.peer_set = true;
            ua.peer_ip = r.ip4;
            ua.peer_port = r.port;
        } else if (!std.mem.eql(u8, &r.ip4, &ua.peer_ip)) {
            continue; // 丢弃陌生来源
        }
        if (r.n < 3) continue;
        if (buf[2] != 0) continue; // FRAG != 0 丢弃（协议 §9.2）
        // buf[3..n] = ATYP+ADDR+PORT+DATA，正是隧道数据报载荷。
        dgramSend(rt, ua.stream_id, ua.open, &ua.pending, buf[3..r.n]);
    }
}

// serve 侧：目标 UDP socket 可读 → recvfrom → 载荷 = 源地址块 + 数据 → 回送。
fn serveTargetReadable(rt: *Runtime, ua: *UdpAssoc) !void {
    var buf: [70000]u8 = undefined;
    while (net.recvFrom4(ua.fd, &buf)) |r| {
        const src = address.Address{ .host = .{ .ipv4 = r.ip4 }, .port = r.port };
        var payload: [70016]u8 = undefined;
        const alen = src.encode(&payload);
        if (alen + r.n > payload.len) continue;
        @memcpy(payload[alen .. alen + r.n], buf[0..r.n]);
        _ = rt.tunnel.sendDatagram(ua.stream_id, payload[0 .. alen + r.n]) catch {};
    }
}

// ===================== 静态 UDP 转发（local） =====================

fn findForwardByFd(rt: *Runtime, fd: net.fd_t) ?*Forward {
    for (rt.forwards) |*f| if (f.fd == fd) return f;
    return null;
}

fn findFwdAssoc(rt: *Runtime, fwd: *Forward, ip: [4]u8, port: u16) ?*FwdAssoc {
    for (rt.fwd_assocs.items) |fa| {
        if (fa.fwd == fwd and fa.cli_port == port and std.mem.eql(u8, &fa.cli_ip, &ip)) return fa;
    }
    return null;
}

fn closeFwdAssoc(rt: *Runtime, fa: *FwdAssoc) void {
    _ = rt.fwd_by_stream.remove(fa.stream_id);
    for (rt.fwd_assocs.items, 0..) |p, i| {
        if (p == fa) {
            _ = rt.fwd_assocs.swapRemove(i);
            break;
        }
    }
    fa.pending.deinit(rt.alloc);
    rt.alloc.destroy(fa);
}

// 数据报缓冲：通道就绪（open）直接发；否则暂存 [u16 len][payload]，
// 等 datagram_accept 后由 dgramFlush 冲刷。解决"通道接受前首包被丢"的竞态。
fn dgramSend(rt: *Runtime, stream_id: u32, open: bool, pending: *std.ArrayList(u8), payload: []const u8) void {
    if (open) {
        _ = rt.tunnel.sendDatagram(stream_id, payload) catch {};
    } else if (pending.items.len + payload.len + 2 <= 64 * 1024) {
        var lb: [2]u8 = undefined;
        std.mem.writeInt(u16, &lb, @intCast(payload.len), .little);
        pending.appendSlice(rt.alloc, &lb) catch return;
        pending.appendSlice(rt.alloc, payload) catch return;
    } // 否则丢弃（暂存已满，符合 UDP 可丢语义）
}

fn dgramFlush(rt: *Runtime, stream_id: u32, pending: *std.ArrayList(u8)) void {
    var off: usize = 0;
    while (off + 2 <= pending.items.len) {
        const n = std.mem.readInt(u16, pending.items[off..][0..2], .little);
        off += 2;
        if (off + n > pending.items.len) break;
        _ = rt.tunnel.sendDatagram(stream_id, pending.items[off .. off + n]) catch {};
        off += n;
    }
    pending.clearAndFree(rt.alloc);
}

// 转发监听可读：收客户端 UDP → 找/建关联 → 载荷 = 目标地址块 + 数据 → 送隧道。
fn fwdReadable(rt: *Runtime, fwd: *Forward) !void {
    var buf: [70000]u8 = undefined;
    while (net.recvFrom4(fwd.fd, &buf)) |r| {
        var fa = findFwdAssoc(rt, fwd, r.ip4, r.port);
        if (fa == null) {
            if (!rt.tunnel.isReady()) continue; // 隧道未就绪，丢弃
            const id = rt.tunnel.openDatagram(fwd.addr_block[0..fwd.addr_len]) catch continue;
            const na = try rt.alloc.create(FwdAssoc);
            na.* = .{ .stream_id = id, .fwd = fwd, .cli_ip = r.ip4, .cli_port = r.port, .last_ms = nowMs() };
            try rt.fwd_assocs.append(rt.alloc, na);
            try rt.fwd_by_stream.put(id, na);
            fa = na;
        }
        // 载荷 = 目标地址块 + 客户端数据。
        var payload: [70300]u8 = undefined;
        if (fwd.addr_len + r.n > payload.len) continue;
        @memcpy(payload[0..fwd.addr_len], fwd.addr_block[0..fwd.addr_len]);
        @memcpy(payload[fwd.addr_len .. fwd.addr_len + r.n], buf[0..r.n]);
        dgramSend(rt, fa.?.stream_id, fa.?.open, &fa.?.pending, payload[0 .. fwd.addr_len + r.n]);
        fa.?.last_ms = nowMs();
    }
}

// 隧道回来的数据报（服务端→本地）：载荷 = 源地址块 + 数据 → 剥地址 → 发回客户端。
fn localReturnForward(rt: *Runtime, fa: *FwdAssoc, payload: []const u8) void {
    const dec = address.decode(payload) catch return;
    const data = payload[dec.consumed..];
    net.sendTo4(fa.fwd.fd, data, fa.cli_ip, fa.cli_port);
    fa.last_ms = nowMs();
    _ = rt;
}

// —— 从 host 字符串 + 端口构造 RFC1928 地址块 ——
fn parseIp4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    return if (i == 4) out else null;
}

fn buildAddrBlock(out: []u8, host: []const u8, port: u16) ?usize {
    if (parseIp4(host)) |ip| {
        return (address.Address{ .host = .{ .ipv4 = ip }, .port = port }).encode(out);
    }
    if (host.len == 0 or host.len > 255) return null;
    return (address.Address{ .host = .{ .domain = host }, .port = port }).encode(out);
}

// ===================== SOCKS5 握手（local） =====================

fn driveSocks5(rt: *Runtime, conn: *Conn) !void {
    switch (net.readFd(conn.fd, conn.hs_buf[conn.hs_len..])) {
        .n => |r| conn.hs_len += r,
        .again => return,
        .eof, .err => {
            conn.dead = true;
            return;
        },
    }
    if (conn.phase == .greeting) {
        const g = socks5.parseGreeting(conn.hs_buf[0..conn.hs_len]) catch {
            conn.dead = true;
            return;
        };
        switch (g) {
            .need_more => return,
            .ok => |gr| {
                if (!gr.no_auth) {
                    try rt.queueToSock(conn, &socks5.methodReply(socks5.auth_unacceptable));
                    conn.phase = .closing;
                    return;
                }
                try rt.queueToSock(conn, &socks5.methodReply(socks5.auth_none));
                // 移除已消费的问候字节
                shiftHs(conn, gr.consumed);
                conn.phase = .request;
                if (conn.hs_len > 0) try driveSocks5Request(rt, conn);
            },
        }
    } else if (conn.phase == .request) {
        try driveSocks5Request(rt, conn);
    }
}

fn driveSocks5Request(rt: *Runtime, conn: *Conn) !void {
    const r = socks5.parseRequest(conn.hs_buf[0..conn.hs_len]) catch {
        conn.dead = true;
        return;
    };
    switch (r) {
        .need_more => return,
        .ok => |req| {
            if (req.cmd == .udp_associate) {
                try startUdpAssociate(rt, conn, req);
                return;
            }
            if (req.cmd != .connect) {
                var rep: [32]u8 = undefined;
                const n = socks5.buildError(&rep, .cmd_unsupported);
                try rt.queueToSock(conn, rep[0..n]);
                conn.phase = .closing;
                return;
            }
            const id = try rt.tunnel.open(req.addr_block);
            conn.stream_id = id;
            conn.phase = .awaiting;
            try rt.by_stream.put(id, conn);
            shiftHs(conn, req.consumed);
        },
    }
}

// local 侧 UDP ASSOCIATE：绑 relay socket、开数据报关联、立刻回 relay 地址给 curl。
// TCP 控制连接保持打开；它一断，关联即销毁（协议 §9.1）。
fn startUdpAssociate(rt: *Runtime, conn: *Conn, req: socks5.Request) !void {
    const relay = net.udpSocket() catch {
        var rep: [32]u8 = undefined;
        const n = socks5.buildError(&rep, .general);
        try rt.queueToSock(conn, rep[0..n]);
        conn.phase = .closing;
        return;
    };
    net.udpBind(relay, .{ 127, 0, 0, 1 }, 0) catch {
        net.close(relay);
        conn.dead = true;
        return;
    };
    const port = net.localPort(relay);
    const id = try rt.tunnel.openDatagram(req.addr_block);
    const ua = try rt.alloc.create(UdpAssoc);
    ua.* = .{ .stream_id = id, .fd = relay, .ctrl = conn };
    try rt.udp.append(rt.alloc, ua);
    try rt.udp_by_stream.put(id, ua);
    conn.stream_id = id;
    conn.phase = .udp_control;
    // 回 curl：SOCKS5 成功 + relay 绑定地址（127.0.0.1:port）。
    var rep: [32]u8 = undefined;
    const bind = address.Address{ .host = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = port };
    const n = socks5.buildReply(&rep, .success, bind);
    try rt.queueToSock(conn, rep[0..n]);
    shiftHs(conn, req.consumed);
}

fn shiftHs(conn: *Conn, consumed: usize) void {
    const rem = conn.hs_len - consumed;
    if (rem > 0) std.mem.copyForwards(u8, conn.hs_buf[0..rem], conn.hs_buf[consumed..conn.hs_len]);
    conn.hs_len = rem;
}

// ===================== 数据泵（piping） =====================

fn pumpConnRead(rt: *Runtime, conn: *Conn) !void {
    if (conn.phase != .piping or conn.stream_id == 0) return;
    var buf: [16384]u8 = undefined;
    switch (net.readFd(conn.fd, &buf)) {
        .n => |r| {
            const accepted = try rt.tunnel.write(conn.stream_id, buf[0..r]);
            if (accepted < r) {
                // 隧道窗口/背压未全收：剩余存入 s2t，停读 socket，等窗口打开再喂。
                try conn.s2t.appendSlice(rt.alloc, buf[accepted..r]);
                conn.want_read = false;
            }
        },
        .again => {},
        .eof => {
            conn.sock_eof = true;
            if (conn.s2t.items.len == 0) try rt.tunnel.closeWrite(conn.stream_id);
            conn.want_read = false;
        },
        .err => conn.dead = true,
    }
}

// 背压恢复：把暂存的 s2t 再喂给隧道。
fn retryConnWrite(rt: *Runtime, conn: *Conn) !void {
    if (conn.stream_id == 0 or conn.s2t.items.len == 0) return;
    const accepted = try rt.tunnel.write(conn.stream_id, conn.s2t.items);
    if (accepted > 0) {
        const rem = conn.s2t.items.len - accepted;
        if (rem > 0) std.mem.copyForwards(u8, conn.s2t.items[0..rem], conn.s2t.items[accepted..]);
        conn.s2t.shrinkRetainingCapacity(rem);
        if (rem == 0) {
            if (conn.sock_eof) {
                try rt.tunnel.closeWrite(conn.stream_id);
            } else {
                conn.want_read = true;
            }
        }
    }
}

// ===================== 事件循环 =====================

fn eventLoop(rt: *Runtime) !void {
    var pollfds: std.ArrayList(posix.pollfd) = .empty;
    defer pollfds.deinit(rt.alloc);
    var last_tick: i64 = nowMs();

    while (rt.running) {
        try rt.pumpTunnelOut();

        pollfds.clearRetainingCapacity();
        // wire in
        try pollfds.append(rt.alloc, .{ .fd = rt.wire_in, .events = POLLIN, .revents = 0 });
        // wire out
        if (rt.wire_obuf.items.len > 0)
            try pollfds.append(rt.alloc, .{ .fd = rt.wire_out, .events = POLLOUT, .revents = 0 });
        // listen —— 握手/探针未完成前不接受 SOCKS5 连接（开流需 ready）。
        if (rt.listen_fd) |lf| if (rt.tunnel.isReady())
            try pollfds.append(rt.alloc, .{ .fd = lf, .events = POLLIN, .revents = 0 });
        // conns
        for (rt.conns.items) |conn| {
            var ev: i16 = 0;
            if (conn.phase == .greeting or conn.phase == .request) ev |= POLLIN;
            if (conn.phase == .piping and conn.want_read) ev |= POLLIN;
            if (conn.phase == .udp_control) ev |= POLLIN; // 检测 TCP 控制连接关闭
            if (conn.t2s.items.len > 0 or conn.phase == .connecting) ev |= POLLOUT;
            if (ev != 0) try pollfds.append(rt.alloc, .{ .fd = conn.fd, .events = ev, .revents = 0 });
        }
        // UDP relay / target socket
        for (rt.udp.items) |ua|
            try pollfds.append(rt.alloc, .{ .fd = ua.fd, .events = POLLIN, .revents = 0 });
        // 静态 UDP 转发监听
        for (rt.forwards) |*f|
            try pollfds.append(rt.alloc, .{ .fd = f.fd, .events = POLLIN, .revents = 0 });

        _ = posix.poll(pollfds.items, 1000) catch 0;

        // 分发 revents
        for (pollfds.items) |pfd| {
            if (pfd.revents == 0) continue;
            if (pfd.fd == rt.wire_in) {
                switch (net.readFd(rt.wire_in, &rt.io_buf)) {
                    .n => |r| try rt.tunnel.recv(rt.io_buf[0..r]),
                    .again => {},
                    .eof, .err => rt.running = false,
                }
            } else if (pfd.fd == rt.wire_out) {
                rt.flushWire();
            } else if (rt.listen_fd != null and pfd.fd == rt.listen_fd.?) {
                while (net.accept(rt.listen_fd.?)) |cfd| {
                    const conn = try rt.alloc.create(Conn);
                    conn.* = .{ .fd = cfd, .phase = .greeting };
                    try rt.addConn(conn);
                }
            } else if (findUdpByFd(rt, pfd.fd)) |ua| {
                if ((pfd.revents & POLLIN) != 0) {
                    if (rt.cfg.mode == .serve) try serveTargetReadable(rt, ua) else try localRelayReadable(rt, ua);
                }
            } else if (findForwardByFd(rt, pfd.fd)) |fwd| {
                if ((pfd.revents & POLLIN) != 0) try fwdReadable(rt, fwd);
            } else {
                // conn fd
                const conn = findConnByFd(rt, pfd.fd) orelse continue;
                if (conn.phase == .udp_control) {
                    // TCP 控制连接：任何可读多半是对端关闭 → 结束 UDP 关联。
                    var tmp: [256]u8 = undefined;
                    switch (net.readFd(conn.fd, &tmp)) {
                        .eof, .err => conn.dead = true,
                        else => {},
                    }
                    continue;
                }
                if (conn.phase == .connecting and (pfd.revents & POLLOUT) != 0) {
                    const e = net.connectResult(conn.fd);
                    if (e == posix.E.SUCCESS) {
                        try rt.tunnel.accept(conn.stream_id, socks5EncodeBind());
                        conn.phase = .piping;
                    } else {
                        try rt.tunnel.reject(conn.stream_id, @intFromEnum(mapErrno(e)));
                        conn.dead = true;
                    }
                    continue;
                }
                if ((pfd.revents & POLLIN) != 0) {
                    if (conn.phase == .greeting or conn.phase == .request) {
                        try driveSocks5(rt, conn);
                    } else if (conn.phase == .piping) {
                        try pumpConnRead(rt, conn);
                    }
                }
                if ((pfd.revents & POLLOUT) != 0) {
                    rt.flushSock(conn);
                }
            }
        }

        try handleTunnelEvents(rt);

        // 背压恢复：尝试把暂存的 s2t 再喂给隧道
        for (rt.conns.items) |conn| try retryConnWrite(rt, conn);

        // 冲刷各 socket、清理死连接
        var i: usize = 0;
        while (i < rt.conns.items.len) {
            const conn = rt.conns.items[i];
            rt.flushSock(conn);
            const flushed = conn.t2s.items.len == 0;
            if (conn.dead and flushed) {
                // UDP 控制连接关闭：先拆本地 relay，reset 通知远端结束关联。
                if (rt.udp_by_stream.get(conn.stream_id)) |ua| closeUdp(rt, ua);
                if (conn.stream_id != 0) rt.tunnel.reset(conn.stream_id, 0) catch {};
                rt.dropConn(conn);
                continue;
            }
            if (conn.phase == .closing and flushed) {
                rt.dropConn(conn);
                continue;
            }
            i += 1;
        }

        // 定期 tick
        const now = nowMs();
        if (now - last_tick >= 500) {
            last_tick = now;
            rt.tunnel.tick(@intCast(now)) catch |e| {
                rt.log("tunnel closed: {s}", .{@errorName(e)});
                rt.running = false;
            };
            // 静态转发关联 idle 回收（60s 无流量 → 结束隧道数据报通道）。
            var fi: usize = 0;
            while (fi < rt.fwd_assocs.items.len) {
                const fa = rt.fwd_assocs.items[fi];
                if (now - fa.last_ms >= 60_000) {
                    rt.tunnel.reset(fa.stream_id, 0) catch {};
                    closeFwdAssoc(rt, fa);
                    continue;
                }
                fi += 1;
            }
        }
    }
}

fn findConnByFd(rt: *Runtime, fd: net.fd_t) ?*Conn {
    for (rt.conns.items) |conn| if (conn.fd == fd) return conn;
    return null;
}

fn socks5EncodeBind() []const u8 {
    // 远端绑定地址：这里简化回全零 IPv4:0（元数据对隧道不透明，local 侧也不使用）。
    return &[_]u8{ 0x01, 0, 0, 0, 0, 0, 0 };
}

fn mapErrno(e: posix.E) socks5.Rep {
    return switch (e) {
        posix.E.CONNREFUSED => .refused,
        posix.E.HOSTUNREACH => .host_unreach,
        posix.E.NETUNREACH => .net_unreach,
        posix.E.TIMEDOUT => .ttl_expired,
        else => .general,
    };
}

// ===================== 入口 =====================

pub fn run(alloc: Allocator, cfg: Config) RunError!void {
    switch (cfg.mode) {
        .local => try runLocal(alloc, cfg),
        .serve => try runServe(alloc, cfg),
    }
}

fn sleepMs(ms: i32) void {
    var none: [0]posix.pollfd = .{};
    _ = posix.poll(&none, ms) catch {};
}

fn runLocal(alloc: Allocator, cfg: Config) RunError!void {
    // SOCKS5 监听端口只开一次，跨重连始终保持——不影响上层代理（决策 D15）。
    const listen_fd = try net.listenTcp(cfg.listen_ip, cfg.listen_port);
    defer net.close(listen_fd);
    if (cfg.verbose) std.debug.print("smodem: local mode: socks5 on {d}.{d}.{d}.{d}:{d}\n", .{ cfg.listen_ip[0], cfg.listen_ip[1], cfg.listen_ip[2], cfg.listen_ip[3], cfg.listen_port });

    // 静态 UDP 转发监听：同样只开一次、跨重连保持。
    const forwards = try alloc.alloc(Forward, cfg.udp_forwards.len);
    defer {
        for (forwards) |f| net.close(f.fd);
        alloc.free(forwards);
    }
    for (cfg.udp_forwards, 0..) |spec, i| {
        const fd = try net.udpSocket();
        errdefer net.close(fd);
        try net.udpBind(fd, cfg.listen_ip, spec.local_port);
        forwards[i] = .{ .fd = fd, .local_port = spec.local_port, .addr_len = 0 };
        forwards[i].addr_len = buildAddrBlock(&forwards[i].addr_block, spec.host, spec.port) orelse return error.SetupFailed;
        if (cfg.verbose) std.debug.print("smodem: udp forward {d} -> {s}:{d}\n", .{ spec.local_port, spec.host, spec.port });
    }

    var backoff_ms: i32 = 1000;
    while (true) {
        const became_ready = runOneSession(alloc, cfg, listen_fd, forwards) catch |e| blk: {
            if (cfg.verbose) std.debug.print("smodem: session error: {s}\n", .{@errorName(e)});
            break :blk false;
        };
        // 传输断开：退避后重连。曾成功握手过则退避归位。
        if (became_ready) backoff_ms = 1000;
        if (cfg.verbose) std.debug.print("smodem: transport down, reconnecting in {d}ms\n", .{backoff_ms});
        sleepMs(backoff_ms);
        backoff_ms = @min(backoff_ms * 2, 30_000);
    }
}

/// 跑一次传输会话：拉起 ssh、建隧道、事件循环，直到隧道断开。返回是否握手成功过。
/// listen_fd 由调用方拥有，跨会话保持，本函数不关它。
fn runOneSession(alloc: Allocator, cfg: Config, listen_fd: net.fd_t, forwards: []Forward) RunError!bool {
    var argv_buf: [1][*:null]const ?[*:0]const u8 = undefined;
    const ch = child.spawn(cfg.transport_argv, &argv_buf) catch return error.TransportFailed;
    defer child.stop(ch);

    var rt = Runtime{
        .alloc = alloc,
        .cfg = cfg,
        .tunnel = try Tunnel.init(alloc, cfg.tunnel, .client),
        .wire_in = ch.stdout_fd,
        .wire_out = ch.stdin_fd,
        .listen_fd = listen_fd,
        .by_stream = std.AutoHashMap(u32, *Conn).init(alloc),
        .udp_by_stream = std.AutoHashMap(u32, *UdpAssoc).init(alloc),
        .forwards = forwards,
        .fwd_by_stream = std.AutoHashMap(u32, *FwdAssoc).init(alloc),
    };
    defer rt.tunnel.deinit();
    defer rt.wire_obuf.deinit(alloc);
    defer rt.by_stream.deinit();
    defer rt.udp_by_stream.deinit();
    defer rt.fwd_by_stream.deinit();
    defer {
        for (rt.fwd_assocs.items) |fa| {
            fa.pending.deinit(alloc);
            alloc.destroy(fa);
        }
        rt.fwd_assocs.deinit(alloc);
    }
    defer {
        for (rt.udp.items) |ua| {
            net.close(ua.fd);
            ua.pending.deinit(alloc);
            alloc.destroy(ua);
        }
        rt.udp.deinit(alloc);
    }
    defer {
        for (rt.conns.items) |conn| {
            net.close(conn.fd); // 断开旧客户端连接，让浏览器/ curl 重连（会被新会话接住）
            conn.deinit(alloc);
            alloc.destroy(conn);
        }
        rt.conns.deinit(alloc);
    }
    // 关闭子进程的管道 fd（stop 只杀进程；fd 由我们持有）。
    defer net.close(rt.wire_in);
    defer net.close(rt.wire_out);
    try eventLoop(&rt);
    return rt.ever_ready;
}

fn runServe(alloc: Allocator, cfg: Config) RunError!void {
    net.setNonBlock(0);
    net.setNonBlock(1);
    var rt = Runtime{
        .alloc = alloc,
        .cfg = cfg,
        .tunnel = try Tunnel.init(alloc, cfg.tunnel, .server),
        .wire_in = 0,
        .wire_out = 1,
        .by_stream = std.AutoHashMap(u32, *Conn).init(alloc),
        .udp_by_stream = std.AutoHashMap(u32, *UdpAssoc).init(alloc),
        .fwd_by_stream = std.AutoHashMap(u32, *FwdAssoc).init(alloc),
    };
    defer rt.tunnel.deinit();
    defer rt.wire_obuf.deinit(alloc);
    defer rt.by_stream.deinit();
    defer rt.udp_by_stream.deinit();
    defer rt.fwd_by_stream.deinit();
    defer {
        for (rt.udp.items) |ua| {
            net.close(ua.fd);
            ua.pending.deinit(alloc);
            alloc.destroy(ua);
        }
        rt.udp.deinit(alloc);
    }
    defer {
        for (rt.conns.items) |conn| {
            conn.deinit(alloc);
            alloc.destroy(conn);
        }
        rt.conns.deinit(alloc);
    }
    try eventLoop(&rt);
}
