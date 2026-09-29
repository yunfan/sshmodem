//! 第一层：通用多路复用隧道（应用无关，sans-io）。设计 §3.2。
//!
//! 心智模型：给它一条又脏又字符化的载体（ssh stdio），它还你若干条
//! 干净、可靠、有序、带流控的字节流。OPEN 元数据 / 错误码 / 数据报载荷
//! 在这一层**都是不透明字节**——它不知道地址、不知道 SOCKS5。
//!
//! 用法：
//!   recv(from_wire)  喂入从载体收到的字节
//!   send(into_wire)  取出要写给载体的字节
//!   tick(now_ms)     推进保活/超时
//!   nextEvent()      取一条事件（其中的 []const u8 在下次调用本对象任一方法前有效）
//!   open/accept/reject/write/consume/closeWrite/reset  流操作
//!
//! 本文件是 M2：握手（引导+HELLO）、SS 定界帧+重同步+冲刷、TCP 流+双层窗口
//! +半关闭，编码用 config 固定值。自动降档探针（协议 §4.2）在后续里程碑接入。

const std = @import("std");
const Allocator = std.mem.Allocator;
const frame = @import("../codec/frame.zig");
const encoding = @import("../codec/encoding.zig");
const derive = @import("../codec/derive.zig");
const hs = @import("handshake.zig");

pub const Role = hs.Role;
pub const caps = hs.caps;
pub const Encoding = encoding.Encoding;

pub const LogLevel = enum { debug, info, warn, err };

pub const Config = struct {
    /// 自动降档探针（协议 §4.2）。开启后：握手走 B64，握手完成对每个方向
    /// 逐级探测 RAW→ESC→B64，各自选出最省的能过的编码；`encoding` 字段被忽略。
    /// 关闭（默认）：全程用固定 `encoding`。CLI 未指定 --encoding 时会打开它。
    auto_probe: bool = false,
    /// 固定运行编码（auto_probe=false 时全程用它，含握手）；默认 B64。
    encoding: Encoding = .b64,
    sentinel: u8 = derive.default_sentinel,
    token: []const u8 = derive.default_token,
    stream_window: u32 = 128 * 1024,
    session_window: u32 = 2 * 1024 * 1024,
    max_streams: u16 = 256,
    caps: u32 = 0,
    impl: []const u8 = "smodem/0.1.0",
    handshake_timeout_ms: u64 = 10_000,
    keepalive_ms: u64 = 30_000,
    idle_timeout_ms: u64 = 90_000,
};

pub const Event = union(enum) {
    ready,
    closed,
    stream_open: struct { id: u32, metadata: []const u8 },
    stream_accept: struct { id: u32, metadata: []const u8 },
    stream_reject: struct { id: u32, code: u8 },
    stream_data: struct { id: u32, bytes: []const u8 },
    stream_writable: u32,
    stream_eof: u32,
    stream_reset: struct { id: u32, reason: u8 },
    // —— UDP 关联（协议 §9）。载荷不透明（socks5 层解释为 地址块+数据）——
    datagram_open: struct { id: u32, metadata: []const u8 },
    datagram_accept: struct { id: u32, metadata: []const u8 },
    datagram_reject: struct { id: u32, code: u8 },
    datagram: struct { id: u32, payload: []const u8 },
    log: struct { level: LogLevel, msg: []const u8 },
};

pub const Error = error{
    NotReady,
    NoSuchStream,
    BadStreamState,
    TooManyStreams,
    HandshakeTimeout,
    IdleTimeout,
    VersionMismatch,
    Corrupt, // RAW 模式帧损坏（脏线用不到 RAW，故视为致命）
    ProtocolError,
} || Allocator.Error || frame.EncodeError;

const StreamState = enum {
    opening_local, // 我方 open，等对端 OPEN_OK/ERR
    open_pending, // 对端 open，等本地 accept/reject
    open,
    half_local, // 本方已 CLOSE
    half_remote, // 对端已 CLOSE
    closed,
};

const StreamKind = enum { tcp, udp };

const Stream = struct {
    id: u32,
    kind: StreamKind = .tcp,
    state: StreamState,
    // 发送：对端授予我方的窗口余额（初始 = 对端 HELLO.stream_window）
    send_window: u32,
    // 接收：我方还允许对端发多少（初始 = 本方 config.stream_window）
    recv_remaining: u32,
    recv_pending_ack: u32 = 0,
};

const Blob = struct { off: u32, len: u32 };

const IEvent = union(enum) {
    ready,
    closed,
    stream_open: struct { id: u32, meta: Blob },
    stream_accept: struct { id: u32, meta: Blob },
    stream_reject: struct { id: u32, code: u8 },
    stream_data: struct { id: u32, data: Blob },
    stream_writable: u32,
    stream_eof: u32,
    stream_reset: struct { id: u32, reason: u8 },
    datagram_open: struct { id: u32, meta: Blob },
    datagram_accept: struct { id: u32, meta: Blob },
    datagram_reject: struct { id: u32, code: u8 },
    datagram: struct { id: u32, data: Blob },
    log: struct { level: LogLevel, msg: Blob },
};

const Phase = enum { syncing, waiting_hello, probing, ready, closed };

/// 握手期固定用它（协议 §3.4）：一定能过，探针再从此降/升档。
const handshake_encoding: Encoding = .b64;

/// 透明性探针图案（协议 §4.3）：256 全值 + 16 陷阱字节。含且仅含一个 0x25，
/// 两侧不同，故不含 SS，捕获边界成立。
const probe_pattern: [272]u8 = blk: {
    @setEvalBranchQuota(2000);
    var p: [272]u8 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) p[i] = @intCast(i);
    const trap = [16]u8{ 0x0D, 0x0A, 0x0A, 0x0D, 0x0D, 0x0D, 0x0A, 0x0A, 0x1A, 0x04, 0x03, 0x1C, 0x11, 0x13, 0x7F, 0xFF };
    @memcpy(p[256..272], &trap);
    break :blk p;
};

pub const Tunnel = struct {
    alloc: Allocator,
    cfg: Config,
    role: Role,
    phase: Phase,

    sentinel: u8,
    tx_enc: Encoding,
    rx_enc: Encoding,

    // 会话级窗口
    session_send: u32, // 对端授予我方的会话窗口
    peer_stream_window: u32 = 0, // 对端 HELLO 声明的 per-stream 窗口（我方发送初始额度）
    session_recv_remaining: u32,
    session_recv_pending_ack: u32 = 0,

    streams: std.AutoHashMap(u32, *Stream),
    next_id: u32,

    // —— TX ——
    tx: std.ArrayList(u8) = .empty,
    tx_off: usize = 0,
    logical_scratch: []u8,
    enc_scratch: []u8,

    // —— RX ——
    bootstrap: hs.Bootstrap,
    sync_buf: [hs.max_sync_len]u8 = undefined,
    rx_synced: bool = false,
    framebuf: []u8,
    framelen: usize = 0,
    in_frame: bool = false,
    sent_run: u8 = 0,
    decoder: encoding.Decoder,
    desync_count: u32 = 0,

    // —— 探针（auto_probe，协议 §4.2）——
    probe_seq: u8 = 0,
    probe_cand: Encoding = .raw, // 我方 tx 正在测试的候选
    tx_decided: bool = false, // 我方 tx 编码已定
    rx_enc_set: bool = false, // 已收到对端 ENCODING_SET
    probe_expected: [640]u8 = undefined, // 我方 PROBE 送出的编码后图案（用于比对）
    probe_expected_len: usize = 0,
    capturing: bool = false, // 正在捕获对端 PROBE 的裸图案
    cap_started: bool = false,
    cap_run: u8 = 0,
    cap_seq: u8 = 0,
    capture: std.ArrayList(u8) = .empty,

    // —— 事件 ——
    events: std.ArrayList(IEvent) = .empty,
    ev_cursor: usize = 0,
    ev_bytes: std.ArrayList(u8) = .empty,

    // —— 计时 ——
    start_ms: ?u64 = null,
    last_rx_ms: u64 = 0,
    last_ping_ms: u64 = 0,

    const max_send_payload = frame.max_data_payload; // 16384
    const rx_frame_cap = frame.frameLen(frame.max_payload); // 65535 上限

    pub fn init(alloc: Allocator, cfg: Config, role: Role) Error!Tunnel {
        const logical = try alloc.alloc(u8, frame.frameLen(max_send_payload));
        errdefer alloc.free(logical);
        const enc_s = try alloc.alloc(u8, encoding.encodeBound(.esc, logical.len) + 8);
        errdefer alloc.free(enc_s);
        const fb = try alloc.alloc(u8, rx_frame_cap);
        errdefer alloc.free(fb);

        // auto_probe：握手期用 B64，探针后再切；否则全程用固定 encoding。
        const start_enc: Encoding = if (cfg.auto_probe) handshake_encoding else cfg.encoding;

        var t = Tunnel{
            .alloc = alloc,
            .cfg = cfg,
            .role = role,
            .phase = .syncing,
            .sentinel = cfg.sentinel,
            .tx_enc = start_enc,
            .rx_enc = start_enc,
            .session_send = 0,
            .session_recv_remaining = cfg.session_window,
            .streams = std.AutoHashMap(u32, *Stream).init(alloc),
            .next_id = if (role == .client) 1 else 2,
            .logical_scratch = logical,
            .enc_scratch = enc_s,
            .bootstrap = undefined,
            .framebuf = fb,
            .decoder = encoding.Decoder.init(start_enc, cfg.sentinel),
        };
        const sync_len = hs.Bootstrap.buildSync(&t.sync_buf, cfg.sentinel, cfg.token);
        t.bootstrap = hs.Bootstrap.init(t.sync_buf[0..sync_len]);

        // 发引导序列。client 立刻发 HELLO；server 等收到 HELLO 再回 HELLO_ACK。
        try t.tx.appendSlice(alloc, t.sync_buf[0..sync_len]);
        if (role == .client) {
            try t.sendHello(.hello);
            t.phase = .waiting_hello;
        } else {
            t.phase = .syncing; // 等对端 SYNC + HELLO
        }
        return t;
    }

    pub fn deinit(self: *Tunnel) void {
        var it = self.streams.valueIterator();
        while (it.next()) |sp| self.alloc.destroy(sp.*);
        self.streams.deinit();
        self.tx.deinit(self.alloc);
        self.events.deinit(self.alloc);
        self.ev_bytes.deinit(self.alloc);
        self.capture.deinit(self.alloc);
        self.alloc.free(self.logical_scratch);
        self.alloc.free(self.enc_scratch);
        self.alloc.free(self.framebuf);
    }

    // ===================== 事件 =====================

    fn pushBlob(self: *Tunnel, bytes: []const u8) Error!Blob {
        const off: u32 = @intCast(self.ev_bytes.items.len);
        try self.ev_bytes.appendSlice(self.alloc, bytes);
        return .{ .off = off, .len = @intCast(bytes.len) };
    }

    fn push(self: *Tunnel, ev: IEvent) Error!void {
        try self.events.append(self.alloc, ev);
    }

    fn log(self: *Tunnel, level: LogLevel, msg: []const u8) Error!void {
        const b = try self.pushBlob(msg);
        try self.push(.{ .log = .{ .level = level, .msg = b } });
    }

    fn blobSlice(self: *Tunnel, b: Blob) []const u8 {
        return self.ev_bytes.items[b.off .. b.off + b.len];
    }

    pub fn nextEvent(self: *Tunnel) ?Event {
        if (self.ev_cursor >= self.events.items.len) {
            self.events.clearRetainingCapacity();
            self.ev_bytes.clearRetainingCapacity();
            self.ev_cursor = 0;
            return null;
        }
        const ie = self.events.items[self.ev_cursor];
        self.ev_cursor += 1;
        return switch (ie) {
            .ready => .ready,
            .closed => .closed,
            .stream_open => |x| .{ .stream_open = .{ .id = x.id, .metadata = self.blobSlice(x.meta) } },
            .stream_accept => |x| .{ .stream_accept = .{ .id = x.id, .metadata = self.blobSlice(x.meta) } },
            .stream_reject => |x| .{ .stream_reject = .{ .id = x.id, .code = x.code } },
            .stream_data => |x| .{ .stream_data = .{ .id = x.id, .bytes = self.blobSlice(x.data) } },
            .stream_writable => |id| .{ .stream_writable = id },
            .stream_eof => |id| .{ .stream_eof = id },
            .stream_reset => |x| .{ .stream_reset = .{ .id = x.id, .reason = x.reason } },
            .datagram_open => |x| .{ .datagram_open = .{ .id = x.id, .metadata = self.blobSlice(x.meta) } },
            .datagram_accept => |x| .{ .datagram_accept = .{ .id = x.id, .metadata = self.blobSlice(x.meta) } },
            .datagram_reject => |x| .{ .datagram_reject = .{ .id = x.id, .code = x.code } },
            .datagram => |x| .{ .datagram = .{ .id = x.id, .payload = self.blobSlice(x.data) } },
            .log => |x| .{ .log = .{ .level = x.level, .msg = self.blobSlice(x.msg) } },
        };
    }

    // ===================== TX =====================

    fn pushFrame(self: *Tunnel, htype: frame.Type, stream_id: u32, payload: []const u8) Error!void {
        try self.pushFrameEx(htype, stream_id, payload, true);
    }

    /// flush=false 用于 PROBE：其后紧跟裸图案，不能夹冲刷换行。
    /// payload 不得与 self.logical_scratch 别名。
    fn pushFrameEx(self: *Tunnel, htype: frame.Type, stream_id: u32, payload: []const u8, flush: bool) Error!void {
        const total = try frame.encode(self.logical_scratch, .{
            .type = htype,
            .stream_id = stream_id,
            .length = 0,
        }, payload);
        const logical = self.logical_scratch[0..total];
        if (self.tx_enc == .raw) {
            try self.tx.appendSlice(self.alloc, logical);
        } else {
            try self.tx.append(self.alloc, self.sentinel);
            try self.tx.append(self.alloc, self.sentinel);
            const n = encoding.encode(self.tx_enc, self.sentinel, self.enc_scratch, logical);
            try self.tx.appendSlice(self.alloc, self.enc_scratch[0..n]);
            if (flush) try self.tx.append(self.alloc, encoding.flush_byte);
        }
    }

    fn sendHello(self: *Tunnel, htype: frame.Type) Error!void {
        const h = hs.Hello{
            .role = self.role,
            .caps = self.cfg.caps,
            .stream_window = self.cfg.stream_window,
            .session_window = self.cfg.session_window,
            .max_streams = self.cfg.max_streams,
            .impl = self.cfg.impl,
        };
        var buf: [64 + 64]u8 = undefined;
        const n = h.encode(&buf);
        try self.pushFrame(htype, 0, buf[0..n]);
    }

    pub fn send(self: *Tunnel, into: []u8) usize {
        const avail = self.tx.items.len - self.tx_off;
        const n = @min(avail, into.len);
        @memcpy(into[0..n], self.tx.items[self.tx_off .. self.tx_off + n]);
        self.tx_off += n;
        if (self.tx_off == self.tx.items.len) {
            self.tx.clearRetainingCapacity();
            self.tx_off = 0;
        }
        return n;
    }

    pub fn pendingTx(self: *Tunnel) usize {
        return self.tx.items.len - self.tx_off;
    }

    // ===================== 流操作 =====================

    fn getStream(self: *Tunnel, id: u32) Error!*Stream {
        return self.streams.get(id) orelse error.NoSuchStream;
    }

    pub fn open(self: *Tunnel, metadata: []const u8) Error!u32 {
        if (self.phase != .ready) return error.NotReady;
        if (self.streams.count() >= self.cfg.max_streams) return error.TooManyStreams;
        const id = self.next_id;
        self.next_id += 2;
        const s = try self.alloc.create(Stream);
        errdefer self.alloc.destroy(s);
        s.* = .{
            .id = id,
            .state = .opening_local,
            .send_window = self.peer_stream_window,
            .recv_remaining = self.cfg.stream_window,
        };
        try self.streams.put(id, s);
        try self.pushFrame(.open, id, metadata);
        return id;
    }

    pub fn accept(self: *Tunnel, id: u32, metadata: []const u8) Error!void {
        const s = try self.getStream(id);
        if (s.state != .open_pending) return error.BadStreamState;
        s.state = .open;
        try self.pushFrame(.open_ok, id, metadata);
    }

    pub fn reject(self: *Tunnel, id: u32, code: u8) Error!void {
        const s = try self.getStream(id);
        if (s.state != .open_pending) return error.BadStreamState;
        try self.pushFrame(.open_err, id, &[_]u8{code});
        self.dropStream(id);
    }

    /// 写入流。返回实际接受的字节数（受窗口 + tx 背压限制），可能小于 bytes.len。
    pub fn write(self: *Tunnel, id: u32, bytes: []const u8) Error!usize {
        const s = try self.getStream(id);
        if (s.state != .open and s.state != .half_remote) return error.BadStreamState;
        // tx 背压：out 缓冲过大就不再接受数据（控制帧仍可发）。
        if (self.pendingTx() >= self.cfg.session_window) return 0;
        var n = @min(bytes.len, @as(usize, max_send_payload));
        n = @min(n, s.send_window);
        n = @min(n, self.session_send);
        if (n == 0) return 0;
        try self.pushFrame(.data, id, bytes[0..n]);
        s.send_window -= @intCast(n);
        self.session_send -= @intCast(n);
        return n;
    }

    /// 告知隧道：流 id 上已消费（写给下游）n 字节，可回补窗口。
    pub fn consume(self: *Tunnel, id: u32, n: u32) Error!void {
        const s = self.streams.get(id) orelse return; // 流可能已关，忽略
        s.recv_pending_ack += n;
        s.recv_remaining += n;
        self.session_recv_pending_ack += n;
        self.session_recv_remaining += n;
        if (s.recv_pending_ack >= self.cfg.stream_window / 2) {
            var wb: [4]u8 = undefined;
            std.mem.writeInt(u32, &wb, s.recv_pending_ack, .little);
            try self.pushFrame(.window, id, &wb);
            s.recv_pending_ack = 0;
        }
        if (self.session_recv_pending_ack >= self.cfg.session_window / 2) {
            var wb: [4]u8 = undefined;
            std.mem.writeInt(u32, &wb, self.session_recv_pending_ack, .little);
            try self.pushFrame(.session_window, 0, &wb);
            self.session_recv_pending_ack = 0;
        }
    }

    pub fn closeWrite(self: *Tunnel, id: u32) Error!void {
        const s = try self.getStream(id);
        try self.pushFrame(.close, id, "");
        switch (s.state) {
            .open => s.state = .half_local,
            .half_remote => self.dropStream(id),
            else => {},
        }
    }

    pub fn reset(self: *Tunnel, id: u32, reason: u8) Error!void {
        _ = try self.getStream(id);
        try self.pushFrame(.reset, id, &[_]u8{reason});
        self.dropStream(id);
    }

    fn dropStream(self: *Tunnel, id: u32) void {
        if (self.streams.fetchRemove(id)) |kv| self.alloc.destroy(kv.value);
    }

    // ===================== UDP 关联（协议 §9）=====================
    // 数据报不走窗口流控（不可靠语义）：sendDatagram 直接入 tx，tx 满则丢弃。
    // metadata / payload 对隧道不透明（socks5 层解释为地址块 / 地址块+数据）。

    pub fn openDatagram(self: *Tunnel, metadata: []const u8) Error!u32 {
        if (self.phase != .ready) return error.NotReady;
        if (self.streams.count() >= self.cfg.max_streams) return error.TooManyStreams;
        const id = self.next_id;
        self.next_id += 2;
        const s = try self.alloc.create(Stream);
        errdefer self.alloc.destroy(s);
        s.* = .{ .id = id, .kind = .udp, .state = .opening_local, .send_window = 0, .recv_remaining = 0 };
        try self.streams.put(id, s);
        try self.pushFrame(.udp_open, id, metadata);
        return id;
    }

    pub fn acceptDatagram(self: *Tunnel, id: u32, metadata: []const u8) Error!void {
        const s = try self.getStream(id);
        if (s.kind != .udp or s.state != .open_pending) return error.BadStreamState;
        s.state = .open;
        try self.pushFrame(.udp_open_ok, id, metadata);
    }

    pub fn rejectDatagram(self: *Tunnel, id: u32, code: u8) Error!void {
        const s = try self.getStream(id);
        if (s.kind != .udp or s.state != .open_pending) return error.BadStreamState;
        try self.pushFrame(.udp_open_err, id, &[_]u8{code});
        self.dropStream(id);
    }

    /// 发一个数据报。tx 过载则丢弃（返回 false），符合 UDP 可丢语义（协议 §9.3）。
    pub fn sendDatagram(self: *Tunnel, id: u32, payload: []const u8) Error!bool {
        const s = self.streams.get(id) orelse return error.NoSuchStream;
        if (s.kind != .udp or s.state != .open) return error.BadStreamState;
        if (payload.len > frame.max_payload) return false;
        if (self.pendingTx() >= self.cfg.session_window) return false; // 丢弃最新
        try self.pushFrame(.udp_data, id, payload);
        return true;
    }

    pub fn closeDatagram(self: *Tunnel, id: u32) void {
        self.dropStream(id);
    }

    // ===================== RX =====================

    pub fn recv(self: *Tunnel, from_wire: []const u8) Error!void {
        for (from_wire) |b| try self.rxByte(b);
    }

    fn startEncFrame(self: *Tunnel) void {
        self.framelen = 0;
        self.in_frame = true;
        self.decoder = encoding.Decoder.init(self.rx_enc, self.sentinel);
    }

    fn resetEncFrame(self: *Tunnel) void {
        self.framelen = 0;
        self.in_frame = false;
    }

    fn rxByte(self: *Tunnel, b: u8) Error!void {
        if (!self.rx_synced) {
            if (self.bootstrap.feedByte(b)) {
                self.rx_synced = true;
                if (self.rx_enc == .raw) {
                    self.framelen = 0;
                    self.in_frame = true;
                }
            }
            return;
        }

        // 捕获模式：收下对端 PROBE 的裸图案，直到 SS（PROBE_END 起始标记）。
        if (self.capturing) {
            if (b == self.sentinel) {
                self.cap_run += 1;
                if (self.cap_run >= 2) {
                    self.cap_run = 0;
                    self.capturing = false;
                    try self.finishCapture();
                    self.startEncFrame(); // 这个 SS 开启 PROBE_END 帧
                }
                return;
            }
            if (self.cap_run == 1) {
                self.cap_run = 0;
                self.cap_started = true;
                try self.captureByte(self.sentinel);
            }
            if (!self.cap_started and b == encoding.flush_byte) return; // 跳过图案前的框帧冲刷
            self.cap_started = true;
            try self.captureByte(b);
            return;
        }

        if (self.rx_enc == .raw) {
            if (self.framelen >= self.framebuf.len) return error.Corrupt;
            self.framebuf[self.framelen] = b;
            self.framelen += 1;
            try self.tryParseRaw();
            return;
        }

        // 编码模式：SS 标记检测在裸线字节层
        if (b == self.sentinel) {
            self.sent_run += 1;
            if (self.sent_run == 2) {
                self.startEncFrame();
                self.sent_run = 0;
            }
            return;
        }
        if (self.sent_run == 1) {
            self.sent_run = 0;
            if (self.in_frame) try self.feedByte(self.sentinel);
        }
        if (b == encoding.flush_byte) return; // 冲刷标记
        if (self.in_frame) try self.feedByte(b);
    }

    fn feedByte(self: *Tunnel, b: u8) Error!void {
        var oi = self.framelen;
        self.decoder.feed(self.framebuf, &oi, &[_]u8{b}) catch {
            // 解码非法（注入垃圾）→ 丢弃当前帧，等下一个 SS 重同步
            self.desync_count += 1;
            try self.log(.warn, "decode error, resyncing");
            self.resetEncFrame();
            return;
        };
        self.framelen = oi;
        if (self.framelen > self.framebuf.len - 4) {
            self.desync_count += 1;
            self.resetEncFrame();
            return;
        }
        try self.tryParseEnc();
    }

    fn tryParseEnc(self: *Tunnel) Error!void {
        switch (frame.parse(self.framebuf[0..self.framelen])) {
            .need_more => {},
            .bad_crc => {
                self.desync_count += 1;
                try self.log(.warn, "frame crc mismatch, resyncing");
                self.resetEncFrame();
            },
            .ok => |p| {
                try self.dispatch(p);
                self.resetEncFrame();
            },
        }
    }

    fn tryParseRaw(self: *Tunnel) Error!void {
        while (true) {
            switch (frame.parse(self.framebuf[0..self.framelen])) {
                .need_more => return,
                .bad_crc => return error.Corrupt,
                .ok => |p| {
                    const consumed = p.consumed;
                    try self.dispatch(p);
                    const rem = self.framelen - consumed;
                    if (rem > 0) std.mem.copyForwards(u8, self.framebuf[0..rem], self.framebuf[consumed..self.framelen]);
                    self.framelen = rem;
                    if (rem == 0) return;
                },
            }
        }
    }

    fn dispatch(self: *Tunnel, p: frame.Parsed) Error!void {
        const t = p.header.type;
        const sid = p.header.stream_id;
        // 会话控制帧 stream_id 必须 0；流帧必须非 0。
        if (t.isControl() and sid != 0) return error.ProtocolError;
        if (!t.isControl() and sid == 0 and t != .flush_probe and t != .flush_ack) return error.ProtocolError;

        switch (t) {
            .hello => try self.onHello(p.payload, false),
            .hello_ack => try self.onHello(p.payload, true),
            .probe => try self.onProbe(p.payload),
            .probe_end => {}, // 边界已由 SS 触发 finishCapture，此帧仅作确认
            .probe_result => try self.onProbeResult(p.payload),
            .encoding_set => try self.onEncodingSet(p.payload),
            .ping => try self.pushFrame(.pong, 0, p.payload),
            .pong => {},
            .session_window => {
                if (p.payload.len >= 4) self.session_send +|= std.mem.readInt(u32, p.payload[0..4], .little);
            },
            .shutdown => {
                self.phase = .closed;
                try self.push(.closed);
            },
            .open => try self.onOpen(sid, p.payload),
            .open_ok => try self.onOpenOk(sid, p.payload),
            .open_err => try self.onOpenErr(sid, p.payload),
            .data => try self.onData(sid, p.payload),
            .window => {
                if (p.payload.len >= 4) {
                    if (self.streams.get(sid)) |s| {
                        s.send_window +|= std.mem.readInt(u32, p.payload[0..4], .little);
                        try self.push(.{ .stream_writable = sid });
                    }
                }
            },
            .close => try self.onClose(sid),
            .reset => try self.onReset(sid, if (p.payload.len > 0) p.payload[0] else 0),
            .udp_open => try self.onUdpOpen(sid, p.payload),
            .udp_open_ok => try self.onUdpOpenOk(sid, p.payload),
            .udp_open_err => try self.onUdpOpenErr(sid, p.payload),
            .udp_data => try self.onUdpData(sid, p.payload),
            else => {}, // 未知：忽略（协议 §5.2）
        }
    }

    fn onHello(self: *Tunnel, payload: []const u8, is_ack: bool) Error!void {
        const h = hs.Hello.decode(payload) catch return error.ProtocolError;
        if (h.version != hs.protocol_version) {
            try self.pushFrame(.shutdown, 0, &[_]u8{0x02});
            return error.VersionMismatch;
        }
        self.peer_stream_window = h.stream_window;
        self.session_send = h.session_window;
        // 已建流的初始 send_window 也补上（正常此时无流）
        if (!is_ack and self.role == .server) {
            try self.sendHello(.hello_ack);
        }
        if (self.cfg.auto_probe) {
            self.phase = .probing;
            try self.startTxProbe(.raw); // 从最省的 RAW 开始逐级降档
        } else {
            self.phase = .ready;
            try self.push(.ready);
        }
    }

    // ===================== 探针（协议 §4.2）=====================

    /// 测试"我方 tx 用 cand 编码能否原样到达对端"：发 PROBE + 裸图案 + PROBE_END。
    fn startTxProbe(self: *Tunnel, cand: Encoding) Error!void {
        self.probe_cand = cand;
        self.probe_seq +%= 1;
        // 图案按 cand 编码后就是要放到线上的裸字节，同时留作比对基准。
        const n = encoding.encode(cand, self.sentinel, &self.probe_expected, &probe_pattern);
        self.probe_expected_len = n;
        var hdr: [4]u8 = undefined;
        hdr[0] = self.probe_seq;
        hdr[1] = @intFromEnum(cand);
        std.mem.writeInt(u16, hdr[2..4], @intCast(n), .little);
        // PROBE 帧不带冲刷换行——紧跟其后的裸图案不能被 \n 干扰（接收方也会跳过前导 \n）。
        try self.pushFrameEx(.probe, 0, &hdr, false);
        try self.tx.appendSlice(self.alloc, self.probe_expected[0..n]);
        try self.pushFrameEx(.probe_end, 0, &[_]u8{self.probe_seq}, true);
    }

    /// 我方 tx 编码定档：通告对端并切换。
    fn txChosen(self: *Tunnel, enc: Encoding) Error!void {
        // 切到 RAW 时不能带冲刷 \n：RAW 是裸帧，\n 会被当帧字节而错位。
        try self.pushFrameEx(.encoding_set, 0, &[_]u8{@intFromEnum(enc)}, enc != .raw);
        self.tx_enc = enc; // 此帧之后本方向改用 enc
        self.tx_decided = true;
        try self.maybeReady();
    }

    fn maybeReady(self: *Tunnel) Error!void {
        if (self.phase == .probing and self.tx_decided and self.rx_enc_set) {
            self.phase = .ready;
            try self.push(.ready);
        }
    }

    // 收到对端 PROBE：进入捕获模式，把随后的裸图案原样收下，遇 SS（PROBE_END）为止。
    fn onProbe(self: *Tunnel, payload: []const u8) Error!void {
        if (payload.len < 1) return error.ProtocolError;
        self.cap_seq = payload[0];
        self.capturing = true;
        self.cap_started = false;
        self.cap_run = 0;
        self.capture.clearRetainingCapacity();
    }

    fn captureByte(self: *Tunnel, b: u8) Error!void {
        if (self.capture.items.len < 4096) try self.capture.append(self.alloc, b);
    }

    // 捕获结束：把收到的裸字节原样回传给对端比对。
    fn finishCapture(self: *Tunnel) Error!void {
        var buf: [3 + 4096]u8 = undefined; // capture 上限 4096
        const clen = @min(self.capture.items.len, 4096);
        buf[0] = self.cap_seq;
        std.mem.writeInt(u16, buf[1..3], @intCast(clen), .little);
        @memcpy(buf[3 .. 3 + clen], self.capture.items[0..clen]);
        try self.pushFrame(.probe_result, 0, buf[0 .. 3 + clen]);
    }

    // 收到 PROBE_RESULT：比对我方 tx 是否透明。
    fn onProbeResult(self: *Tunnel, payload: []const u8) Error!void {
        if (payload.len < 3) return error.ProtocolError;
        const seq = payload[0];
        if (seq != self.probe_seq or self.tx_decided) return; // 过期/已定
        const rx_len = std.mem.readInt(u16, payload[1..3], .little);
        const rx = payload[3..];
        const ok = rx_len == self.probe_expected_len and
            rx.len >= rx_len and
            std.mem.eql(u8, rx[0..rx_len], self.probe_expected[0..self.probe_expected_len]);
        if (ok) {
            try self.logChosen(self.probe_cand);
            try self.txChosen(self.probe_cand);
        } else switch (self.probe_cand) {
            .raw => try self.startTxProbe(.esc),
            .esc => {
                // ESC 也不行：回落 B64（握手已证明它能过，不必再测）。
                try self.logChosen(.b64);
                try self.txChosen(.b64);
            },
            else => {
                try self.logChosen(.b64);
                try self.txChosen(.b64);
            },
        }
    }

    fn logChosen(self: *Tunnel, enc: Encoding) Error!void {
        const msg = switch (enc) {
            .raw => "probe: send encoding = RAW",
            .esc => "probe: send encoding = ESC",
            .b64 => "probe: send encoding = B64",
            .b32 => "probe: send encoding = B32",
        };
        try self.log(.info, msg);
    }

    fn onEncodingSet(self: *Tunnel, payload: []const u8) Error!void {
        if (payload.len < 1) return error.ProtocolError;
        const enc: Encoding = switch (payload[0]) {
            0 => .raw,
            1 => .esc,
            2 => .b64,
            3 => .b32,
            else => return error.ProtocolError,
        };
        self.rx_enc = enc; // 下一帧起本方向改用 enc（startEncFrame 会以新 rx_enc 建解码器）
        self.rx_enc_set = true;
        try self.maybeReady();
    }

    fn onOpen(self: *Tunnel, sid: u32, metadata: []const u8) Error!void {
        if (self.streams.get(sid) != null) return error.ProtocolError;
        const s = try self.alloc.create(Stream);
        errdefer self.alloc.destroy(s);
        s.* = .{
            .id = sid,
            .state = .open_pending,
            .send_window = self.peer_stream_window,
            .recv_remaining = self.cfg.stream_window,
        };
        try self.streams.put(sid, s);
        const b = try self.pushBlob(metadata);
        try self.push(.{ .stream_open = .{ .id = sid, .meta = b } });
    }

    fn onOpenOk(self: *Tunnel, sid: u32, metadata: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return error.ProtocolError;
        if (s.state != .opening_local) return error.ProtocolError;
        s.state = .open;
        const b = try self.pushBlob(metadata);
        try self.push(.{ .stream_accept = .{ .id = sid, .meta = b } });
    }

    fn onOpenErr(self: *Tunnel, sid: u32, payload: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return error.ProtocolError;
        if (s.state != .opening_local) return error.ProtocolError;
        const code: u8 = if (payload.len > 0) payload[0] else 1;
        try self.push(.{ .stream_reject = .{ .id = sid, .code = code } });
        self.dropStream(sid);
    }

    fn onData(self: *Tunnel, sid: u32, payload: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return; // 已关流的残留数据丢弃
        if (s.state != .open and s.state != .half_local) return; // 对端已 EOF 还发？忽略
        const n: u32 = @intCast(payload.len);
        if (n > s.recv_remaining or n > self.session_recv_remaining) {
            // 超窗（对端 bug）→ RESET 该流
            try self.pushFrame(.reset, sid, &[_]u8{0x03});
            self.dropStream(sid);
            return;
        }
        s.recv_remaining -= n;
        self.session_recv_remaining -= n;
        const b = try self.pushBlob(payload);
        try self.push(.{ .stream_data = .{ .id = sid, .data = b } });
    }

    fn onClose(self: *Tunnel, sid: u32) Error!void {
        const s = self.streams.get(sid) orelse return;
        try self.push(.{ .stream_eof = sid });
        switch (s.state) {
            .open => s.state = .half_remote,
            .half_local => self.dropStream(sid),
            else => {},
        }
    }

    fn onReset(self: *Tunnel, sid: u32, reason: u8) Error!void {
        if (self.streams.get(sid) == null) return;
        try self.push(.{ .stream_reset = .{ .id = sid, .reason = reason } });
        self.dropStream(sid);
    }

    fn onUdpOpen(self: *Tunnel, sid: u32, metadata: []const u8) Error!void {
        if (self.streams.get(sid) != null) return error.ProtocolError;
        const s = try self.alloc.create(Stream);
        errdefer self.alloc.destroy(s);
        s.* = .{ .id = sid, .kind = .udp, .state = .open_pending, .send_window = 0, .recv_remaining = 0 };
        try self.streams.put(sid, s);
        const b = try self.pushBlob(metadata);
        try self.push(.{ .datagram_open = .{ .id = sid, .meta = b } });
    }

    fn onUdpOpenOk(self: *Tunnel, sid: u32, metadata: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return error.ProtocolError;
        if (s.kind != .udp or s.state != .opening_local) return error.ProtocolError;
        s.state = .open;
        const b = try self.pushBlob(metadata);
        try self.push(.{ .datagram_accept = .{ .id = sid, .meta = b } });
    }

    fn onUdpOpenErr(self: *Tunnel, sid: u32, payload: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return error.ProtocolError;
        if (s.kind != .udp or s.state != .opening_local) return error.ProtocolError;
        const code: u8 = if (payload.len > 0) payload[0] else 1;
        try self.push(.{ .datagram_reject = .{ .id = sid, .code = code } });
        self.dropStream(sid);
    }

    fn onUdpData(self: *Tunnel, sid: u32, payload: []const u8) Error!void {
        const s = self.streams.get(sid) orelse return; // 关联已关，丢弃
        if (s.kind != .udp or s.state != .open) return;
        const b = try self.pushBlob(payload);
        try self.push(.{ .datagram = .{ .id = sid, .data = b } });
    }

    // ===================== 计时 =====================

    pub fn tick(self: *Tunnel, now_ms: u64) Error!void {
        if (self.start_ms == null) {
            self.start_ms = now_ms;
            self.last_rx_ms = now_ms;
            self.last_ping_ms = now_ms;
        }
        if (self.phase != .ready) {
            if (now_ms - self.start_ms.? >= self.cfg.handshake_timeout_ms) return error.HandshakeTimeout;
            return;
        }
        if (now_ms - self.last_rx_ms >= self.cfg.idle_timeout_ms) return error.IdleTimeout;
        if (now_ms - self.last_ping_ms >= self.cfg.keepalive_ms) {
            self.last_ping_ms = now_ms;
            var pb: [8]u8 = undefined;
            std.mem.writeInt(u64, &pb, now_ms, .little);
            try self.pushFrame(.ping, 0, &pb);
        }
    }

    pub fn isReady(self: *Tunnel) bool {
        return self.phase == .ready;
    }

    /// 探针/协商定下的编码（供内省与测试）。
    pub fn txEncoding(self: *Tunnel) Encoding {
        return self.tx_enc;
    }
    pub fn rxEncoding(self: *Tunnel) Encoding {
        return self.rx_enc;
    }
    pub fn desyncCount(self: *Tunnel) u32 {
        return self.desync_count;
    }
};

test {
    _ = hs;
}
