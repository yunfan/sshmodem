//! POSIX socket / DNS 辅助（链接 libc）。仅 io 层使用，不属于 sans-io 核心。
//! 非阻塞 socket + std.posix.poll 事件循环的底座。

const std = @import("std");
const c = std.c;
const posix = std.posix;

pub const fd_t = posix.fd_t;

pub const IoError = error{ SocketFailed, BindFailed, ListenFailed, ConnectFailed, ResolveFailed, Unexpected };

fn cerrno() posix.E {
    return @enumFromInt(c._errno().*);
}

const O_NONBLOCK: c_int = 0o4000; // Linux
pub fn setNonBlock(fd: fd_t) void {
    const flags = c.fcntl(fd, @as(c_int, 3), @as(c_int, 0)); // F_GETFL
    _ = c.fcntl(fd, @as(c_int, 4), flags | O_NONBLOCK); // F_SETFL
}

/// 建一个非阻塞 TCP socket（IPv4）。
pub fn tcpSocket() IoError!fd_t {
    const s = c.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    if (s < 0) return error.SocketFailed;
    setNonBlock(s);
    return s;
}

/// 监听 127.0.0.1:port（或给定 IPv4）。返回监听 fd。
pub fn listenTcp(ip4: [4]u8, port: u16) IoError!fd_t {
    const s = try tcpSocket();
    errdefer close(s);
    const one: c_int = 1;
    _ = c.setsockopt(s, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&one), @as(posix.socklen_t, @sizeOf(c_int)));
    var addr = std.mem.zeroes(posix.sockaddr.in);
    addr.family = posix.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = @bitCast(ip4);
    if (c.bind(s, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) != 0) return error.BindFailed;
    if (c.listen(s, 128) != 0) return error.ListenFailed;
    return s;
}

/// accept 一个连接；无连接时返回 null（EAGAIN）。
pub fn accept(listen_fd: fd_t) ?fd_t {
    const s = c.accept(listen_fd, null, null);
    if (s < 0) return null;
    setNonBlock(s);
    return s;
}

pub const ConnectStart = union(enum) {
    /// 连接已建立或仍在进行（EINPROGRESS）；poll 可写后用 connectResult 确认。
    fd: fd_t,
    /// 立即失败（loopback 拒绝等常见），带 errno 供上层映射成 SOCKS5 REP。
    failed: posix.E,
};

/// 发起非阻塞 connect 到 IPv4。
pub fn connectTcp4(ip4: [4]u8, port: u16) IoError!ConnectStart {
    const s = try tcpSocket();
    var addr = std.mem.zeroes(posix.sockaddr.in);
    addr.family = posix.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = @bitCast(ip4);
    const r = c.connect(s, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    if (r != 0) {
        const e = cerrno();
        if (e != posix.E.INPROGRESS) {
            close(s);
            return .{ .failed = e };
        }
    }
    return .{ .fd = s };
}

/// connect 完成后查 SO_ERROR：0 成功，否则 errno。
pub fn connectResult(fd: fd_t) posix.E {
    var err: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    _ = c.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err), &len);
    return @enumFromInt(err);
}

/// 解析域名到首个 IPv4。域名走远端解析，正是隧道的意义（协议 §5.4）。
pub fn resolve4(host: [:0]const u8, port: u16) IoError![4]u8 {
    var hints = std.mem.zeroes(c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.STREAM;
    var res: ?*c.addrinfo = null;
    var portbuf: [8]u8 = undefined;
    const ports = std.fmt.bufPrintZ(&portbuf, "{d}", .{port}) catch return error.ResolveFailed;
    const rc = c.getaddrinfo(host.ptr, ports.ptr, &hints, &res);
    if (@intFromEnum(rc) != 0) return error.ResolveFailed;
    const ai = res orelse return error.ResolveFailed;
    defer c.freeaddrinfo(ai);
    const sa: *posix.sockaddr.in = @ptrCast(@alignCast(ai.addr.?));
    return @bitCast(sa.addr);
}

pub const RwResult = union(enum) { n: usize, again, eof, err };

pub fn readFd(fd: fd_t, buf: []u8) RwResult {
    const r = c.read(fd, buf.ptr, buf.len);
    if (r > 0) return .{ .n = @intCast(r) };
    if (r == 0) return .eof;
    return switch (cerrno()) {
        posix.E.AGAIN, posix.E.INTR => .again,
        else => .err,
    };
}

pub fn writeFd(fd: fd_t, buf: []const u8) RwResult {
    const r = c.write(fd, buf.ptr, buf.len);
    if (r >= 0) return .{ .n = @intCast(r) };
    return switch (cerrno()) {
        posix.E.AGAIN, posix.E.INTR => .again,
        else => .err,
    };
}

pub fn close(fd: fd_t) void {
    _ = c.close(fd);
}

pub fn shutdownWrite(fd: fd_t) void {
    _ = c.shutdown(fd, posix.SHUT.WR);
}

// ===================== UDP（协议 §9）=====================

pub const SockAddr4 = posix.sockaddr.in;

pub fn udpSocket() IoError!fd_t {
    const s = c.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    if (s < 0) return error.SocketFailed;
    setNonBlock(s);
    return s;
}

/// 绑定 UDP socket 到 ip4:port（port=0 让内核选）。
pub fn udpBind(fd: fd_t, ip4: [4]u8, port: u16) IoError!void {
    var addr = std.mem.zeroes(SockAddr4);
    addr.family = posix.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = @bitCast(ip4);
    if (c.bind(fd, @ptrCast(&addr), @sizeOf(SockAddr4)) != 0) return error.BindFailed;
}

/// 取本地绑定端口（主机序）。
pub fn localPort(fd: fd_t) u16 {
    var addr = std.mem.zeroes(SockAddr4);
    var len: posix.socklen_t = @sizeOf(SockAddr4);
    _ = c.getsockname(fd, @ptrCast(&addr), &len);
    return std.mem.bigToNative(u16, addr.port);
}

pub const RecvFrom = struct { n: usize, ip4: [4]u8, port: u16 };

pub fn recvFrom4(fd: fd_t, buf: []u8) ?RecvFrom {
    var addr = std.mem.zeroes(SockAddr4);
    var len: posix.socklen_t = @sizeOf(SockAddr4);
    const r = c.recvfrom(fd, buf.ptr, buf.len, 0, @ptrCast(&addr), &len);
    if (r < 0) return null;
    return .{ .n = @intCast(r), .ip4 = @bitCast(addr.addr), .port = std.mem.bigToNative(u16, addr.port) };
}

pub fn sendTo4(fd: fd_t, buf: []const u8, ip4: [4]u8, port: u16) void {
    var addr = std.mem.zeroes(SockAddr4);
    addr.family = posix.AF.INET;
    addr.port = std.mem.nativeToBig(u16, port);
    addr.addr = @bitCast(ip4);
    _ = c.sendto(fd, buf.ptr, buf.len, 0, @ptrCast(&addr), @sizeOf(SockAddr4));
}
