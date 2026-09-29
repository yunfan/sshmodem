//! SOCKS5 报文解析与应答构造（RFC 1928，协议 §8）。纯 sans-io，无 syscall。
//!
//! 这一层只懂 SOCKS5 线格式。它解析出的地址块（ATYP+ADDR+PORT 原始字节）
//! 会被上层原样当作隧道 open 的元数据搬运——三层之间零翻译（协议 §5.4、§8）。

const std = @import("std");
const address = @import("../codec/address.zig");

pub const version: u8 = 0x05;
pub const auth_none: u8 = 0x00;
pub const auth_unacceptable: u8 = 0xFF;

pub const Cmd = enum(u8) { connect = 1, bind = 2, udp_associate = 3, _ };

/// SOCKS5 应答码（协议 §8）。与隧道 OPEN_ERR 的 payload 同值，零翻译。
pub const Rep = enum(u8) {
    success = 0,
    general = 1,
    not_allowed = 2,
    net_unreach = 3,
    host_unreach = 4,
    refused = 5,
    ttl_expired = 6,
    cmd_unsupported = 7,
    atyp_unsupported = 8,
    _,
};

pub const ParseError = error{ BadVersion, BadAddress };

// ---- 握手问候：VER NMETHODS METHODS... ----

pub const Greeting = struct { consumed: usize, no_auth: bool };
pub const GreetingResult = union(enum) { need_more, ok: Greeting };

pub fn parseGreeting(buf: []const u8) ParseError!GreetingResult {
    if (buf.len < 2) return .need_more;
    if (buf[0] != version) return error.BadVersion;
    const nmethods = buf[1];
    const total = 2 + @as(usize, nmethods);
    if (buf.len < total) return .need_more;
    var no_auth = false;
    for (buf[2..total]) |m| {
        if (m == auth_none) no_auth = true;
    }
    return .{ .ok = .{ .consumed = total, .no_auth = no_auth } };
}

/// 方法选择应答：VER METHOD。
pub fn methodReply(method: u8) [2]u8 {
    return .{ version, method };
}

// ---- 请求：VER CMD RSV ATYP DST.ADDR DST.PORT ----

pub const Request = struct {
    cmd: Cmd,
    addr: address.Address,
    /// ATYP+ADDR+PORT 原始字节切片（借用 buf），直接用作隧道 open 元数据。
    addr_block: []const u8,
    consumed: usize,
};
pub const RequestResult = union(enum) { need_more, ok: Request };

pub fn parseRequest(buf: []const u8) ParseError!RequestResult {
    if (buf.len < 4) return .need_more;
    if (buf[0] != version) return error.BadVersion;
    const cmd: Cmd = @enumFromInt(buf[1]);
    // buf[2] = RSV, buf[3..] = ATYP+ADDR+PORT
    const dec = address.decode(buf[3..]) catch |e| switch (e) {
        error.ShortBuffer => return .need_more,
        else => return error.BadAddress,
    };
    const consumed = 3 + dec.consumed;
    return .{ .ok = .{
        .cmd = cmd,
        .addr = dec.addr,
        .addr_block = buf[3..consumed],
        .consumed = consumed,
    } };
}

/// 应答：VER REP 00 ATYP BND.ADDR BND.PORT。返回写入长度。
pub fn buildReply(out: []u8, rep: Rep, bind: address.Address) usize {
    out[0] = version;
    out[1] = @intFromEnum(rep);
    out[2] = 0x00; // RSV
    const n = bind.encode(out[3..]);
    return 3 + n;
}

/// 全零 IPv4:0 的绑定地址，用于失败应答或无意义 BND 场景。
pub const null_bind = address.Address{ .host = .{ .ipv4 = .{ 0, 0, 0, 0 } }, .port = 0 };

/// 便捷：构造一个失败应答（BND 用全零）。
pub fn buildError(out: []u8, rep: Rep) usize {
    return buildReply(out, rep, null_bind);
}

test "greeting parse" {
    switch (try parseGreeting(&[_]u8{ 0x05, 0x01, 0x00 })) {
        .ok => |g| {
            try std.testing.expect(g.no_auth);
            try std.testing.expectEqual(@as(usize, 3), g.consumed);
        },
        else => return error.TestUnexpectedResult,
    }
    // 分片：先给 2 字节说要 2 methods，不够。
    try std.testing.expect(try parseGreeting(&[_]u8{ 0x05, 0x02, 0x00 }) == .need_more);
    try std.testing.expectError(error.BadVersion, parseGreeting(&[_]u8{ 0x04, 0x01, 0x00 }));
}

test "connect request parse, domain" {
    // VER CMD RSV ATYP=3 len=11 "example.com" port=443
    const req = [_]u8{ 0x05, 0x01, 0x00, 0x03, 0x0b } ++ "example.com".* ++ [_]u8{ 0x01, 0xbb };
    switch (try parseRequest(&req)) {
        .ok => |r| {
            try std.testing.expectEqual(Cmd.connect, r.cmd);
            try std.testing.expectEqualStrings("example.com", r.addr.host.domain);
            try std.testing.expectEqual(@as(u16, 443), r.addr.port);
            try std.testing.expectEqual(req.len, r.consumed);
            // addr_block 原样是请求里的地址部分
            try std.testing.expectEqualSlices(u8, req[3..], r.addr_block);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "request need_more when truncated" {
    const partial = [_]u8{ 0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x' };
    try std.testing.expect(try parseRequest(&partial) == .need_more);
}

test "reply round-trips through address decoder" {
    var out: [32]u8 = undefined;
    const bind = address.Address{ .host = .{ .ipv4 = .{ 127, 0, 0, 1 } }, .port = 1080 };
    const n = buildReply(&out, .success, bind);
    try std.testing.expectEqual(version, out[0]);
    try std.testing.expectEqual(@as(u8, 0), out[1]);
    const dec = try address.decode(out[3..n]);
    try std.testing.expectEqual(@as(u16, 1080), dec.addr.port);
}
