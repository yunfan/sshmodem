//! RFC 1928 地址块编解码（协议 §5.4）。
//! 端口是大端（照抄 SOCKS5），使 SOCKS5 请求里的地址字节能原样搬运。
//! 纯计算，无 syscall。

const std = @import("std");

pub const Atyp = enum(u8) {
    ipv4 = 0x01,
    domain = 0x03,
    ipv6 = 0x04,
};

/// 一个地址。域名情形下 `host.domain` 指向调用方缓冲区（sans-io：不复制）。
pub const Address = struct {
    host: Host,
    port: u16,

    pub const Host = union(enum) {
        ipv4: [4]u8,
        ipv6: [16]u8,
        domain: []const u8, // 不含结尾 0，长度 1..255
    };

    /// 编码后占多少字节。
    pub fn encodedLen(self: Address) usize {
        return switch (self.host) {
            .ipv4 => 1 + 4 + 2,
            .ipv6 => 1 + 16 + 2,
            .domain => |d| 1 + 1 + d.len + 2,
        };
    }

    /// 编码进 out（须足够大，见 encodedLen），返回写入长度。
    pub fn encode(self: Address, out: []u8) usize {
        var i: usize = 0;
        switch (self.host) {
            .ipv4 => |a| {
                out[i] = @intFromEnum(Atyp.ipv4);
                i += 1;
                @memcpy(out[i .. i + 4], &a);
                i += 4;
            },
            .ipv6 => |a| {
                out[i] = @intFromEnum(Atyp.ipv6);
                i += 1;
                @memcpy(out[i .. i + 16], &a);
                i += 16;
            },
            .domain => |d| {
                out[i] = @intFromEnum(Atyp.domain);
                i += 1;
                out[i] = @intCast(d.len);
                i += 1;
                @memcpy(out[i .. i + d.len], d);
                i += d.len;
            },
        }
        std.mem.writeInt(u16, out[i..][0..2], self.port, .big);
        i += 2;
        return i;
    }
};

pub const DecodeError = error{ ShortBuffer, BadAtyp, BadDomainLen };

pub const Decoded = struct {
    addr: Address,
    consumed: usize,
};

/// 从 buf 解出一个地址块。域名切片借用 buf，调用方须保证 buf 存活。
pub fn decode(buf: []const u8) DecodeError!Decoded {
    if (buf.len < 1) return error.ShortBuffer;
    const atyp: Atyp = switch (buf[0]) {
        0x01 => .ipv4,
        0x03 => .domain,
        0x04 => .ipv6,
        else => return error.BadAtyp,
    };
    return switch (atyp) {
        .ipv4 => blk: {
            if (buf.len < 1 + 4 + 2) return error.ShortBuffer;
            var a: [4]u8 = undefined;
            @memcpy(&a, buf[1..5]);
            break :blk .{
                .addr = .{ .host = .{ .ipv4 = a }, .port = std.mem.readInt(u16, buf[5..7], .big) },
                .consumed = 7,
            };
        },
        .ipv6 => blk: {
            if (buf.len < 1 + 16 + 2) return error.ShortBuffer;
            var a: [16]u8 = undefined;
            @memcpy(&a, buf[1..17]);
            break :blk .{
                .addr = .{ .host = .{ .ipv6 = a }, .port = std.mem.readInt(u16, buf[17..19], .big) },
                .consumed = 19,
            };
        },
        .domain => blk: {
            if (buf.len < 2) return error.ShortBuffer;
            const dlen = buf[1];
            if (dlen == 0) return error.BadDomainLen;
            const total = 2 + @as(usize, dlen) + 2;
            if (buf.len < total) return error.ShortBuffer;
            break :blk .{
                .addr = .{
                    .host = .{ .domain = buf[2 .. 2 + dlen] },
                    .port = std.mem.readInt(u16, buf[2 + dlen ..][0..2], .big),
                },
                .consumed = total,
            };
        },
    };
}

test "ipv4 round-trip" {
    const a = Address{ .host = .{ .ipv4 = .{ 1, 2, 3, 4 } }, .port = 8080 };
    var buf: [32]u8 = undefined;
    const n = a.encode(&buf);
    try std.testing.expectEqual(a.encodedLen(), n);
    const d = try decode(buf[0..n]);
    try std.testing.expectEqual(@as(usize, 7), d.consumed);
    try std.testing.expectEqualSlices(u8, &a.host.ipv4, &d.addr.host.ipv4);
    try std.testing.expectEqual(@as(u16, 8080), d.addr.port);
}

test "domain round-trip" {
    const a = Address{ .host = .{ .domain = "example.com" }, .port = 443 };
    var buf: [64]u8 = undefined;
    const n = a.encode(&buf);
    const d = try decode(buf[0..n]);
    try std.testing.expectEqualStrings("example.com", d.addr.host.domain);
    try std.testing.expectEqual(@as(u16, 443), d.addr.port);
    try std.testing.expectEqual(n, d.consumed);
}

test "ipv6 round-trip" {
    const a = Address{ .host = .{ .ipv6 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } }, .port = 53 };
    var buf: [64]u8 = undefined;
    const n = a.encode(&buf);
    const d = try decode(buf[0..n]);
    try std.testing.expectEqualSlices(u8, &a.host.ipv6, &d.addr.host.ipv6);
    try std.testing.expectEqual(@as(u16, 53), d.addr.port);
}

test "malformed inputs error, never panic" {
    try std.testing.expectError(error.ShortBuffer, decode(""));
    try std.testing.expectError(error.BadAtyp, decode(&[_]u8{0x02}));
    try std.testing.expectError(error.ShortBuffer, decode(&[_]u8{ 0x01, 1, 2 }));
    try std.testing.expectError(error.BadDomainLen, decode(&[_]u8{ 0x03, 0x00, 1, 2 }));
    // 域名长度声称 5 但缓冲不足
    try std.testing.expectError(error.ShortBuffer, decode(&[_]u8{ 0x03, 0x05, 'a', 'b' }));
}
