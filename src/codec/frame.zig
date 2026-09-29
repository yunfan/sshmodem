//! 逻辑帧编解码（协议 §5.1）：头 8 字节 + payload + 尾 4 字节 CRC32。
//! CRC 校验范围是「头 + payload」，不含帧尾自身。
//! 帧头字段一律小端。纯计算，无 syscall。

const std = @import("std");
const crc32 = @import("crc32.zig");

pub const protocol_version: u8 = 1;

pub const header_len = 8;
pub const crc_len = 4;

/// DATA payload 上限（协议 §5.3）。B64/B32 模式另有更小上限，由上层控制。
pub const max_data_payload = 16384;
/// 任何帧 payload 的硬上限（length 是 u16）。
pub const max_payload = 65535;

/// 帧类型（协议 §5.3）。非穷举枚举：未知值能安全承载，由 isKnown 校验。
pub const Type = enum(u8) {
    hello = 0x01,
    hello_ack = 0x02,
    probe = 0x03,
    probe_end = 0x04,
    probe_result = 0x05,
    encoding_set = 0x06,
    flush_probe = 0x07,
    flush_ack = 0x08,
    ping = 0x09,
    pong = 0x0A,
    shutdown = 0x0B,
    session_window = 0x0C,
    open = 0x10,
    open_ok = 0x11,
    open_err = 0x12,
    data = 0x13,
    window = 0x14,
    close = 0x15,
    reset = 0x16,
    udp_open = 0x20,
    udp_open_ok = 0x21,
    udp_open_err = 0x22,
    udp_data = 0x23,
    _,

    pub fn isKnown(t: Type) bool {
        return switch (t) {
            _ => false,
            else => true,
        };
    }

    /// 会话控制帧（stream_id 必须为 0）。
    pub fn isControl(t: Type) bool {
        return @intFromEnum(t) < 0x10;
    }
};

pub const Header = struct {
    type: Type,
    flags: u8 = 0,
    length: u16,
    stream_id: u32,
};

/// 编码后总长度。
pub fn frameLen(payload_len: usize) usize {
    return header_len + payload_len + crc_len;
}

pub const EncodeError = error{ PayloadTooLong, ShortBuffer };

/// 把一个逻辑帧编码进 out，返回写入长度。length 字段自动置为 payload.len。
pub fn encode(out: []u8, h: Header, payload: []const u8) EncodeError!usize {
    if (payload.len > max_payload) return error.PayloadTooLong;
    const total = frameLen(payload.len);
    if (out.len < total) return error.ShortBuffer;

    out[0] = @intFromEnum(h.type);
    out[1] = h.flags;
    std.mem.writeInt(u16, out[2..4], @intCast(payload.len), .little);
    std.mem.writeInt(u32, out[4..8], h.stream_id, .little);
    @memcpy(out[header_len .. header_len + payload.len], payload);

    const crc = crc32.hash(out[0 .. header_len + payload.len]);
    std.mem.writeInt(u32, out[header_len + payload.len ..][0..4], crc, .little);
    return total;
}

pub const Parsed = struct {
    header: Header,
    payload: []const u8, // 借用输入缓冲
    consumed: usize,
};

/// 解析结果：字节不够、CRC 错、或成功。
/// CRC 错交给上层决定处理（RAW 致命 / ESC·B64 重同步，协议 §5.6）。
pub const ParseResult = union(enum) {
    need_more,
    bad_crc,
    ok: Parsed,
};

/// 从（已解码的）字节缓冲里尝试解析一个逻辑帧。
pub fn parse(buf: []const u8) ParseResult {
    if (buf.len < header_len) return .need_more;
    const length = std.mem.readInt(u16, buf[2..4], .little);
    const total = frameLen(length);
    if (buf.len < total) return .need_more;

    const want = std.mem.readInt(u32, buf[header_len + length ..][0..4], .little);
    const got = crc32.hash(buf[0 .. header_len + length]);
    if (want != got) return .bad_crc;

    return .{ .ok = .{
        .header = .{
            .type = @enumFromInt(buf[0]),
            .flags = buf[1],
            .length = length,
            .stream_id = std.mem.readInt(u32, buf[4..8], .little),
        },
        .payload = buf[header_len .. header_len + length],
        .consumed = total,
    } };
}

test "round-trip" {
    var buf: [128]u8 = undefined;
    const payload = "hello world";
    const n = try encode(&buf, .{ .type = .data, .stream_id = 7, .length = 0 }, payload);
    try std.testing.expectEqual(frameLen(payload.len), n);
    switch (parse(buf[0..n])) {
        .ok => |p| {
            try std.testing.expectEqual(Type.data, p.header.type);
            try std.testing.expectEqual(@as(u32, 7), p.header.stream_id);
            try std.testing.expectEqualStrings(payload, p.payload);
            try std.testing.expectEqual(n, p.consumed);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "empty payload round-trip" {
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, .{ .type = .close, .stream_id = 3, .length = 0 }, "");
    switch (parse(buf[0..n])) {
        .ok => |p| {
            try std.testing.expectEqual(@as(usize, 0), p.payload.len);
            try std.testing.expectEqual(Type.close, p.header.type);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "need_more when short" {
    var buf: [128]u8 = undefined;
    const n = try encode(&buf, .{ .type = .data, .stream_id = 1, .length = 0 }, "abcdef");
    try std.testing.expect(parse(buf[0 .. n - 1]) == .need_more);
    try std.testing.expect(parse(buf[0..3]) == .need_more);
}

test "corrupted byte -> bad_crc" {
    var buf: [128]u8 = undefined;
    const n = try encode(&buf, .{ .type = .data, .stream_id = 1, .length = 0 }, "abcdef");
    buf[9] ^= 0xFF; // 翻一个 payload 字节
    try std.testing.expect(parse(buf[0..n]) == .bad_crc);
}

test "unknown type parses but flagged" {
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, .{ .type = @enumFromInt(0x7E), .stream_id = 0, .length = 0 }, "");
    switch (parse(buf[0..n])) {
        .ok => |p| try std.testing.expect(!p.header.type.isKnown()),
        else => return error.TestUnexpectedResult,
    }
}
