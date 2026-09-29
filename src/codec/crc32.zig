//! CRC-32/ISO-HDLC（即 zlib/PNG 所用 CRC）。
//! 协议里探针（协议 §4.2）与逻辑帧尾（协议 §5.1）共用这一份实现。
//! 纯计算，无 syscall，可 freestanding 编译。

const std = @import("std");

const table: [256]u32 = blk: {
    @setEvalBranchQuota(20000);
    var t: [256]u32 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        var c: u32 = @intCast(i);
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            c = if (c & 1 != 0) 0xEDB88320 ^ (c >> 1) else c >> 1;
        }
        t[i] = c;
    }
    break :blk t;
};

/// 增量式：多次 update 后 final。
pub const Hasher = struct {
    state: u32 = 0xFFFF_FFFF,

    pub fn update(self: *Hasher, data: []const u8) void {
        var crc = self.state;
        for (data) |b| {
            crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        }
        self.state = crc;
    }

    pub fn final(self: Hasher) u32 {
        return self.state ^ 0xFFFF_FFFF;
    }
};

/// 一次性算完一段数据的 CRC32。
pub fn hash(data: []const u8) u32 {
    var h = Hasher{};
    h.update(data);
    return h.final();
}

test "known vectors" {
    try std.testing.expectEqual(@as(u32, 0x0000_0000), hash(""));
    try std.testing.expectEqual(@as(u32, 0xCBF4_3926), hash("123456789"));
    try std.testing.expectEqual(@as(u32, 0x414F_A339), hash("The quick brown fox jumps over the lazy dog"));
}

test "incremental equals one-shot" {
    const msg = "the quick brown fox";
    var h = Hasher{};
    h.update(msg[0..4]);
    h.update(msg[4..]);
    try std.testing.expectEqual(hash(msg), h.final());
}
