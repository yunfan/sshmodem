//! 传输编码层（协议 §3）：RAW / ESC / B64 / B32 四档，哨兵字节参数化。
//!
//! 帧层永远认为自己在一条 8-bit clean 的线上；所有脏活由本层吸收。
//! 本层只做「一段字节 → 线上字节」的纯变换：
//!   - `SS`（哨兵重复两次）帧起始标记、`\n` 冲刷、`%%` 重同步这些**定界**逻辑，
//!     属于上层（reader/session），不在本文件；
//!   - 但**解码必须是流式的**（转义序列、base 四元/五元组都可能跨 read 分片），
//!     所以本层提供带状态的 `Decoder`。
//!
//! 不变量（协议 §2.1、§13.2）：ESC/B64/B32 的输出中**永不出现 `SS`**。
//! 本文件的 test 会遍历安全哨兵池 + 随机数据把这条钉死。
//!
//! 纯计算，无 syscall，可 freestanding 编译。

const std = @import("std");

pub const Encoding = enum(u8) { raw = 0, esc = 1, b64 = 2, b32 = 3 };

/// 冲刷标记：裸 0x0A（协议 §3.5）。ESC/B64/B32 下它不可能是数据，解码时跳过。
pub const flush_byte: u8 = '\n';

const b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const b32_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// ESC 总要转义的危险控制字节（协议 §3.3）。含 0x0A，故真实换行会被转义，
/// 裸 0x0A 便只可能是冲刷标记。
pub const esc_danger = [_]u8{
    0x00, 0x03, 0x04, 0x0A, 0x0D, 0x11, 0x13, 0x15,
    0x17, 0x1A, 0x1B, 0x1C, 0x0E, 0x7F, 0xFF,
};

fn isDanger(b: u8) bool {
    for (esc_danger) |d| if (d == b) return true;
    return false;
}

fn escNeeds(b: u8, sentinel: u8) bool {
    return b == sentinel or isDanger(b);
}

/// encode 输出长度上限（用于给缓冲定容）。
pub fn encodeBound(enc: Encoding, data_len: usize) usize {
    return switch (enc) {
        .raw => data_len,
        .esc => data_len * 2,
        .b64 => (data_len + 2) / 3 * 4 + 4,
        .b32 => (data_len + 4) / 5 * 8 + 8,
    };
}

fn baseEncode(out: []u8, data: []const u8, alpha: []const u8, bpc: u5, group: usize) usize {
    const mask: u32 = (@as(u32, 1) << bpc) - 1;
    var acc: u32 = 0;
    var nbits: u5 = 0;
    var oi: usize = 0;
    for (data) |b| {
        acc = (acc << 8) | b;
        nbits += 8;
        while (nbits >= bpc) {
            nbits -= bpc;
            out[oi] = alpha[(acc >> nbits) & mask];
            oi += 1;
        }
    }
    if (nbits > 0) {
        out[oi] = alpha[(acc << (bpc - nbits)) & mask];
        oi += 1;
    }
    while (oi % group != 0) {
        out[oi] = '=';
        oi += 1;
    }
    return oi;
}

/// 把 data 按 enc 编码进 out，返回写入长度。out 须 >= encodeBound。
pub fn encode(enc: Encoding, sentinel: u8, out: []u8, data: []const u8) usize {
    switch (enc) {
        .raw => {
            @memcpy(out[0..data.len], data);
            return data.len;
        },
        .esc => {
            var oi: usize = 0;
            for (data) |b| {
                if (escNeeds(b, sentinel)) {
                    out[oi] = sentinel;
                    out[oi + 1] = b ^ 0x40;
                    oi += 2;
                } else {
                    out[oi] = b;
                    oi += 1;
                }
            }
            return oi;
        },
        .b64 => return baseEncode(out, data, b64_alpha, 6, 4),
        .b32 => return baseEncode(out, data, b32_alpha, 5, 8),
    }
}

pub const DecodeError = error{Invalid};

/// 流式解码器：喂进（去掉了 SS 标记的）编码内容流，解出原始字节。
/// 跨分片的转义序列 / base 组由内部状态承接。裸 0x0A 冲刷标记被跳过。
pub const Decoder = struct {
    enc: Encoding,
    sentinel: u8,
    esc_pending: bool = false,
    acc: u32 = 0,
    nbits: u5 = 0,
    saw_pad: bool = false,

    pub fn init(enc: Encoding, sentinel: u8) Decoder {
        return .{ .enc = enc, .sentinel = sentinel };
    }

    fn baseVal(self: *Decoder, ch: u8) DecodeError!u8 {
        return switch (self.enc) {
            .b64 => switch (ch) {
                'A'...'Z' => ch - 'A',
                'a'...'z' => ch - 'a' + 26,
                '0'...'9' => ch - '0' + 52,
                '+' => 62,
                '/' => 63,
                else => error.Invalid,
            },
            .b32 => switch (ch) {
                'A'...'Z' => ch - 'A',
                '2'...'7' => ch - '2' + 26,
                else => error.Invalid,
            },
            else => unreachable,
        };
    }

    /// 解码一块，追加到 out（从 oi 处，caller 保证足够大），推进 oi。
    pub fn feed(self: *Decoder, out: []u8, oi: *usize, chunk: []const u8) DecodeError!void {
        switch (self.enc) {
            .raw => {
                @memcpy(out[oi.* .. oi.* + chunk.len], chunk);
                oi.* += chunk.len;
            },
            .esc => {
                for (chunk) |ch| {
                    if (self.esc_pending) {
                        out[oi.*] = ch ^ 0x40;
                        oi.* += 1;
                        self.esc_pending = false;
                    } else if (ch == self.sentinel) {
                        self.esc_pending = true;
                    } else if (ch == flush_byte) {
                        // 冲刷标记，跳过
                    } else {
                        out[oi.*] = ch;
                        oi.* += 1;
                    }
                }
            },
            .b64, .b32 => {
                const bpc: u5 = if (self.enc == .b64) 6 else 5;
                for (chunk) |ch| {
                    if (ch == flush_byte) continue;
                    if (ch == '=') {
                        self.saw_pad = true;
                        continue;
                    }
                    if (self.saw_pad) return error.Invalid; // 填充后又来数据
                    const v = try self.baseVal(ch);
                    self.acc = (self.acc << bpc) | v;
                    self.nbits += bpc;
                    if (self.nbits >= 8) {
                        self.nbits -= 8;
                        out[oi.*] = @intCast((self.acc >> self.nbits) & 0xFF);
                        oi.* += 1;
                    }
                    if (self.nbits > 0) {
                        self.acc &= (@as(u32, 1) << self.nbits) - 1;
                    } else {
                        self.acc = 0;
                    }
                }
            },
        }
    }
};

/// 便捷：一次性解码整段（内部就是喂给 Decoder）。返回写入 out 的长度。
pub fn decode(enc: Encoding, sentinel: u8, out: []u8, wire: []const u8) DecodeError!usize {
    var d = Decoder.init(enc, sentinel);
    var oi: usize = 0;
    try d.feed(out, &oi, wire);
    return oi;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const derive = @import("derive.zig");

fn roundTrip(enc: Encoding, sentinel: u8, data: []const u8) !void {
    var enc_buf: [4096]u8 = undefined;
    var dec_buf: [4096]u8 = undefined;
    const wlen = encode(enc, sentinel, &enc_buf, data);
    try std.testing.expect(wlen <= encodeBound(enc, data.len));
    const dlen = try decode(enc, sentinel, &dec_buf, enc_buf[0..wlen]);
    try std.testing.expectEqualSlices(u8, data, dec_buf[0..dlen]);
}

test "round-trip all encodings, tricky inputs" {
    var all256: [256]u8 = undefined;
    for (&all256, 0..) |*p, i| p.* = @intCast(i);
    const inputs = [_][]const u8{
        "",
        "a",
        "hello world",
        &all256,
        &[_]u8{ '%', '%', '%', '%' },
        &[_]u8{ '\n', '\n', 0x0D, 0x0A },
        &[_]u8{ 0xFF, 0xFF, 0x00, 0x00 },
    };
    for ([_]Encoding{ .raw, .esc, .b64, .b32 }) |enc| {
        for (inputs) |in| try roundTrip(enc, derive.default_sentinel, in);
    }
}

test "invariant: no SS in output, across whole sentinel pool" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const rng = prng.random();
    var data: [512]u8 = undefined;
    var enc_buf: [2048]u8 = undefined;

    for (derive.sentinel_pool) |sentinel| {
        for ([_]Encoding{ .esc, .b64, .b32 }) |enc| {
            var trial: usize = 0;
            while (trial < 200) : (trial += 1) {
                rng.bytes(&data);
                const wlen = encode(enc, sentinel, &enc_buf, &data);
                var i: usize = 1;
                while (i < wlen) : (i += 1) {
                    if (enc_buf[i] == sentinel and enc_buf[i - 1] == sentinel) {
                        std.debug.print("SS found: enc={} sentinel={c}\n", .{ enc, sentinel });
                        return error.InvariantViolated;
                    }
                }
            }
        }
    }
}

test "arbitrary fragmentation of decode input" {
    var all256: [256]u8 = undefined;
    for (&all256, 0..) |*p, i| p.* = @intCast(i);
    var enc_buf: [1024]u8 = undefined;

    for ([_]Encoding{ .esc, .b64, .b32 }) |enc| {
        const wlen = encode(enc, derive.default_sentinel, &enc_buf, &all256);
        for ([_]usize{ 1, 2, 3, 5, 7, 13, wlen }) |step| {
            var d = Decoder.init(enc, derive.default_sentinel);
            var out: [512]u8 = undefined;
            var oi: usize = 0;
            var pos: usize = 0;
            while (pos < wlen) {
                const end = @min(pos + step, wlen);
                try d.feed(&out, &oi, enc_buf[pos..end]);
                pos = end;
            }
            try std.testing.expectEqualSlices(u8, &all256, out[0..oi]);
        }
    }
}

test "flush newlines between content are skipped" {
    // 在 B64 内容中间插冲刷 \n，解码结果应不变。
    var enc_buf: [64]u8 = undefined;
    const data = "abcdef";
    const wlen = encode(.b64, derive.default_sentinel, &enc_buf, data);
    var with_nl: [128]u8 = undefined;
    var j: usize = 0;
    for (enc_buf[0..wlen], 0..) |ch, i| {
        with_nl[j] = ch;
        j += 1;
        if (i % 2 == 0) {
            with_nl[j] = '\n';
            j += 1;
        }
    }
    var out: [64]u8 = undefined;
    const dlen = try decode(.b64, derive.default_sentinel, &out, with_nl[0..j]);
    try std.testing.expectEqualStrings(data, out[0..dlen]);
}

test "invalid base char errors, no panic" {
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.Invalid, decode(.b32, derive.default_sentinel, &out, "AAAA0AAA")); // '0' 不在 b32
    try std.testing.expectError(error.Invalid, decode(.b64, derive.default_sentinel, &out, "AA=A")); // 填充后又来数据
}
