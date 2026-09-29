//! 由 --key 派生引导序列的 token 与哨兵字节（协议 §13.1、§13.2）。
//! 用 std.crypto 的 SHA256 + 自带的 BASE32 编码，无第三方依赖，纯计算。
//!
//! 注意：这不是安全机制（协议 §11、§13 开头）。它防碰撞、做弱配对、降指纹，
//! 安全性仍全部来自 SSH。

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// RFC 4648 BASE32 字母表（不含填充；派生只取定长前缀，无需填充）。
const b32_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 默认 token（不给 key 时用，协议 §4.1）。
pub const default_token = "SMODEM/1";

/// 默认哨兵字节 '%'（协议 §2.1）。
pub const default_sentinel: u8 = '%';

/// 派生 token 的固定长度（字符数）。
pub const token_len = 12;

/// 安全哨兵字节池（协议 §13.2）。挑选标准，保证哨兵配**任何**编码都不破坏不变量：
///   - 不在 B64 字母表内（故排除 A-Za-z0-9 与 + / =，数字也在此列）；
///   - 不在 B32 字母表内（A-Z2-7）；
///   - 不是空白或换行（0x0A 另有冲刷含义）；
///   - 且 `b XOR 0x40` 不落在 ESC 危险字节集内——否则自定义哨兵配 ESC 时，
///     某个被转义字节的第二字节会等于哨兵，凭空造出 `SS`，破坏不变量。
///     （这条把 '@'=0x40 排除，它的 XOR 结果 0x00 是危险字节。）
/// 哨兵只出现在数据流里、以数字码经命令行传给远端，本身不作 shell token，
/// 故不必额外考虑 shell 元字符。
pub const sentinel_pool = "%^_,.:-";

fn base32Encode(out: []u8, data: []const u8) usize {
    var acc: u64 = 0;
    var nbits: u6 = 0;
    var oi: usize = 0;
    for (data) |b| {
        acc = (acc << 8) | b;
        nbits += 8;
        while (nbits >= 5) {
            nbits -= 5;
            const idx: u5 = @intCast((acc >> nbits) & 0x1F);
            out[oi] = b32_alpha[idx];
            oi += 1;
        }
    }
    if (nbits > 0) {
        const idx: u5 = @intCast((acc << (@as(u6, 5) - nbits)) & 0x1F);
        out[oi] = b32_alpha[idx];
        oi += 1;
    }
    return oi;
}

fn digest(domain: []const u8, key: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(domain);
    h.update(&[_]u8{0}); // 域分隔符，防止不同 domain+key 拼接碰撞
    h.update(key);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

/// 由 key 派生 token（写入 out，长度 token_len）。
pub fn deriveToken(out: *[token_len]u8, key: []const u8) void {
    const d = digest("smodem/1/sync", key);
    var buf: [64]u8 = undefined;
    const n = base32Encode(&buf, &d);
    std.debug.assert(n >= token_len);
    @memcpy(out, buf[0..token_len]);
}

/// 由 key 从安全池里派生一个哨兵字节。
pub fn deriveSentinel(key: []const u8) u8 {
    const d = digest("smodem/1/sentinel", key);
    return sentinel_pool[d[0] % sentinel_pool.len];
}

test "token is deterministic and key-sensitive" {
    var a: [token_len]u8 = undefined;
    var b: [token_len]u8 = undefined;
    var c: [token_len]u8 = undefined;
    deriveToken(&a, "myproject");
    deriveToken(&b, "myproject");
    deriveToken(&c, "other");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "token is base32 alphabet only" {
    var t: [token_len]u8 = undefined;
    deriveToken(&t, "whatever");
    for (t) |ch| try std.testing.expect(std.mem.indexOfScalar(u8, b32_alpha, ch) != null);
}

test "sentinel comes from the safe pool" {
    // 扫一批 key，派生出的哨兵必须都落在池里。
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var kb: [8]u8 = undefined;
        std.mem.writeInt(u64, &kb, i, .little);
        const s = deriveSentinel(&kb);
        try std.testing.expect(std.mem.indexOfScalar(u8, sentinel_pool, s) != null);
    }
}
