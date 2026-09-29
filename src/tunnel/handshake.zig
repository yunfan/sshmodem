//! 握手相关的纯逻辑（协议 §4.1、§5.5）：
//!   - 引导序列扫描器：越过 MOTD/提示符/倒计时等垃圾，找到 SYNC。
//!   - HELLO / HELLO_ACK 会话参数编解码。
//! 纯计算，无 syscall。

const std = @import("std");
const derive = @import("../codec/derive.zig");

pub const protocol_version: u8 = 1;

pub const Role = enum(u8) { client = 0, server = 1 };

/// 能力位（协议 §5.5）。
pub const caps = struct {
    pub const udp_associate: u32 = 1 << 0;
    pub const reverse: u32 = 1 << 1;
    pub const resume_session: u32 = 1 << 2;
};

/// 会话参数，HELLO 与 HELLO_ACK 共用（协议 §5.5）。
pub const Hello = struct {
    version: u8 = protocol_version,
    role: Role,
    caps: u32 = 0,
    stream_window: u32,
    session_window: u32,
    max_streams: u16,
    impl: []const u8 = "smodem/0.1.0",

    pub const fixed_len = 19; // version..impl_len

    pub fn encodedLen(self: Hello) usize {
        return fixed_len + self.impl.len;
    }

    pub fn encode(self: Hello, out: []u8) usize {
        out[0] = self.version;
        out[1] = @intFromEnum(self.role);
        std.mem.writeInt(u32, out[2..6], self.caps, .little);
        std.mem.writeInt(u32, out[6..10], self.stream_window, .little);
        std.mem.writeInt(u32, out[10..14], self.session_window, .little);
        std.mem.writeInt(u16, out[14..16], self.max_streams, .little);
        std.mem.writeInt(u16, out[16..18], 0, .little); // reserved
        out[18] = @intCast(self.impl.len);
        @memcpy(out[19 .. 19 + self.impl.len], self.impl);
        return self.encodedLen();
    }

    pub const DecodeError = error{ Short, BadRole };

    /// impl 切片借用 buf。
    pub fn decode(buf: []const u8) DecodeError!Hello {
        if (buf.len < fixed_len) return error.Short;
        const impl_len = buf[18];
        if (buf.len < fixed_len + @as(usize, impl_len)) return error.Short;
        const role: Role = switch (buf[1]) {
            0 => .client,
            1 => .server,
            else => return error.BadRole,
        };
        return .{
            .version = buf[0],
            .role = role,
            .caps = std.mem.readInt(u32, buf[2..6], .little),
            .stream_window = std.mem.readInt(u32, buf[6..10], .little),
            .session_window = std.mem.readInt(u32, buf[10..14], .little),
            .max_streams = std.mem.readInt(u16, buf[14..16], .little),
            .impl = buf[19 .. 19 + impl_len],
        };
    }
};

/// SYNC 字面量最大长度（哨兵2 + token 12 + 哨兵2 有富余）。
pub const max_sync_len = 64;

/// 引导序列扫描器（协议 §4.1）。逐字节喂入，匹配到 SYNC 返回 true。
/// SYNC = SS + token + SS，默认 "%%SMODEM/1%%"。用 KMP，正确处理哨兵前缀重复
/// （如输入 "%%%SMODEM/1%%" 也能定位）。匹配前的字节留末 4 KiB 供诊断。
/// 注意：Bootstrap **自己内联拥有** SYNC 字节与 KMP 表，不持有任何外部切片。
/// 这样它可以随所属结构体按值移动/拷贝而不失效（避免自引用悬垂指针）。
pub const Bootstrap = struct {
    sync_buf: [max_sync_len]u8 = undefined,
    sync_len: usize = 0,
    lps: [max_sync_len]usize = undefined, // KMP 失败函数
    matched: usize = 0,
    diag: [4096]u8 = undefined,
    diag_len: usize = 0,
    diag_start: usize = 0,

    /// 用哨兵与 token 构造 SYNC 字面量到 out（长度 = 2 + token.len + 2）。
    pub fn buildSync(out: []u8, sentinel: u8, token: []const u8) usize {
        out[0] = sentinel;
        out[1] = sentinel;
        @memcpy(out[2 .. 2 + token.len], token);
        out[2 + token.len] = sentinel;
        out[3 + token.len] = sentinel;
        return 4 + token.len;
    }

    pub fn init(sync: []const u8) Bootstrap {
        std.debug.assert(sync.len <= max_sync_len);
        var bs = Bootstrap{};
        @memcpy(bs.sync_buf[0..sync.len], sync);
        bs.sync_len = sync.len;
        const s = bs.sync_buf[0..sync.len];
        // 计算 KMP 失败函数。
        bs.lps[0] = 0;
        var len: usize = 0;
        var i: usize = 1;
        while (i < s.len) {
            if (s[i] == s[len]) {
                len += 1;
                bs.lps[i] = len;
                i += 1;
            } else if (len != 0) {
                len = bs.lps[len - 1];
            } else {
                bs.lps[i] = 0;
                i += 1;
            }
        }
        return bs;
    }

    fn pushDiag(self: *Bootstrap, b: u8) void {
        if (self.diag_len < self.diag.len) {
            self.diag[self.diag_len] = b;
            self.diag_len += 1;
        } else {
            self.diag[self.diag_start] = b;
            self.diag_start = (self.diag_start + 1) % self.diag.len;
        }
    }

    /// 喂一个字节。返回 true 表示此字节完成了 SYNC 匹配（其后即第一帧）。
    pub fn feedByte(self: *Bootstrap, b: u8) bool {
        while (true) {
            if (b == self.sync_buf[self.matched]) {
                self.matched += 1;
                if (self.matched == self.sync_len) {
                    self.matched = 0;
                    return true;
                }
                return false;
            }
            if (self.matched == 0) {
                self.pushDiag(b); // 完全不沾边的字节才计入诊断
                return false;
            }
            self.matched = self.lps[self.matched - 1]; // 回退后用同一 b 重试
        }
    }

    /// 诊断缓冲（按写入顺序）拷贝到 out，返回长度。
    pub fn diagnostics(self: *Bootstrap, out: []u8) usize {
        const n = @min(self.diag_len, out.len);
        if (self.diag_len < self.diag.len) {
            @memcpy(out[0..n], self.diag[0..n]);
        } else {
            // 环形：从 diag_start 起
            var i: usize = 0;
            while (i < n) : (i += 1) {
                out[i] = self.diag[(self.diag_start + i) % self.diag.len];
            }
        }
        return n;
    }
};

test "hello round-trip" {
    const h = Hello{
        .role = .client,
        .caps = caps.udp_associate,
        .stream_window = 128 * 1024,
        .session_window = 2 * 1024 * 1024,
        .max_streams = 256,
        .impl = "smodem/test",
    };
    var buf: [64]u8 = undefined;
    const n = h.encode(&buf);
    try std.testing.expectEqual(h.encodedLen(), n);
    const d = try Hello.decode(buf[0..n]);
    try std.testing.expectEqual(Role.client, d.role);
    try std.testing.expectEqual(caps.udp_associate, d.caps);
    try std.testing.expectEqual(@as(u32, 128 * 1024), d.stream_window);
    try std.testing.expectEqual(@as(u16, 256), d.max_streams);
    try std.testing.expectEqualStrings("smodem/test", d.impl);
}

test "hello decode rejects short and bad role" {
    try std.testing.expectError(error.Short, Hello.decode("abc"));
    var buf: [64]u8 = undefined;
    const h = Hello{ .role = .server, .stream_window = 1, .session_window = 1, .max_streams = 1, .impl = "" };
    const n = h.encode(&buf);
    buf[1] = 9; // 非法 role
    try std.testing.expectError(error.BadRole, Hello.decode(buf[0..n]));
}

test "bootstrap finds sync after garbage" {
    var sync_buf: [16]u8 = undefined;
    const sync_len = Bootstrap.buildSync(&sync_buf, '%', derive.default_token);
    const sync = sync_buf[0..sync_len];
    try std.testing.expectEqualStrings("%%SMODEM/1%%", sync);

    var bs = Bootstrap.init(sync);
    const junk = "Last login: Tue\r\n$ smodem serve\r\n";
    for (junk) |b| try std.testing.expect(!bs.feedByte(b));
    var matched = false;
    for (sync) |b| {
        matched = bs.feedByte(b);
    }
    try std.testing.expect(matched);

    var diag: [128]u8 = undefined;
    const dn = bs.diagnostics(&diag);
    try std.testing.expect(std.mem.indexOf(u8, diag[0..dn], "smodem serve") != null);
}
