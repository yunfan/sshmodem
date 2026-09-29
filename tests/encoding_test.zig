//! 编码层的跨文件回归（设计 §7.1、§7.2）。
//! 坏管道模拟（onlcr/isig/... hostile/bastion）需要 session 层对接，
//! 待第二层就位后补齐；此处先放一个占位断言，保证测试目标存在且能跑。

const std = @import("std");
const smodem = @import("smodem");
const encoding = smodem.codec.encoding;
const derive = smodem.codec.derive;

test "placeholder: encoding reachable via public API" {
    var out: [64]u8 = undefined;
    const n = encoding.encode(.b64, derive.default_sentinel, &out, "hi");
    var back: [64]u8 = undefined;
    const m = try encoding.decode(.b64, derive.default_sentinel, &back, out[0..n]);
    try std.testing.expectEqualStrings("hi", back[0..m]);
}
