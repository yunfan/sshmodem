//! 薄命令行 binary（设计 §6）。当前处于实现早期：
//! 逻辑都在库里，这里只占位，随 io/runtime 与 cli/args 就位后接线。

const std = @import("std");
const smodem = @import("smodem");

pub fn main() !void {
    _ = smodem;
    std.debug.print("smodem: implementation in progress (core codec layer ready)\n", .{});
}
