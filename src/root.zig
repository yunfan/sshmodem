//! smodem 库的唯一公开入口（设计 §3.1）。
//! 别人 `@import("smodem")` 拿到的就是这里 re-export 的稳定 API。
//! 内部模块（core/ io/ cli/）不外泄，可自由重构而不惊动下游。

const std = @import("std");
const core = @import("core/root.zig");

// 层次三：协议原语。
pub const codec = core.codec;

// 层次二（Session/Event）与层次一（run/Config）随实现推进补上。

test {
    _ = core;
}
