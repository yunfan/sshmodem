//! 核心库入口（sans-io）。零 syscall，可对 freestanding 目标编译——
//! 这条红线由 build.zig 的 freestanding check 在编译期守住（设计 §3）。
//!
//! 目前实现进度：第一层 codec 已就绪；session/socks5 等随后加入。

const std = @import("std");

/// 协议原语：线格式编解码（设计 §3.1 层次三）。
pub const codec = struct {
    pub const crc32 = @import("codec/crc32.zig");
    pub const derive = @import("codec/derive.zig");
    pub const address = @import("codec/address.zig");
    pub const frame = @import("codec/frame.zig");
    pub const encoding = @import("codec/encoding.zig");
};

test {
    _ = codec.crc32;
    _ = codec.derive;
    _ = codec.address;
    _ = codec.frame;
    _ = codec.encoding;
}
