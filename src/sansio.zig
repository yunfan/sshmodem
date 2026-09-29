//! sans-io 层聚合根：codec + tunnel + socks5。
//! 这三层**零 syscall**，本文件被 build.zig 的 freestanding check 编译，
//! 一旦其中混进 std.posix/std.net/std.process 就编译失败（设计 §3）。
//!
//! io/（POSIX 运行时）与 cli/（薄 binary）**不**在这里，它们才碰操作系统。

const std = @import("std");

// 第零层：线格式原语。
pub const codec = struct {
    pub const crc32 = @import("codec/crc32.zig");
    pub const derive = @import("codec/derive.zig");
    pub const address = @import("codec/address.zig");
    pub const frame = @import("codec/frame.zig");
    pub const encoding = @import("codec/encoding.zig");
};

// 第一层：通用多路复用隧道（应用无关）。随实现推进补上导出。
// pub const Tunnel = @import("tunnel/tunnel.zig").Tunnel;

// 第二层：SOCKS5 语义（建在隧道上）。随实现推进补上导出。
// pub const socks5 = @import("socks5/root.zig");

test {
    _ = codec.crc32;
    _ = codec.derive;
    _ = codec.address;
    _ = codec.frame;
    _ = codec.encoding;
}
