//! smodem 库的唯一公开入口（设计 §3.1）。
//! 别人 `@import("smodem")` 拿到的就是这里 re-export 的稳定 API。
//! 内部分层（codec/ tunnel/ socks5/ io/ cli/）不外泄，可自由重构。

const std = @import("std");
const sansio = @import("sansio.zig");

// 层次三（协议原语）：线格式编解码。
pub const codec = sansio.codec;

// 层次二（通用隧道）：Tunnel / Event / Stream —— 应用无关的传输，可单独复用。
//   pub const Tunnel = sansio.Tunnel;   （随实现补上）

// 层次一（SOCKS5 与开箱即用 run/Config）：随 socks5/ 与 io/ 就位补上。

test {
    _ = sansio;
}
