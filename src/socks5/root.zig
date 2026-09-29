//! 第二层：SOCKS5 语义，建在隧道上（设计 §3.2、协议 §8·§9）。
//! 目前 wire.zig（纯报文解析/应答）已就绪；连接编排在 io/runtime。

pub const wire = @import("wire.zig");

test {
    _ = wire;
}
