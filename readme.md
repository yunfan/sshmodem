# smodem

a y modem like tool for people using jumphost

跳板机关掉了 `AllowTcpForwarding`，`ssh -D` / `-L` / `-W` 全都用不了，
但**执行一条命令**总是可以的。`smodem` 就把那条命令的标准输入输出当成一根线，
在上面跑多路复用隧道，在本地开出一个 SOCKS5 代理。

```
smodem user@jumphost          # 本地 127.0.0.1:1080 起 SOCKS5
```

```
浏览器 ──SOCKS5──> smodem ──stdin/stdout──> ssh ══> sshd ──> smodem serve ──> 目标
```

像 YMODEM 一样"在一条只能跑字符的线上传数据"，但线已经由 SSH 保证了可靠，
所以不做重传。力气花在 YMODEM 没做的四件事上：

- **传输编码自动降档** —— 线不一定是 8-bit clean 的。开头探一次，
  `RAW`（0% 开销）→ `ESC`（6%）→ `B64`（33%）逐级降档，两个方向各自协商。
  pty 把 `0x0A` 改成 `0x0D 0x0A` 这种事，第一秒就查出来，而不是让数据静默损坏。
- **穿透审计堡垒机** —— 逐行审计导致的死锁会自动探出并逐帧补换行；
  倒计时/"剩余时间"提示注入到流中间，靠帧校验发现并 `%%` 重同步，至多丢一帧。
- **多路复用** —— 所有连接共享一条线，出站 round-robin，大文件下载不会把
  嵌套的 SSH 会话饿死。
- **流量控制** —— 双层窗口，窗口不够就停止从源头读，背压一路顶到 TCP 对端。
  内存只跟连接数有关，跟流量无关。
- **诊断** —— 失败时直接说出根因，而不是给一句"校验错误"让你自己猜。

SOCKS5 的 TCP `CONNECT` 和 UDP `ASSOCIATE` 都支持。

握手序列可用 `--key` 派生、`--marker` 指定；`--armor` 提供只用可见字符的加固传输
（牺牲带宽换对抗性与更低指纹）。**这些默认全关**，且都不是安全机制——
安全始终来自 SSH。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/protocol.md](docs/protocol.md) | 线协议规范，字节级 |
| [docs/design.md](docs/design.md) | 架构、目录结构、并发模型、测试策略 |
| [docs/decisions.md](docs/decisions.md) | 技术决策记录，每条都写了放弃了什么 |
| [docs/usage.md](docs/usage.md) | 使用手册 |

## 构建

```
zig build          # ReleaseSafe + baseline CPU
zig build test
zig build release  # 多平台静态基线二进制
```

不出 Debug 产物。远端二进制静态链接 musl、baseline 指令集，
可以直接丢到任何一台 Linux 跳板机上跑（自己 `scp` 过去，
smodem 不会偷偷往跳板机上写东西）。

## 作为库使用

smodem 是**一个可复用库 + 一个薄命令行 binary**，库本身自底向上分层：

```
codec  →  tunnel  →  socks5  →  (io)  →  cli
线原语    通用隧道    SOCKS5 应用          薄 binary
```

最值得复用的是**隧道层**：它应用无关，给它一条又脏又字符化的载体（ssh stdio），
还你若干条干净、可靠、有序、带流控的字节流。它不知道什么是 SOCKS5——
SOCKS5 只是建在它上面的第一个应用。你可以拿同一条隧道去跑反向转发、文件传输、RPC。

核心是 **sans-io** 的：喂它字节和时间，它吐出要发的字节和事件，不碰 socket，
所以能塞进任何 I/O 模型（poll / epoll / io_uring / 异步 / wasm）。

```zig
const smodem = @import("smodem");

// 开箱即用：起一个完整 SOCKS5 隧道
try smodem.run(alloc, .{ .listen_port = 1080, .target = "user@host" });

// 或者只取通用隧道，自己接 I/O、自己定义要跑的应用：
var t = try smodem.Tunnel.init(alloc, .{}, .client);
try t.recv(bytes_from_ssh);
const id = try t.open(my_metadata);       // 元数据对隧道不透明
while (t.nextEvent()) |ev| switch (ev) { ... }
```

公开 API 分四层次：`run`/`Config`（开箱即用）、`Tunnel`/`Event`（通用隧道，
自带 I/O 模型）、`socks5`（SOCKS5↔隧道映射）、`codec`（协议原语）。
详见 [docs/design.md §3.1](docs/design.md)。

## 实现状态

已完成并测试（45 单测 + 端到端 e2e 全绿）：

- 第零层 codec：crc32 / derive / address / frame / encoding(RAW/ESC/B64/B32，参数化哨兵)
- 第一层 tunnel：握手、SS 定界+CRC 重同步+冲刷、双层窗口流控+半关闭、
  **自动降档探针**（每方向 RAW→ESC→B64）、**UDP 数据报通道**
- 第二层 socks5：报文解析与应答
- 第三层 io：poll(2) 事件循环、拉起 ssh、TCP connect、**UDP 中继**（含来源校验）
- 第四层 cli：薄 binary
- 构建：默认 ReleaseSafe + baseline，freestanding 红线守住 sans-io 三层零 syscall，
  `zig build release` 出 4 平台静态 baseline 二进制

命令：`zig build`（构建）、`zig build test`（全测试）、`zig build e2e`（端到端冒烟）、
`zig build release`（多平台产物）。

加固与握手可配置（协议 §13）：`--key` 派生握手 marker、`--marker` 直接指定、
`--sentinel` 指定哨兵、`--armor` 全程 B32 + key 派生哨兵/marker（可见字符、约 60% 开销）。
解析后的值自动传给远端；secret（`--key`）不出本地机器。这些不是加密/认证，安全来自 SSH。

探针不透明时会打逐字节诊断（协议 §4.4）：方向、收发长度差、首个差异字节、根因推断。

未做：交互式传输驱动（堡垒机只给 shell 不许带命令的兜底；单开一条命令代理即可绕开）。
