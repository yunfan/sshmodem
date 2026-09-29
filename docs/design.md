# SMODEM 架构设计

配套文档：[protocol.md](protocol.md) 线协议规范 · [decisions.md](decisions.md) 技术决策记录 · [usage.md](usage.md) 使用手册

## 1. 一句话

`smodem` 把 `ssh user@jumphost smodem serve` 这条命令的标准输入输出当成一根线，
在上面跑多路复用隧道，在本地开出一个 SOCKS5 代理。

跳板机关掉 `AllowTcpForwarding` 时，`ssh -D` 不可用，但执行命令总是可以的。

## 2. 进程与数据流

```
                         本地机器                    │        跳板机
                                                     │
  ┌─────────┐   TCP     ┌──────────────────────┐    │   ┌────────────────────┐   TCP   ┌────────┐
  │ 浏览器  │──SOCKS5──>│  smodem (local)      │    │   │ smodem serve       │────────>│ 目标   │
  │ curl    │           │                      │    │   │                    │         │ 服务   │
  └─────────┘           │  ┌────────────────┐  │    │   │ ┌────────────────┐ │         └────────┘
                        │  │ socks5 前端    │  │    │   │ │ 连接器         │ │
  ┌─────────┐           │  ├────────────────┤  │    │   │ ├────────────────┤ │
  │ 其它    │──SOCKS5──>│  │ mux 会话       │  │    │   │ │ mux 会话       │ │
  └─────────┘           │  ├────────────────┤  │    │   │ ├────────────────┤ │
                        │  │ 帧编解码       │  │    │   │ │ 帧编解码       │ │
                        │  └───────┬────────┘  │    │   │ └───────┬────────┘ │
                        └──────────┼───────────┘    │   └─────────┼──────────┘
                                   │ stdin/stdout   │             │ stdin/stdout
                              ┌────▼─────┐          │       ┌─────▼────┐
                              │ ssh 子进程│══════════╪══════>│  sshd    │
                              └──────────┘   加密    │       └──────────┘
```

本地端**自己 fork 出 ssh 子进程**，而不是要求用户去拼管道。
用户只需要 `smodem user@jumphost`，剩下的一切都是约定。

## 3. 目录结构

结构即文档，目录名直接对应上面的分层：

```
build.zig                 构建脚本，含 release 目标（交叉编译 + baseline）
build.zig.zon
docs/
  protocol.md             线协议规范（规范性）
  design.md               本文，架构设计
  decisions.md            技术决策记录（ADR）
  usage.md                使用手册
src/
  main.zig                CLI 入口：解析参数，分发到 local / serve
  root.zig                库入口，导出全部模块供测试使用
  protocol/
    frame.zig             帧头编解码、类型定义、常量
    address.zig           RFC 1928 地址块编解码
    handshake.zig         SYNC 扫描、HELLO 协商、PROBE 自检
    crc32.zig             CRC-32/ISO-HDLC（仅探针用）
  mux/
    session.zig           会话状态机、帧分发、保活
    stream.zig            流状态机、双层窗口
    scheduler.zig         出站 round-robin + 控制帧优先
    reader.zig            入站字节流 → 帧（处理任意分片）
  socks5.zig              SOCKS5 服务端握手解析器（增量式）
  local.zig               本地模式：监听、ssh 子进程、事件循环
  serve.zig               远端模式：stdio、connect、事件循环
  io/
    poller.zig            poll(2) 事件循环封装
    tty.zig               isatty / cfmakeraw / 恢复
    pipe.zig              非阻塞读写、部分写处理
tests/
  frame_test.zig          帧编解码 + 分片 + 畸形输入
  socks5_test.zig         SOCKS5 解析器 + 逐字节喂入
  session_test.zig        会话状态机、窗口、半关闭
  e2e_test.zig            端到端：两个真实进程 + socketpair + 真实 TCP
```

## 4. 并发模型：单线程事件循环

一个线程，一个 `poll(2)` 循环，管三类 fd：

| fd | 事件 | 动作 |
|---|---|---|
| SOCKS5 监听 socket（仅 local） | 可读 | `accept`，建流 |
| 每条流的 TCP socket | 可读 | 有窗口才读，读到就封 `DATA` 帧入队 |
| | 可写 | 把收到的数据写出去，写成功才补 `WINDOW` |
| 隧道 stdin / stdout | 可读 | 喂给帧解析器 |
| | 可写 | 调度器取帧写出 |

选单线程的理由：所有流共享**一条**出站管道，这是天然的串行点。
多线程只会为了抢这个串行点而加锁，换不来吞吐，却换来一整类竞态 bug。
"如无必要勿增实体"。

### 4.1 背压如何贯通

这是整个实现最要紧的一条链路，必须一眼能看懂：

```
目标服务器发得太快
   → 浏览器读得慢，本地 TCP 发送缓冲满
   → 本地端写不出去，不补 WINDOW
   → 远端流窗口耗尽
   → 远端停止 read() 那条 TCP socket      ← 关键：停止读，而不是读进来缓冲
   → 远端内核接收缓冲填满
   → 内核把 TCP 窗口降到 0
   → 目标服务器自己停下来
```

全程没有任何一处无界缓冲。进程内存占用与连接数成正比，与流量无关。

反过来，如果在"远端停止读"这一步改成"读进来先缓冲着"，
一个大文件就能把进程内存吃光——这是这类工具最常见的失败方式。

### 4.2 部分写

管道和 socket 都可能只写进去一部分。所有写路径**必须**保留未写完的偏移，
等下一次可写事件继续，绝不阻塞、绝不丢弃、绝不重发已写部分。
`io/pipe.zig` 把这件事收口成一个类型，别处不再各写一遍。

## 5. 内存

- 启动时一次性分配：流表（`max_streams` 条）、每流收发缓冲、帧解析缓冲、出站队列。
- 稳态**零堆分配**。跑起来之后不再向分配器要内存，也就不存在"跑了三天 OOM"。
- 每条流的固定开销：接收缓冲 128 KiB（= 流窗口）+ 发送侧 16 KiB（= 一个 `DATA` 帧）
  + 控制结构。512 条流上限下，最坏约 74 MiB；
  默认上限 256 条流，约 37 MiB。默认值可调。

## 6. CLI（约定大于配置）

```
smodem user@jumphost                  # 最常用：本地 1080 起 SOCKS5，自动拉 ssh
smodem -p 8080 user@jumphost          # 换端口
smodem serve                          # 远端模式，从 stdin/stdout 服务
smodem -- ssh -J a@b c@d smodem serve # 完全自定义传输命令
```

约定：

| 约定 | 值 |
|---|---|
| 监听地址 | `127.0.0.1:1080` |
| 传输命令 | `ssh -T <目标> smodem serve` |
| 远端可执行名 | `smodem`（走远端 PATH） |
| 日志 | 全部走 stderr，stdout 只属于协议 |
| 退出码 | 0 正常，1 用法错误，2 握手失败，3 传输中断 |

`stdout 只属于协议` 这条在远端模式下是硬约束：任何一个 `print` 走错到 stdout
都会破坏帧流。实现上远端模式启动时就把 stdout 的 writer 从日志层摘掉。

## 7. 测试策略

分四层，每层抓不同的问题：

### 7.1 编解码层（`frame_test.zig`、`socks5_test.zig`）

- **往返**：编码后解码必须得到原值，覆盖所有帧类型与地址类型。
- **任意分片**：把同一段字节流按 1 字节、2 字节、素数长度、单块等多种切法喂进解析器，
  结果必须完全一致。这是流式解析器最容易出错的地方，也是最容易被漏测的地方。
- **畸形输入**：超长 length、未知 type、会话帧带非 0 stream_id、
  流帧带 0 stream_id、地址块长度自相矛盾——全部必须报错而不是 panic 或读越界。
- **fuzz**：`std.testing.fuzz` 喂随机字节给解析器，要求永不 panic、永不越界。

### 7.2 状态机层（`session_test.zig`）

用内存管道对接两个会话对象，不碰真实 fd：

- 握手全流程，含版本不匹配、探针失败两条失败路径；
- 窗口耗尽 → 停读 → 补窗 → 恢复；
- 半关闭的四种顺序（本方先、对方先、同时、只有一方）；
- `RESET` 在各状态下的行为；
- 流 id 回收与回绕。

### 7.3 透明性回归（`session_test.zig`）

**专门模拟一条坏掉的管道**：写一个中间层，按 `ONLCR` 规则把 `0x0A` 改写成 `0x0D 0x0A`，
断言探针**必须**检测出来并给出"长度变长"的诊断。
再写一个吞掉 `0x03` 的中间层，断言探针报"长度变短"。

这条测试直接锁住本工具最独特的那个功能不被改坏。

### 7.4 端到端（`e2e_test.zig`）

起两个**真实进程**，用 `socketpair` 当传输，本地端开 SOCKS5，
另起一个测试 HTTP/echo 服务器当目标：

- 单连接正确性；
- 并发 64 条流同时跑，校验每条流的数据完整；
- 大对象（16 MiB）传输，同时观察进程 RSS 不随流量增长——把 §4.1 的背压钉死；
- 目标拒绝连接 / 域名不存在 → SOCKS5 REP 码必须原样透传；
- 传输中途杀掉一端 → 另一端干净退出，不留僵尸、不 panic。

## 8. 构建

**不出 Debug 产物。** 默认构建即 `ReleaseSafe`：

```
zig build                    # ReleaseSafe + baseline CPU（默认）
zig build test               # 全部测试
zig build release            # 交叉编译多平台静态基线二进制到 zig-out/release/
```

三个硬性要求及其原因：

| 要求 | 原因 |
|---|---|
| `-Doptimize=ReleaseSafe` | 保留边界检查与整数溢出检查。这是个处理不可信网络输入的程序，**安全检查比那点性能重要**；真有热点再针对性优化，而不是整体降级到 ReleaseFast |
| `-Dcpu=baseline` | 跳板机的 CPU 可能很老。用 baseline 指令集，不赌目标机支持 AVX-512 |
| 静态链接 musl | 远端二进制要能丢到任何一台 Linux 上直接跑，不能依赖对方的 glibc 版本 |

`release` 目标产出：`x86_64-linux-musl`、`aarch64-linux-musl`、
`x86_64-macos`、`aarch64-macos`，全部 baseline。
Linux 产物静态链接，体积应控制在 1 MiB 量级——因为它常常要被 `scp` 或
`cat | ssh` 传到跳板机上去。
