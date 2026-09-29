# SMODEM 架构设计

配套文档：[protocol.md](protocol.md) 线协议规范 · [decisions.md](decisions.md) 技术决策记录 · [usage.md](usage.md) 使用手册

## 1. 一句话

`smodem` 把 `ssh user@jumphost smodem serve` 这条命令的标准输入输出当成一根线，
在上面跑多路复用隧道，在本地开出一个 SOCKS5 代理（TCP + UDP）。

跳板机关掉 `AllowTcpForwarding` 时，`ssh -D` 不可用，但执行命令总是可以的。

## 2. 进程与数据流

```
                       本地机器                     │      跳板机
  ┌─────────┐  TCP   ┌──────────────────────┐      │  ┌────────────────────┐  TCP  ┌────────┐
  │ 浏览器  │─SOCKS5>│  smodem (local)      │      │  │ smodem serve       │──────>│ 目标   │
  │ curl    │  UDP   │                      │      │  │                    │  UDP  │ 服务   │
  └─────────┘        │  socks5 前端         │      │  │ 连接器 / UDP 中继  │       └────────┘
  ┌─────────┐        │  mux 会话            │      │  │ mux 会话           │
  │ 其它    │─SOCKS5>│  帧编解码            │      │  │ 帧编解码           │
  └─────────┘        │  传输编码 RAW/ESC/B64│      │  │ 传输编码           │
                     └──────────┬───────────┘      │  └─────────┬──────────┘
                                │ stdin/stdout     │            │ stdin/stdout
                           ┌────▼─────┐            │      ┌─────▼────┐
                           │ ssh 子进程│════════════╪═════>│  sshd    │
                           └──────────┘    加密     │      └──────────┘
```

本地端**自己 fork ssh 子进程**，用户不必去拼管道。

## 3. 目录结构

分成**三层，边界即依赖方向**：核心库不依赖 I/O，I/O 运行时不依赖 CLI，
CLI 只是接线。目录直接画出这条边界（详见 §3.1 库 API 与复用边界）。

```
build.zig                 暴露库模块 "smodem" + 薄可执行 "smodem" + release 目标
build.zig.zon             .name = .smodem，供他人作依赖引用
docs/                     protocol.md / design.md / decisions.md / usage.md

src/
  root.zig                ← 库的唯一公开入口。别人 @import("smodem") 拿到的就是它，
                            只 re-export 稳定 API（§3.1），内部模块不外泄

  core/                   ← 【第一层】sans-io 内核。零 syscall，可 freestanding 编译
    codec/
      encoding.zig          RAW/ESC/B64/B32 编解码器、冲刷换行、SS 重同步（哨兵参数化）
      frame.zig             逻辑帧编解码（头 + payload + CRC32 帧尾）、类型与常量
      address.zig           RFC 1928 地址块编解码
      crc32.zig             CRC-32/ISO-HDLC（探针与帧尾共用）
      derive.zig            由 key 派生 token 与哨兵（SHA256 + BASE32，std.crypto）
    handshake.zig         引导/HELLO/降档探针/冲刷探针——全部是纯状态机
    session.zig           会话引擎：喂字节+时间 → 出字节+事件（sans-io 的门面）
    stream.zig            TCP 流状态机、双层窗口
    udp.zig               UDP 关联状态：丢弃队列、来源校验规则（不含 socket）
    scheduler.zig         出站 round-robin + 控制帧优先
    socks5.zig            SOCKS5 服务端解析器（增量式，含 UDP 头）——纯状态机

  io/                     ← 【第二层】POSIX I/O 运行时。可选：别人可整个不用
    poller.zig            poll(2) 事件循环封装
    tty.zig               isatty / cfmakeraw / 恢复
    pipe.zig              非阻塞读写、部分写处理
    transport.zig         传输命令驱动：命令/交互/自定义三档（协议 §12），拉起 ssh
    runtime.zig           把 core.Session 接到真实 fd 上，run(config) 的所在

  cli/                    ← 【第三层】薄 binary
    main.zig              解析 argv → 建 Config → 调 io.runtime.run → 错误映射退出码
    args.zig             参数解析（-p / --key / --armor / -- 透传 …）

tests/
  encoding_test.zig       四种编码往返 + 不变量(含派生哨兵) + 坏管道模拟
  derive_test.zig         key 派生 token/哨兵的确定性与安全性
  frame_test.zig          帧编解码 + 分片 + 畸形输入 + fuzz
  socks5_test.zig         SOCKS5 解析器 + 逐字节喂入 + UDP 头
  session_test.zig        会话引擎：握手、窗口、半关闭、降档（纯内存，无 fd）
  udp_test.zig            UDP 关联生命周期、丢弃策略、来源校验
  freestanding_test.zig   断言 core/ 能对 freestanding 目标编译（守住"零 syscall"）
  e2e_test.zig            端到端：两个真实进程 + socketpair + 真实 TCP/UDP
```

依赖方向是**单向**的：`cli → io → core`，`core` 谁都不依赖。
任何一处 `core/` 里出现 `std.posix` / `std.net` / `std.process`，
`freestanding_test.zig` 就会编译失败——这条红线由编译器守，不靠自觉。

### 3.1 库 API 与复用边界

别人 `@import("smodem")` 只看见 `root.zig` re-export 的这几样，分三个层次，
按"想复用多少"各取所需：

```zig
// 层次一：开箱即用（薄 binary 走的就是这条）
pub const Config = io.runtime.Config;      // 约定大于配置，Config{} 即默认可用
pub fn run(alloc, config) Error!void       // 起一个完整隧道，阻塞直到结束

// 层次二：sans-io 引擎（想用自己的 I/O 模型的人走这条）
pub const Session = core.Session;          // 喂字节+时间，出字节+事件，不碰 fd
pub const Event = core.Event;              // stream_open / data / close / log / ready …
pub const Role = core.Role;                // .client / .server

// 层次三：协议原语（只想要线格式的人走这条）
pub const codec = core.codec;              // encoding / frame / address / crc32 / derive
pub const socks5 = core.socks5;            // 单独的 SOCKS5 解析器
pub const wire = core.wire;                // 常量：版本、帧类型、默认窗口 …
```

三条纪律让它"能被别人安心复用"，也是 code review 的硬标准：

1. **调用方给 allocator。** 库内不藏全局分配器，任何分配都收 `std.mem.Allocator`。
2. **库不打印、不退出。** 没有 `std.debug.print`，没有 `std.process.exit`。
   诊断（探针失败、降档、重同步计数）作为 `Event.log{ level, msg }` **返回**给调用方，
   由调用方决定写去哪。退出码是 `cli/` 把 `Error` 翻译出来的，不是库的事。
3. **sans-io 内核零 syscall。** `core/` 只做纯计算，见上面那条编译期红线。

`io/runtime.zig` 是"电池"——把 `Session` 接到 poll 循环和真实 socket 上，
并把 `Event.log` 默认写到 stderr。想要不同 I/O 模型（epoll、io_uring、异步框架、
甚至编译进浏览器 wasm）的人，跳过 `io/`，直接驱动 `Session` 即可。

## 4. 并发模型：单线程事件循环

> 本节讲的是 `io/runtime.zig` 这一层——**内核（`core/`）本身不含任何并发或 I/O**，
> 它只是被这个循环喂字节、要字节。换一个 I/O 模型，本节整段可以另写，内核不动。

`io/runtime.zig` 用一个线程、一个 `poll(2)` 循环，管这些 fd：

| fd | 事件 | 动作 |
|---|---|---|
| SOCKS5 监听 socket（local） | 可读 | `accept`，建流 |
| 每条流的 TCP socket | 可读 | 有窗口才读，读到就封 `DATA` 入队 |
| | 可写 | 写出已收数据，写成功才补 `WINDOW` |
| UDP 中继 socket | 可读 | `recvfrom`，校验来源，封 `UDP_DATA` |
| 隧道 stdin | 可读 | 喂给解码器 → 帧解析器 |
| 隧道 stdout | 可写 | 调度器取帧 → 编码器 → 写出 |

选单线程的理由：所有流共享**一条**出站管道，这是天然的串行点。
多线程只会为了抢这个串行点加锁，换不来吞吐，却换来一整类竞态 bug。

### 4.1 背压如何贯通

这是实现最要紧的一条链路，必须一眼能看懂：

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

全程没有任何一处无界缓冲。进程内存与连接数成正比，与流量无关。

如果把"远端停止读"改成"读进来先缓冲着"，一个大文件就能把进程内存吃光——
这是这类工具最常见的失败方式。

UDP 走另一条规则：不做窗口，队列满就丢最旧的（协议 §9.3）。
可靠性由上层应用负责，这本来就是 UDP 的契约。

### 4.2 部分写

管道和 socket 都可能只写进去一部分。所有写路径**必须**保留未写完的偏移，
等下一次可写事件继续，绝不阻塞、绝不丢弃、绝不重发已写部分。
`io/pipe.zig` 把这件事收口成一个类型，别处不再各写一遍。

### 4.3 编码层放在哪

编码是**纯字节变换**，放在最外层，紧贴 fd：

```
出站：调度器取帧 → frame.encode() → encoding.encode() → pipe.write()
入站：pipe.read() → encoding.decode() → reader.feed() → 帧
```

帧层之上的所有代码（mux、socks5、local、serve）**完全看不见编码的存在**。
这是这个分层最大的价值：线有多烂是编码层一个人的事。

ESC 与 B64 解码器都必须能处理**任意分片**——一个转义序列的两个字节、
一个 Base64 四元组的四个字符，都可能跨两次 `read()` 到达。
解码器因此是带状态的增量式解码器，不是纯函数。

## 5. 内存

- 启动时一次性分配：流表、每流收发缓冲、帧解析缓冲、出站队列、UDP 丢弃队列。
- 稳态**零堆分配**。跑起来之后不再向分配器要内存，也就不存在"跑了三天 OOM"。
- 每条 TCP 流固定开销：接收缓冲 128 KiB（= 流窗口）+ 发送侧 16 KiB + 控制结构。
- 每个 UDP 关联：64 × 2 KiB 丢弃队列（超过 2 KiB 的数据报另行分配自固定池）。
- 默认 256 条流上限时约 37 MiB；上限 512 时约 74 MiB。默认值可调。

编码层的额外开销：出站编码缓冲最坏 2 倍帧长（ESC 全转义）或 1.34 倍（B64），
按最大帧 16 KiB 算是 32 KiB，单例，不随连接数增长。

## 6. CLI（约定大于配置）

CLI 是**薄**的：`cli/main.zig` 只做三件事——解析 argv 成 `Config`、
调 `smodem.run(alloc, config)`、把返回的 `Error` 翻译成退出码。
没有任何协议逻辑漏在这一层；把 binary 整个删掉，库照样完整可用。

```
smodem user@jumphost                  # 最常用：本地 1080 起 SOCKS5，自动拉 ssh
smodem -p 8080 user@jumphost          # 换端口
smodem serve                          # 远端模式，从 stdin/stdout 服务
smodem -- ssh -J a@b c@d smodem serve # 完全自定义传输命令
```

| 约定 | 值 |
|---|---|
| 监听地址 | `127.0.0.1:1080` |
| 传输命令 | `ssh -T <目标> smodem serve` |
| 远端可执行名 | `smodem`（走远端 PATH，用户自行部署，见 usage.md） |
| 日志 | 全部走 stderr，stdout 只属于协议 |
| 退出码 | 0 正常，1 用法错误，2 握手失败，3 传输中断 |

`stdout 只属于协议`在远端模式下是硬约束：任何一个 `print` 走错到 stdout
都会破坏帧流。实现上远端模式启动时就把 stdout 从日志层摘掉。

## 7. 测试策略

分五层，每层抓不同的问题。

### 7.1 编码层（`encoding_test.zig`）

这是最该被测狠的一层，因为它是所有诡异 bug 的藏身处。

- **往返**：四种编码（RAW/ESC/B64/B32），`encode` 后 `decode` 必须得到原值。
  输入覆盖全 256 字节值、全 `0x0A`、全哨兵、空输入、随机数据。
- **不变量（含派生哨兵）**：ESC/B64/B32 的输出中**必须不含 `SS`**。
  不只测默认哨兵 `%`，还要**遍历安全字节池里的每一个候选哨兵**跑一遍穷举 + 随机数据。
  这条不变量塌了，`SS` 就不再是可靠的同步标记，探针边界、引导、重同步全跟着错——
  而派生哨兵最容易在这里翻车（比如某个哨兵的 `XOR 0x40` 忘了进 ESC 转义集合）。
- **任意分片**：把编码后的流按 1 字节、2 字节、素数长度、单块等切法喂给解码器，
  结果必须一致。转义序列和 base 四元/五元组跨分片是最容易写错的地方。
- **畸形输入**：孤立的哨兵结尾、非法字母表字符、哨兵后跟不可能的字节——
  必须报错，不得 panic、不得越界。
- **派生一致性**（`derive.zig`）：同一 `--key` 必须派生出同一 token 与同一哨兵；
  不同 key 几乎必然不同；派生出的哨兵**必须落在安全字节池内**（否则不变量无从谈起）。
- **fuzz**：`std.testing.fuzz` 喂随机字节给四个解码器，要求永不 panic。

### 7.2 坏管道模拟（`encoding_test.zig`）

写一组**故意坏掉的管道**中间层，每个模拟一种真实破坏：

| 模拟器 | 行为 | 期望 |
|---|---|---|
| `onlcr` | `0x0A` → `0x0D 0x0A` | 探针 Round 0 失败，诊断报"插入字节"，降到 ESC 后通过 |
| `isig` | 吞掉 `0x03` `0x1A` `0x1C` | Round 0 失败，报"吞字节"，降到 ESC 通过 |
| `ixon` | 吞掉 `0x11` `0x13` | 同上 |
| `istrip` | `b & 0x7F` | Round 0、Round 1 都失败，降到 B64 通过 |
| `ssh_tilde` | 行首 `~~` → `~` | 协议不使用 `~`，必须不受影响 |
| `line_buffered` | 攒着字节，见到 `\n` 才整段放行 | 冲刷探针判定逐行缓冲；启用每帧补 `\n` 后数据不再死锁 |
| `maxcanon` | 逐行缓冲 + 单行超 4096 字节就截断 | payload 压到 512 后不再丢数据 |
| `injector` | 稳态每隔 N 字节插入一段 `\r\n[3 min left]\r\n` | CRC 发现被污染帧，`%%` 重同步，至多丢一帧，其余完整 |
| `bastion` | `onlcr` + `line_buffered` + `injector` 同时开 | 模拟审计堡垒机全套：最终必须落到 ESC/B64、逐行冲刷、能重同步，数据完整 |
| `hostile` | 以上全部再叠 `istrip` | 只剩可打印 ASCII 也要通：落到 B64 且数据完整 |

`line_buffered` 那行专门锁住 D22 最隐蔽的死锁：**不写这条测试，行缓冲的链路会
"握手成功、一发数据就永久卡死"，而这在没有专门模拟器时根本复现不出来。**

`injector` 那行锁住 D23：稳态注入必须被 CRC 发现、被 `%%` 重同步吸收，
损失有界而不是从此全乱。

最后两行是终极断言：**线再烂，只要还能过可打印 ASCII，隧道就得通**。
这组测试直接锁住本工具最独特的能力不被改坏。

### 7.3 帧与解析层（`frame_test.zig`、`socks5_test.zig`）

- 往返，覆盖所有帧类型与地址类型；
- 任意分片喂入；
- 畸形输入：超长 `length`、未知 type、会话帧带非 0 `stream_id`、
  流帧带 0 `stream_id`、地址块长度自相矛盾——全部必须报错；
- SOCKS5 的 UDP 头解析，含 `FRAG != 0` 必须丢弃；
- fuzz。

### 7.4 状态机层（`session_test.zig`、`udp_test.zig`）

用内存管道对接两个会话对象，不碰真实 fd：

- 握手全流程，含版本不匹配、三级降档全失败两条失败路径；
- 两个方向协商出**不同**编码的场景；
- 窗口耗尽 → 停读 → 补窗 → 恢复；
- 半关闭的四种顺序（本方先、对方先、同时、只有一方）；
- `RESET` 在各状态下的行为；流 id 回收与回绕；
- UDP：关联随 TCP 流关闭而销毁、队列满时丢最旧、非法来源地址被丢弃、
  超大数据报被丢弃。

### 7.5 端到端（`e2e_test.zig`）

起两个**真实进程**，用 `socketpair` 当传输，本地端开 SOCKS5，
另起测试 HTTP/echo/UDP-echo 服务器当目标：

- 单连接正确性；
- 并发 64 条流同时跑，校验每条流数据完整；
- 大对象（16 MiB）传输，同时观察进程 RSS **不随流量增长**——把 §4.1 的背压钉死；
- UDP echo 往返，含 DNS 查询这种真实用例；
- 目标拒绝连接 / 域名不存在 → SOCKS5 REP 码必须原样透传；
- 传输中途杀掉一端 → 另一端干净退出，不留僵尸、不 panic；
- 在 socketpair 上套 §7.2 的 `hostile` 中间层再跑一遍全部用例。

## 8. 构建

### 8.1 库与 binary 一个仓库、两个产物

`build.zig` 同时产出两样，共用一份源码：

```zig
// 1) 库模块——别人作依赖时拿到的就是它
const smodem = b.addModule("smodem", .{ .root_source_file = b.path("src/root.zig") });

// 2) 薄可执行——只是把库接到 argv 和退出码上
const exe = b.addExecutable(.{ .name = "smodem", ... });
exe.root_module.addImport("smodem", smodem);
```

别人复用时，`build.zig.zon` 里加依赖，然后：

```zig
const smodem = b.dependency("smodem", .{}).module("smodem");
my_exe.root_module.addImport("smodem", smodem);
// 代码里：const smodem = @import("smodem"); try smodem.run(alloc, .{});
```

他们只会拿到 `root.zig` 暴露的稳定 API（§3.1），`core/` `io/` `cli/` 的内部结构
可以随便重构而不惊动下游——这正是"薄 binary + 可复用库"要买的东西。

### 8.2 编译要求

**不出 Debug 产物。** 默认构建即 `ReleaseSafe`：

```
zig build          # ReleaseSafe + baseline CPU（默认），产出库 + binary
zig build test     # 全部测试（含 freestanding 编译红线）
zig build release  # 交叉编译多平台静态基线二进制到 zig-out/release/
```

三个硬性要求及其原因：

| 要求 | 原因 |
|---|---|
| `-Doptimize=ReleaseSafe` | 保留边界检查与整数溢出检查。这是处理不可信网络输入的程序，**安全检查比那点性能重要**；真有热点再针对性优化，而不是整体降级到 ReleaseFast |
| `-Dcpu=baseline` | 跳板机 CPU 可能很老，不赌目标机支持哪些指令集扩展 |
| 静态链接 musl | 远端二进制要能丢到任何一台 Linux 上直接跑，不依赖对方的 glibc 版本 |

`release` 目标产出 `x86_64-linux-musl`、`aarch64-linux-musl`、
`x86_64-macos`、`aarch64-macos`，全部 baseline。Linux 产物静态链接，
体积控制在 1 MiB 量级——它常常要被 `scp` 到跳板机上去。
