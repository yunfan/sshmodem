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

状态：设计完成，实现进行中。
