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
所以不做重传，改为专注三件 YMODEM 没做的事：**多路复用**、**流量控制**、
**通道透明性自检**（开头就查出 pty 会不会把二进制流改坏，而不是让它静默损坏）。

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
可以直接丢到任何一台 Linux 跳板机上跑。

状态：设计完成，实现进行中。
