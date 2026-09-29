# smodem 使用手册

> 本文描述**设计意图**。实现完成前，这里写的命令还不能真正执行。

## 1. 装到跳板机上

`smodem` 不会自动往跳板机上写任何东西（[D21](decisions.md#d21--远端二进制部署不做自动化)）。
远端二进制要你自己放上去。

```bash
zig build release                      # 产物在 zig-out/release/
scp zig-out/release/smodem-x86_64-linux-musl user@jumphost:~/bin/smodem
ssh user@jumphost chmod +x ~/bin/smodem
```

跳板机不让 `scp` 的话，管道也行：

```bash
cat zig-out/release/smodem-x86_64-linux-musl | ssh user@jumphost 'cat > ~/bin/smodem && chmod +x ~/bin/smodem'
```

产物是静态链接 musl、baseline 指令集，不依赖跳板机的 glibc 版本和 CPU 型号。

确认 `~/bin` 在远端 PATH 里，或者启动时用 `--remote-cmd` 指明完整路径。

## 2. 用起来

```bash
smodem user@jumphost
```

就这一条。本地 `127.0.0.1:1080` 起 SOCKS5，浏览器/curl 指过去即可：

```bash
curl -x socks5h://127.0.0.1:1080 https://example.com
```

注意是 `socks5h` 不是 `socks5`——`h` 表示**域名交给代理解析**，
这既是隧道的意义，也避免 DNS 泄漏。

常用参数：

```bash
smodem -p 8080 user@jumphost               # 换本地端口
smodem --remote-cmd '~/bin/smodem serve' user@jumphost
smodem -- ssh -J bastion@a user@b smodem serve   # 自定义整条传输命令
```

最后一条形式下，`--` 之后的一切原样执行，你可以套任意层跳板、
换成 `kubectl exec`、`docker exec`、串口工具，只要它能跑一个双向字符通道。

## 3. 已经登录在终端里的情况

像当年敲 `rz` 那样：人已经在跳板机的交互式 shell 里，直接敲

```
smodem serve
```

然后在本地另开一端接上去。这条路会走到 pty，`smodem` 会自动把 tty 切成 raw，
并在退出时恢复。

## 4. 看懂启动输出

正常启动大概是这样（全部走 stderr，stdout 只属于协议）：

```
smodem 0.1.0  local mode
  transport : ssh -T user@jumphost smodem serve
  listen    : 127.0.0.1:1080 (socks5, tcp+udp)
  handshake : sync ok, peer smodem/0.1.0 linux-x86_64
  encoding  : send=RAW recv=RAW          <- 线是干净的，零开销
  ready     : 0.34s
```

线不干净时会看到降档：

```
  encoding  : send=ESC recv=RAW          <- 只有上行脏，下行不陪着降档
```

两个方向各自协商，不会互相拖累。

## 5. 出问题时

### 握手超时

失败时 smodem 会把引导阶段丢弃的字节**原样打出来**——
跳板机场景的真正原因几乎总藏在那里：

```
handshake failed: no SYNC within 10s
--- last 4 KiB received from peer ---
bash: smodem: command not found
------------------------------------
```

照着改就行。常见的三种：

| 打出来的内容 | 原因 |
|---|---|
| `command not found` | 远端没装，或不在 PATH。用 `--remote-cmd` 给完整路径 |
| `Permission denied` | ssh 认证没过 |
| `Host key verification failed` | 先手工 `ssh user@jumphost` 一次确认指纹 |

### 通道不干净

```
channel is not 8-bit clean (client -> server), round 0 (RAW)
  sent 272 bytes, received 277 bytes  (+5, bytes were INSERTED)
  first difference at offset 10:
    sent     ... 08 09 0A 0B 0C ...
    received ... 08 09 0D 0A 0B ...
                       ^^ 0x0A became 0x0D 0x0A
  likely cause: ONLCR on a pty
  retrying with ESC encoding
```

这不是错误，是**正常的自动降档**，后面会接着跑。只有三档全失败才会退出：

```
channel unusable: even Base64 did not survive
```

真到这一步，说明这条线连可打印 ASCII 都传不完整，换条线吧。

### 慢

先看 `encoding` 那行。`B64` 意味着 33% 的额外开销，
如果本该是干净管道却降到了 B64，多半是 ssh 分配了 pty——
确认传输命令里有 `-T`。

## 6. 安全须知

- **协议自己不加密**，安全性完全来自 SSH。不要在裸 TCP 或裸串口上
  用它传敏感流量。
- 监听地址默认 `127.0.0.1`。改成 `0.0.0.0` 等于把一个**无认证的 SOCKS5 代理
  （含 UDP 中继）** 暴露给整个网络，smodem 会对此告警。真要这么做，
  请自己在前面加防火墙。
- 隧道不提供任何提权。远端能访问什么，取决于你 ssh 登录的那个用户能访问什么。
