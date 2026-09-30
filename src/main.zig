//! 薄命令行 binary（设计 §6）。只做：解析 argv → 建 Config → 调 io.run → 退出码。
//! 所有逻辑都在库里；这里是接线。

const std = @import("std");
const rt = @import("io/runtime.zig");
const smodem = @import("smodem");
const derive = smodem.codec.derive;

const usage =
    \\smodem — SOCKS5 tunnel over an ssh command channel
    \\
    \\  smodem [options] <user@host>     local: SOCKS5 on 127.0.0.1:1080, spawns ssh
    \\  smodem serve                     remote: serve over stdin/stdout
    \\  smodem [options] -- <cmd...>     custom transport command
    \\
    \\Options (local):
    \\  -p, --port <n>        local SOCKS5 port (default 1080)
    \\  -U, --udp <l:h:p>     static UDP forward: local port l -> remote h:p (repeatable)
    \\      --remote-cmd <s>  remote command (default "smodem serve")
    \\      --encoding <e>    raw|esc|b64|b32 (default: auto-probe)
    \\      --key <secret>    derive a per-session handshake marker (not a secret channel)
    \\      --marker <str>    set the handshake marker literally
    \\      --sentinel <b>    sentinel byte, e.g. 0x25 or '%'
    \\      --armor           hardened transport: B32 + key-derived marker & sentinel
    \\                        (visible chars only, ~60% overhead; opt-in)
    \\  -q, --quiet           less logging
    \\  -h, --help
    \\
    \\Note: --key/--marker/--sentinel/--armor are NOT encryption or auth — security
    \\      comes from SSH. They avoid collisions, weakly pair the two ends, and cut
    \\      fingerprinting. Resolved values are passed to the remote automatically.
    \\
;

const ExitCode = enum(u8) { ok = 0, usage = 1, handshake = 2, transport = 3 };

pub fn main(init: std.process.Init) u8 {
    return runMain(init) catch |e| {
        std.debug.print("smodem: error: {s}\n", .{@errorName(e)});
        return @intFromEnum(ExitCode.transport);
    };
}

fn parseEncoding(s: []const u8) ?smodem.tunnel.Encoding {
    if (std.mem.eql(u8, s, "raw")) return .raw;
    if (std.mem.eql(u8, s, "esc")) return .esc;
    if (std.mem.eql(u8, s, "b64")) return .b64;
    if (std.mem.eql(u8, s, "b32")) return .b32;
    return null;
}

/// 解析 "localport:host:port"（host 可为 IPv4 或域名；域名在服务端解析）。
fn parseUdpForward(s: []const u8) ?rt.UdpForward {
    const first = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    const last = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    if (last <= first) return null;
    const lp = std.fmt.parseInt(u16, s[0..first], 10) catch return null;
    const host = s[first + 1 .. last];
    const tp = std.fmt.parseInt(u16, s[last + 1 ..], 10) catch return null;
    if (host.len == 0) return null;
    return .{ .local_port = lp, .host = host, .port = tp };
}

fn parseSentinel(s: []const u8) ?u8 {
    if (s.len == 1) return s[0];
    if (s.len == 4 and (std.mem.eql(u8, s[0..2], "0x") or std.mem.eql(u8, s[0..2], "0X")))
        return std.fmt.parseInt(u8, s[2..], 16) catch null;
    return std.fmt.parseInt(u8, s, 0) catch null;
}

fn runMain(init: std.process.Init) !u8 {
    const alloc = init.gpa;
    const arena = init.arena.allocator();
    const args = try std.process.Args.toSlice(init.minimal.args, arena);

    var cfg = rt.Config{};
    var target: ?[]const u8 = null;
    var remote_cmd: []const u8 = "smodem serve";
    var custom: ?[]const [:0]const u8 = null;

    var encoding_forced = false;
    var armor = false;
    var key: ?[]const u8 = null;
    var marker: ?[]const u8 = null;
    var sentinel_arg: ?u8 = null;
    var udp_forwards: std.ArrayList(rt.UdpForward) = .empty;
    defer udp_forwards.deinit(alloc);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "serve")) {
            cfg.mode = .serve;
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            std.debug.print("{s}", .{usage});
            return @intFromEnum(ExitCode.ok);
        } else if (std.mem.eql(u8, a, "-q") or std.mem.eql(u8, a, "--quiet")) {
            cfg.verbose = false;
        } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--port")) {
            i += 1;
            if (i >= args.len) return usageErr();
            cfg.listen_port = std.fmt.parseInt(u16, args[i], 10) catch return usageErr();
        } else if (std.mem.eql(u8, a, "--remote-cmd")) {
            i += 1;
            if (i >= args.len) return usageErr();
            remote_cmd = args[i];
        } else if (std.mem.eql(u8, a, "--encoding")) {
            i += 1;
            if (i >= args.len) return usageErr();
            cfg.tunnel.encoding = parseEncoding(args[i]) orelse return usageErr();
            encoding_forced = true;
        } else if (std.mem.eql(u8, a, "--armor")) {
            armor = true;
        } else if (std.mem.eql(u8, a, "--key")) {
            i += 1;
            if (i >= args.len) return usageErr();
            key = args[i];
        } else if (std.mem.eql(u8, a, "--marker")) {
            i += 1;
            if (i >= args.len) return usageErr();
            marker = args[i];
        } else if (std.mem.eql(u8, a, "--sentinel")) {
            i += 1;
            if (i >= args.len) return usageErr();
            sentinel_arg = parseSentinel(args[i]) orelse return usageErr();
        } else if (std.mem.eql(u8, a, "--udp") or std.mem.eql(u8, a, "-U")) {
            i += 1;
            if (i >= args.len) return usageErr();
            try udp_forwards.append(alloc, parseUdpForward(args[i]) orelse return usageErr());
        } else if (std.mem.eql(u8, a, "--")) {
            custom = args[i + 1 ..];
            break;
        } else if (a.len > 0 and a[0] != '-') {
            target = a;
        } else {
            return usageErr();
        }
    }

    // ---- 解析握手 marker / 哨兵 / 编码（协议 §13）----
    // token（marker）：显式 > 由 key 派生 > 默认。
    if (marker) |m| {
        cfg.tunnel.token = m;
    } else if (key) |k| {
        const buf = try arena.alloc(u8, derive.token_len);
        derive.deriveToken(buf[0..derive.token_len], k);
        cfg.tunnel.token = buf;
    }
    // 哨兵：显式 > armor 时由 key 派生 > 默认。
    if (sentinel_arg) |sb| {
        cfg.tunnel.sentinel = sb;
    } else if (armor) {
        cfg.tunnel.sentinel = derive.deriveSentinel(key orelse "");
    }
    // 编码：armor 强制 B32；否则 --encoding 或自动探针。
    if (armor) {
        cfg.tunnel.encoding = .b32;
        encoding_forced = true;
    }
    if (!encoding_forced) cfg.tunnel.auto_probe = true;
    cfg.tunnel.caps = smodem.tunnel.caps.udp_associate;
    cfg.udp_forwards = udp_forwards.items;

    if (cfg.mode == .serve) {
        try rt.run(alloc, cfg);
        return @intFromEnum(ExitCode.ok);
    }

    // local：拼传输命令 argv。
    var argv: std.ArrayList([:0]const u8) = .empty;
    defer argv.deinit(alloc);
    if (custom) |cv| {
        // 自定义传输：用户全权负责，也把解析后的握手参数附加到末尾（若非默认）。
        for (cv) |c| try argv.append(alloc, c);
        try appendResolved(alloc, &argv, cfg, encoding_forced);
    } else {
        const t = target orelse return usageErr();
        try argv.append(alloc, "ssh");
        try argv.append(alloc, "-T");
        // ssh 传输层保活：沉默也每 15s 发一次，3 次没回应（45s）即判死断开，触发重连。
        try argv.append(alloc, "-o");
        try argv.append(alloc, "ServerAliveInterval=15");
        try argv.append(alloc, "-o");
        try argv.append(alloc, "ServerAliveCountMax=3");
        try argv.append(alloc, try alloc.dupeZ(u8, t));
        var it = std.mem.tokenizeScalar(u8, remote_cmd, ' ');
        while (it.next()) |tok| try argv.append(alloc, try alloc.dupeZ(u8, tok));
        try appendResolved(alloc, &argv, cfg, encoding_forced);
    }
    cfg.transport_argv = argv.items;
    try rt.run(alloc, cfg);
    return @intFromEnum(ExitCode.ok);
}

/// 把解析后的握手参数（非默认者）附加到远端命令，让两端一致。
/// 注意：只传解析结果，绝不传 --key（secret 不出本地机器，协议 §13.1）。
fn appendResolved(alloc: std.mem.Allocator, argv: *std.ArrayList([:0]const u8), cfg: rt.Config, encoding_forced: bool) !void {
    if (!std.mem.eql(u8, cfg.tunnel.token, derive.default_token)) {
        try argv.append(alloc, "--marker");
        try argv.append(alloc, try alloc.dupeZ(u8, cfg.tunnel.token));
    }
    if (cfg.tunnel.sentinel != derive.default_sentinel) {
        try argv.append(alloc, "--sentinel");
        try argv.append(alloc, try std.fmt.allocPrintSentinel(alloc, "0x{X:0>2}", .{cfg.tunnel.sentinel}, 0));
    }
    if (encoding_forced) {
        try argv.append(alloc, "--encoding");
        try argv.append(alloc, try alloc.dupeZ(u8, @tagName(cfg.tunnel.encoding)));
    }
}

fn usageErr() u8 {
    std.debug.print("{s}", .{usage});
    return @intFromEnum(ExitCode.usage);
}
