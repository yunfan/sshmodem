//! 薄命令行 binary（设计 §6）。只做：解析 argv → 建 Config → 调 io.run → 退出码。
//! 所有逻辑都在库里；这里是接线。

const std = @import("std");
const rt = @import("io/runtime.zig");
const smodem = @import("smodem");

const usage =
    \\smodem — SOCKS5 tunnel over an ssh command channel
    \\
    \\  smodem [options] <user@host>     local: SOCKS5 on 127.0.0.1:1080, spawns ssh
    \\  smodem serve                     remote: serve over stdin/stdout
    \\  smodem [options] -- <cmd...>     custom transport command
    \\
    \\Options (local):
    \\  -p, --port <n>        local SOCKS5 port (default 1080)
    \\      --remote-cmd <s>  remote command (default "smodem serve")
    \\      --encoding <e>    raw|esc|b64|b32 (default b64)
    \\  -q, --quiet           less logging
    \\  -h, --help
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

fn runMain(init: std.process.Init) !u8 {
    const alloc = init.gpa;
    const args = try std.process.Args.toSlice(init.minimal.args, init.arena.allocator());

    var cfg = rt.Config{};
    var target: ?[]const u8 = null;
    var remote_cmd: []const u8 = "smodem serve";
    var custom: ?[]const [:0]const u8 = null;
    var encoding_forced = false;

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
        } else if (std.mem.eql(u8, a, "--")) {
            custom = args[i + 1 ..];
            break;
        } else if (a.len > 0 and a[0] != '-') {
            target = a;
        } else {
            return usageErr();
        }
    }

    // 未显式 --encoding 时开启自动降档探针（协议 §4.2），默认体验：干净管道零开销。
    if (!encoding_forced) cfg.tunnel.auto_probe = true;
    cfg.tunnel.caps = smodem.tunnel.caps.udp_associate;

    if (cfg.mode == .serve) {
        try rt.run(alloc, cfg);
        return @intFromEnum(ExitCode.ok);
    }

    // local：拼传输命令 argv。
    var argv: std.ArrayList([:0]const u8) = .empty;
    defer argv.deinit(alloc);
    if (custom) |cv| {
        for (cv) |c| try argv.append(alloc, c);
    } else {
        const t = target orelse return usageErr();
        try argv.append(alloc, "ssh");
        try argv.append(alloc, "-T");
        try argv.append(alloc, try alloc.dupeZ(u8, t));
        var it = std.mem.tokenizeScalar(u8, remote_cmd, ' ');
        while (it.next()) |tok| try argv.append(alloc, try alloc.dupeZ(u8, tok));
    }
    cfg.transport_argv = argv.items;
    try rt.run(alloc, cfg);
    return @intFromEnum(ExitCode.ok);
}

fn usageErr() u8 {
    std.debug.print("{s}", .{usage});
    return @intFromEnum(ExitCode.usage);
}
