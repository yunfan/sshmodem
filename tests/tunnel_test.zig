//! 隧道引擎端到端（纯内存，无 fd）。两个 Tunnel 用字节泵对接，
//! 覆盖：握手、开流/接受/拒绝、双向数据、半关闭、流控背压、注入重同步。

const std = @import("std");
const smodem = @import("smodem");
const Tunnel = smodem.Tunnel;
const Event = smodem.Event;

const alloc = std.testing.allocator;

/// 在两端之间来回搬字节，直到没有更多可搬。
fn pump(a: *Tunnel, b: *Tunnel) !void {
    var buf: [8192]u8 = undefined;
    var progress = true;
    while (progress) {
        progress = false;
        const na = a.send(&buf);
        if (na > 0) {
            try b.recv(buf[0..na]);
            progress = true;
        }
        const nb = b.send(&buf);
        if (nb > 0) {
            try a.recv(buf[0..nb]);
            progress = true;
        }
    }
}

/// 泵中途注入垃圾（模拟堡垒机倒计时），验证重同步。
fn pumpWithInjection(a: *Tunnel, b: *Tunnel, junk: []const u8) !void {
    var buf: [8192]u8 = undefined;
    var progress = true;
    var injected = false;
    while (progress) {
        progress = false;
        const na = a.send(&buf);
        if (na > 0) {
            if (!injected and na > 4) {
                // 把 junk 插到 a→b 数据流中间
                try b.recv(buf[0 .. na / 2]);
                try b.recv(junk);
                try b.recv(buf[na / 2 .. na]);
                injected = true;
            } else {
                try b.recv(buf[0..na]);
            }
            progress = true;
        }
        const nb = b.send(&buf);
        if (nb > 0) {
            try a.recv(buf[0..nb]);
            progress = true;
        }
    }
}

const Collected = struct {
    ready: bool = false,
    opens: std.ArrayList(struct { id: u32, meta: []u8 }) = .empty,
    accepts: std.ArrayList(u32) = .empty,
    rejects: std.ArrayList(struct { id: u32, code: u8 }) = .empty,
    data: std.ArrayList(struct { id: u32, bytes: []u8 }) = .empty,
    writable: std.ArrayList(u32) = .empty,
    eofs: std.ArrayList(u32) = .empty,
    resets: std.ArrayList(u32) = .empty,

    fn deinit(self: *Collected) void {
        for (self.opens.items) |o| alloc.free(o.meta);
        for (self.data.items) |d| alloc.free(d.bytes);
        self.opens.deinit(alloc);
        self.accepts.deinit(alloc);
        self.rejects.deinit(alloc);
        self.data.deinit(alloc);
        self.writable.deinit(alloc);
        self.eofs.deinit(alloc);
        self.resets.deinit(alloc);
    }

    fn drain(self: *Collected, t: *Tunnel) !void {
        while (t.nextEvent()) |ev| switch (ev) {
            .ready => self.ready = true,
            .stream_open => |x| try self.opens.append(alloc, .{ .id = x.id, .meta = try alloc.dupe(u8, x.metadata) }),
            .stream_accept => |x| try self.accepts.append(alloc, x.id),
            .stream_reject => |x| try self.rejects.append(alloc, .{ .id = x.id, .code = x.code }),
            .stream_data => |x| try self.data.append(alloc, .{ .id = x.id, .bytes = try alloc.dupe(u8, x.bytes) }),
            .stream_writable => |id| try self.writable.append(alloc, id),
            .stream_eof => |id| try self.eofs.append(alloc, id),
            .stream_reset => |x| try self.resets.append(alloc, x.id),
            .log => {},
            .closed => {},
        };
    }

    fn dataFor(self: *Collected, id: u32, out: *std.ArrayList(u8)) !void {
        for (self.data.items) |d| if (d.id == id) try out.appendSlice(alloc, d.bytes);
    }
};

fn runHandshakeAndEcho(enc: smodem.tunnel.Encoding) !void {
    const cfg = smodem.tunnel.Config{ .encoding = enc };
    var client = try Tunnel.init(alloc, cfg, .client);
    defer client.deinit();
    var server = try Tunnel.init(alloc, cfg, .server);
    defer server.deinit();

    try pump(&client, &server);

    var cc = Collected{};
    defer cc.deinit();
    var sc = Collected{};
    defer sc.deinit();
    try cc.drain(&client);
    try sc.drain(&server);
    try std.testing.expect(cc.ready);
    try std.testing.expect(sc.ready);
    try std.testing.expect(client.isReady());
    try std.testing.expect(server.isReady());

    // client 开流，元数据不透明（这里放一段假地址块）。
    const meta = "\x03\x0bexample.com\x01\xbb";
    const id = try client.open(meta);
    try std.testing.expectEqual(@as(u32, 1), id); // client 用奇数
    try pump(&client, &server);

    sc.deinit();
    sc = Collected{};
    try sc.drain(&server);
    try std.testing.expectEqual(@as(usize, 1), sc.opens.items.len);
    try std.testing.expectEqual(id, sc.opens.items[0].id);
    try std.testing.expectEqualSlices(u8, meta, sc.opens.items[0].meta);

    // server 接受，回一段绑定地址。
    try server.accept(id, "\x01\x00\x00\x00\x00\x00\x00");
    try pump(&client, &server);
    cc.deinit();
    cc = Collected{};
    try cc.drain(&client);
    try std.testing.expectEqual(@as(usize, 1), cc.accepts.items.len);

    // 双向数据。
    _ = try client.write(id, "ping");
    try pump(&client, &server);
    sc.deinit();
    sc = Collected{};
    try sc.drain(&server);
    {
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(alloc);
        try sc.dataFor(id, &got);
        try std.testing.expectEqualStrings("ping", got.items);
    }
    try server.consume(id, 4);

    _ = try server.write(id, "pong!");
    try pump(&client, &server);
    cc.deinit();
    cc = Collected{};
    try cc.drain(&client);
    {
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(alloc);
        try cc.dataFor(id, &got);
        try std.testing.expectEqualStrings("pong!", got.items);
    }
    try client.consume(id, 5);

    // 半关闭：client 先关写。
    try client.closeWrite(id);
    try pump(&client, &server);
    sc.deinit();
    sc = Collected{};
    try sc.drain(&server);
    try std.testing.expectEqual(@as(usize, 1), sc.eofs.items.len);

    // server 关写 → 双向关闭。
    try server.closeWrite(id);
    try pump(&client, &server);
    cc.deinit();
    cc = Collected{};
    try cc.drain(&client);
    try std.testing.expectEqual(@as(usize, 1), cc.eofs.items.len);
}

test "handshake + echo over b64" {
    try runHandshakeAndEcho(.b64);
}
test "handshake + echo over esc" {
    try runHandshakeAndEcho(.esc);
}
test "handshake + echo over raw" {
    try runHandshakeAndEcho(.raw);
}
test "handshake + echo over b32" {
    try runHandshakeAndEcho(.b32);
}

test "open rejected maps through" {
    const cfg = smodem.tunnel.Config{};
    var client = try Tunnel.init(alloc, cfg, .client);
    defer client.deinit();
    var server = try Tunnel.init(alloc, cfg, .server);
    defer server.deinit();
    try pump(&client, &server);
    _ = client.nextEvent();
    while (client.nextEvent()) |_| {}
    while (server.nextEvent()) |_| {}

    const id = try client.open("\x01\x7f\x00\x00\x01\x00\x50");
    try pump(&client, &server);
    // server 侧取出 open，拒绝，错误码 0x05（连接被拒）。
    var sc = Collected{};
    defer sc.deinit();
    try sc.drain(&server);
    try std.testing.expectEqual(@as(usize, 1), sc.opens.items.len);
    try server.reject(id, 0x05);
    try pump(&client, &server);

    var cc = Collected{};
    defer cc.deinit();
    try cc.drain(&client);
    try std.testing.expectEqual(@as(usize, 1), cc.rejects.items.len);
    try std.testing.expectEqual(@as(u8, 0x05), cc.rejects.items[0].code);
}

test "flow control caps write to window" {
    // 极小窗口：单流窗口 8 字节。
    const cfg = smodem.tunnel.Config{ .stream_window = 8, .session_window = 64 };
    var client = try Tunnel.init(alloc, cfg, .client);
    defer client.deinit();
    var server = try Tunnel.init(alloc, cfg, .server);
    defer server.deinit();
    try pump(&client, &server);
    while (client.nextEvent()) |_| {}
    while (server.nextEvent()) |_| {}

    const id = try client.open("meta");
    try pump(&client, &server);
    while (server.nextEvent()) |ev| if (ev == .stream_open) {
        try server.accept(ev.stream_open.id, "");
    };
    try pump(&client, &server);
    while (client.nextEvent()) |_| {}

    // 想写 20 字节，但窗口只有 8。
    const n1 = try client.write(id, "0123456789abcdefghij");
    try std.testing.expectEqual(@as(usize, 8), n1);
    // 窗口耗尽，再写返回 0。
    const n2 = try client.write(id, "xxxx");
    try std.testing.expectEqual(@as(usize, 0), n2);

    try pump(&client, &server);
    // server 收下 8 字节并消费 → 回补窗口。
    var sc = Collected{};
    defer sc.deinit();
    try sc.drain(&server);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(alloc);
    try sc.dataFor(id, &got);
    try std.testing.expectEqual(@as(usize, 8), got.items.len);
    try server.consume(id, 8);
    try pump(&client, &server);

    // client 收到 window 回补 → 可继续写。
    while (client.nextEvent()) |_| {}
    const n3 = try client.write(id, "yyyy");
    try std.testing.expect(n3 > 0);
}

test "mid-stream garbage injection triggers resync, data still delivered" {
    const cfg = smodem.tunnel.Config{ .encoding = .b64 };
    var client = try Tunnel.init(alloc, cfg, .client);
    defer client.deinit();
    var server = try Tunnel.init(alloc, cfg, .server);
    defer server.deinit();
    try pump(&client, &server);
    while (client.nextEvent()) |_| {}
    while (server.nextEvent()) |_| {}

    const id = try client.open("meta");
    try pump(&client, &server);
    while (server.nextEvent()) |ev| if (ev == .stream_open) try server.accept(ev.stream_open.id, "");
    try pump(&client, &server);
    while (client.nextEvent()) |_| {}

    // 先发一帧数据；注入垃圾会污染它（可能丢），但后续帧必须能重同步收到。
    _ = try client.write(id, "AAAA");
    try pumpWithInjection(&client, &server, "\r\n[session expires in 5 min]\r\n");
    while (server.nextEvent()) |_| {}

    // 注入之后，新数据必须完好送达。
    _ = try client.write(id, "BBBBBBBB");
    try pump(&client, &server);
    var sc = Collected{};
    defer sc.deinit();
    try sc.drain(&server);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(alloc);
    try sc.dataFor(id, &got);
    try std.testing.expect(std.mem.indexOf(u8, got.items, "BBBBBBBB") != null);
}

// ===================== 探针自动降档（M3） =====================

const Encoding = smodem.tunnel.Encoding;

const Mangler = *const fn ([]const u8, *std.ArrayList(u8)) anyerror!void;

fn mIdentity(in: []const u8, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(alloc, in);
}
fn mOnlcr(in: []const u8, out: *std.ArrayList(u8)) !void { // 0x0A -> 0x0D 0x0A（插字节）
    for (in) |b| {
        if (b == 0x0A) try out.append(alloc, 0x0D);
        try out.append(alloc, b);
    }
}
fn mIstrip(in: []const u8, out: *std.ArrayList(u8)) !void { // 剥高位
    for (in) |b| try out.append(alloc, b & 0x7F);
}
fn mIsig(in: []const u8, out: *std.ArrayList(u8)) !void { // 吞 ^C ^Z ^\
    for (in) |b| {
        if (b == 0x03 or b == 0x1A or b == 0x1C) continue;
        try out.append(alloc, b);
    }
}

fn manglePump(a: *Tunnel, b: *Tunnel, ab: Mangler, ba: Mangler) !void {
    var buf: [8192]u8 = undefined;
    var tmp: std.ArrayList(u8) = .empty;
    defer tmp.deinit(alloc);
    var progress = true;
    var guard: usize = 0;
    while (progress and guard < 10000) : (guard += 1) {
        progress = false;
        const na = a.send(&buf);
        if (na > 0) {
            tmp.clearRetainingCapacity();
            try ab(buf[0..na], &tmp);
            try b.recv(tmp.items);
            progress = true;
        }
        const nb = b.send(&buf);
        if (nb > 0) {
            tmp.clearRetainingCapacity();
            try ba(buf[0..nb], &tmp);
            try a.recv(tmp.items);
            progress = true;
        }
    }
}

fn drainAll(t: *Tunnel) void {
    while (t.nextEvent()) |_| {}
}

/// 建立一对 auto_probe 隧道，用给定 mangler 跑到 ready，再校验一次数据往返。
fn probeAndVerify(ab: Mangler, ba: Mangler, want_client_tx: Encoding, want_server_tx: Encoding) !void {
    const cfg = smodem.tunnel.Config{ .auto_probe = true };
    var client = try Tunnel.init(alloc, cfg, .client);
    defer client.deinit();
    var server = try Tunnel.init(alloc, cfg, .server);
    defer server.deinit();

    try manglePump(&client, &server, ab, ba);
    try std.testing.expect(client.isReady());
    try std.testing.expect(server.isReady());
    // client 的 tx 方向 = client→server = ab；server 的 tx = server→client = ba。
    try std.testing.expectEqual(want_client_tx, client.txEncoding());
    try std.testing.expectEqual(want_server_tx, server.txEncoding());
    // 两端的 rx 应等于对端的 tx。
    try std.testing.expectEqual(want_server_tx, client.rxEncoding());
    try std.testing.expectEqual(want_client_tx, server.rxEncoding());
    drainAll(&client);
    drainAll(&server);

    // 真实数据必须在协商出的编码下穿过 mangler 完好送达。
    const id = try client.open("meta");
    try manglePump(&client, &server, ab, ba);
    while (server.nextEvent()) |ev| if (ev == .stream_open) try server.accept(ev.stream_open.id, "");
    try manglePump(&client, &server, ab, ba);
    drainAll(&client);
    const payload = "the quick brown fox 0123456789 \n\r\x03\x1a\xff\x00 done";
    _ = try client.write(id, payload);
    try manglePump(&client, &server, ab, ba);
    var sc = Collected{};
    defer sc.deinit();
    try sc.drain(&server);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(alloc);
    try sc.dataFor(id, &got);
    try std.testing.expectEqualSlices(u8, payload, got.items);
}

test "probe: clean pipe picks RAW both directions" {
    try probeAndVerify(mIdentity, mIdentity, .raw, .raw);
}

test "probe: ONLCR on client->server downgrades that direction to ESC" {
    try probeAndVerify(mOnlcr, mIdentity, .esc, .raw);
}

test "probe: ISTRIP on client->server downgrades to B64, other stays RAW" {
    try probeAndVerify(mIstrip, mIdentity, .b64, .raw);
}

test "probe: ISIG (byte-eating) downgrades to ESC" {
    try probeAndVerify(mIsig, mIdentity, .esc, .raw);
}

test "probe: both directions hostile (istrip) both pick B64" {
    try probeAndVerify(mIstrip, mIstrip, .b64, .b64);
}
