const std = @import("std");
const builtin = @import("builtin");
const network = @import("network");
const expect = std.testing.expect;

test "Get endpoint list" {
    try network.init();
    defer network.deinit();

    const endpoint_list = try network.getEndpointList(std.heap.page_allocator, "google.com", 80);
    defer endpoint_list.deinit();

    for (endpoint_list.endpoints) |endpt| {
        std.debug.print("{}\n", .{endpt});
    }
}

test "Connect to an echo server" {
    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(std.heap.page_allocator, "tcpbin.com", 4242, .tcp);
    defer sock.close();

    const msg = "Hi from socket!\n";
    try sock.writer().writeAll(msg);

    var buf: [128]u8 = undefined;
    std.debug.print("Echo: {s}", .{buf[0..try sock.reader().readAll(buf[0..msg.len])]});
}

test "UDP timeout" {
    try network.init();
    defer network.deinit();

    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();
    try sock.connect(.{
        .address = .{ .ipv4 = network.Address.IPv4.init(1, 1, 1, 1) },
        .port = 53,
    });
    try sock.setReadTimeout(3000000); // 3 seconds
    try std.testing.expectError(error.WouldBlock, sock.reader().readByte());
}

test "IPv4 parse" {
    const make = network.Address.IPv4.init;
    const parse = network.Address.IPv4.parse;

    try std.testing.expectEqual(make(0, 0, 0, 0), try parse("0"));
    try std.testing.expectEqual(make(0, 0, 0, 0), try parse("0.0"));
    try std.testing.expectEqual(make(0, 0, 0, 0), try parse("0.0.0"));
    try std.testing.expectEqual(make(0, 0, 0, 0), try parse("0.0.0.0"));

    try std.testing.expectEqual(make(0, 0, 0, 10), try parse("10"));
    try std.testing.expectEqual(make(20, 0, 0, 10), try parse("20.10"));
    try std.testing.expectEqual(make(30, 20, 0, 10), try parse("30.20.10"));
    try std.testing.expectEqual(make(40, 30, 20, 10), try parse("40.30.20.10"));

    try std.testing.expectEqual(make(127, 0, 0, 1), try parse("2130706433"));
    try std.testing.expectEqual(make(127, 10, 20, 30), try parse("127.660510"));
    try std.testing.expectEqual(make(127, 33, 10, 20), try parse("127.33.2580"));
    try std.testing.expectEqual(make(255, 255, 255, 255), try parse("255.255.255.255"));
}

// https://github.com/MasterQ32/zig-network/issues/66
test "Windows-only, check that recvfrom ECONNRESET error are no longer returned" {
    if (builtin.os.tag != .windows) {
        // Skip if not Windows
        return;
    }
    if (builtin.single_threaded) {
        // Can't test bug if single threaded
        return;
    }
    try network.init();
    defer network.deinit();

    // note(jae): 2023-07-09
    // Catching the ECONNRESET bug only happens occassionally so we loop a fair number of
    // times to ensure it catches the bug.
    //
    // On my machine I've tested with lower numbers like 5-25 but that *sometimes* doesn't
    // catch the bug if we comment out the SIO_UDP_CONNRESET fix.
    for (0..100) |_| {
        // setup
        var server_sock = try network.Socket.create(.ipv4, .udp);
        defer server_sock.close();
        try server_sock.setReadTimeout(25 * std.time.us_per_ms);
        try server_sock.bind(.{
            .address = network.Address{ .ipv4 = network.Address.IPv4.any },
            .port = 1234,
        });
        var client_sock = try network.Socket.create(.ipv4, .udp);
        defer client_sock.close();
        try client_sock.connect(.{
            .address = .{ .ipv4 = network.Address.IPv4.init(127, 0, 0, 1) },
            .port = 1234,
        });
        try client_sock.setReadTimeout(25 * std.time.us_per_ms);

        // start server in thread
        var has_stopped_server_thread = std.atomic.Atomic(bool).init(false);
        var server_thread = try std.Thread.spawn(.{}, struct {
            fn thread_fn(sock: network.Socket, is_thread_stopped: *std.atomic.Atomic(bool)) !void {
                const buflen = 64;
                var server_msg: [buflen]u8 = undefined;
                while (true) {
                    if (is_thread_stopped.load(.Monotonic)) {
                        return;
                    }
                    const recvFrom = sock.receiveFrom(server_msg[0..buflen]) catch |err| switch (err) {
                        error.WouldBlock => {
                            continue;
                        },
                        else => {
                            return err;
                        },
                    };
                    _ = try sock.sendTo(recvFrom.sender, "data");
                }
            }
        }.thread_fn, .{ server_sock, &has_stopped_server_thread });
        defer {
            has_stopped_server_thread.store(true, .Monotonic);
            server_thread.join();
        }

        // start client sending thread
        var has_stopped_client_thread = std.atomic.Atomic(bool).init(false);
        var client_thread = try std.Thread.spawn(.{}, struct {
            fn thread_fn(sock: network.Socket, is_thread_stopped: *std.atomic.Atomic(bool)) !void {
                while (true) {
                    if (is_thread_stopped.load(.Monotonic)) {
                        return;
                    }
                    _ = try sock.send("connect_info");
                }
            }
        }.thread_fn, .{ client_sock, &has_stopped_client_thread });
        defer {
            has_stopped_client_thread.store(true, .Monotonic);
            client_thread.join();
        }

        // client read data from server
        const buflen = 64;
        var msg: [buflen]u8 = undefined;
        for (0..100) |_| {
            // receive data
            const numberOfBytesReceived = try client_sock.receive(msg[0..buflen]);
            try std.testing.expect(std.mem.eql(u8, msg[0..numberOfBytesReceived], "data"));
        }
    }
}
