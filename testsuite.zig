const std = @import("std");
const builtin = @import("builtin");
const network = @import("network");
const expect = std.testing.expect;

test "Get endpoint list" {
    try network.init();
    defer network.deinit();

    const endpoint_list = try network.getEndpointList(std.testing.allocator, "google.com", 80);
    defer endpoint_list.deinit();

    for (endpoint_list.endpoints) |endpt| {
        std.debug.print("{}\n", .{endpt});
    }
}

test "Connect to an echo server" {
    const test_host = "tcpbin.com";

    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(std.testing.allocator, test_host, 4242, .tcp);
    defer sock.close();

    const msg = "Hi from socket!\n";
    try sock.writer().writeAll(msg);

    var buf: [128]u8 = undefined;
    const read_size = try sock.reader().readAll(buf[0..msg.len]);
    try std.testing.expectEqualSlices(u8, msg, buf[0..read_size]);
    std.debug.print("Echo: {s}", .{buf[0..read_size]});
}

test "Echo server readiness" {
    const test_host = "tcpbin.com";

    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(
        std.testing.allocator,
        test_host,
        4242,
        .tcp,
    );
    defer sock.close();

    var write_set = try network.SocketSet.init(std.testing.allocator);
    defer write_set.deinit();
    var read_set = try network.SocketSet.init(std.testing.allocator);
    defer read_set.deinit();

    try write_set.add(sock, .{ .write = true, .read = false });
    defer write_set.remove(sock);

    try read_set.add(sock, .{ .write = false, .read = true });
    defer read_set.remove(sock);

    const msg = "Hi from socket!\n";

    if (try network.waitForSocketEvent(&write_set, 5 * std.time.ns_per_s) != 1) {
        return error.InvalidSocketWriteWait;
    }
    if (!write_set.isReadyWrite(sock)) {
        return error.SocketNotReadyForWrite;
    }
    try sock.writer().writeAll(msg);

    if (try network.waitForSocketEvent(&read_set, 5 * std.time.ns_per_s) != 1) {
        return error.InvalidSocketReadWait;
    }
    if (!read_set.isReadyRead(sock)) {
        return error.SocketNotReadyForRead;
    }
    var buf: [128]u8 = undefined;
    const read_size = try sock.reader().readAll(buf[0..msg.len]);
    try std.testing.expectEqualSlices(u8, msg, buf[0..read_size]);
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
    try sock.setReadTimeout(3 * std.time.us_per_s);
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

test "IPv6 parse" {
    const make = network.Address.IPv6.init;
    const parse = network.Address.IPv6.parse;

    var expected = make(.{0} ** 16, 0);
    try std.testing.expectEqual(expected, try parse("::"));
    try std.testing.expectEqual(expected, try parse("0:0:0:0:0:0:0:0"));
    expected.value[15] = 1;
    try std.testing.expectEqual(expected, try parse("::1"));
    expected.value = .{0} ** 16;
    expected.value[0] = 1;
    try std.testing.expectEqual(expected, try parse("100::"));
    expected.value[0] = 0xff;
    expected.value[1] = 0xff;
    expected.value[15] = 1;
    try std.testing.expectEqual(expected, try parse("ffff::1"));
    expected.value[0] = 0x20;
    expected.value[1] = 0x01;
    expected.value[2] = 0x0d;
    expected.value[3] = 0xb8;
    expected.value[4] = 0x0a;
    expected.value[5] = 0x0b;
    expected.value[6] = 0x11;
    expected.value[7] = 0xff;
    expected.value[15] = 0x01;
    try std.testing.expectEqual(
        expected,
        try parse("2001:0db8:0a0b:11ff:0:0:0:1"),
    );
    try std.testing.expectEqual(expected, try parse("2001:db8:a0b:11ff::1"));

    try std.testing.expectError(error.InvalidFormat, parse(":"));
    try std.testing.expectError(error.InvalidFormat, parse(":1"));
    try std.testing.expectError(error.InvalidFormat, parse("1"));
    try std.testing.expectError(error.InvalidFormat, parse("0:0:0:0"));
    try std.testing.expectError(error.InvalidFormat, parse(":::1"));
    try std.testing.expectError(error.InvalidFormat, parse("6::2::1"));

    // NOTE: The below is a valid IPv6 address with zone ID that is explicitly
    // not parsed.
    try std.testing.expectError(error.InvalidFormat, parse("::1%eth0"));
}

// https://github.com/MasterQ32/zig-network/issues/66
test "Windows-only, fix UDP WSAECONNRESET error when calling recvfrom after send failure" {
    if (builtin.os.tag != .windows) {
        // Skip if not Windows
        return;
    }
    try network.init();
    defer network.deinit();

    // setup sockets
    var server_sock = try network.Socket.create(.ipv4, .udp);
    defer server_sock.close();
    try server_sock.setReadTimeout(25 * std.time.us_per_ms);
    try server_sock.bind(.{
        .address = network.Address{ .ipv4 = network.Address.IPv4.any },
        .port = 1234,
    });
    var client_sock = try network.Socket.create(.ipv4, .udp);
    var client_sock_closed = false;
    defer {
        if (!client_sock_closed) {
            client_sock.close();
            client_sock_closed = true;
        }
    }
    try client_sock.connect(.{
        .address = .{ .ipv4 = network.Address.IPv4.init(127, 0, 0, 1) },
        .port = 1234,
    });
    try client_sock.setReadTimeout(25 * std.time.us_per_ms);

    // setup buffer
    const buflen = 32;
    var msg: [buflen]u8 = undefined;

    // send and read data back and forth
    _ = try client_sock.send("connect_info");
    const recvFrom = try server_sock.receiveFrom(msg[0..buflen]);
    // close the socket to force the WSAECONNRESET error when we send below
    client_sock.close();
    client_sock_closed = true;
    // If we do not disable SIO_UDP_CONNRESET then a failed "send" will be caught when the
    // next "recvfrom" function is called.
    //
    // MDN: https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
    // WSAECONNRESET: "On a UDP-datagram socket this error indicates a previous send operation resulted
    // in an ICMP Port Unreachable message."
    _ = try server_sock.sendTo(recvFrom.sender, "data");
    _ = server_sock.receiveFrom(msg[0..buflen]) catch |err| switch (err) {
        error.WouldBlock => {
            // fallthrough, expect this to timeout
        },
        else => {
            return err;
        },
    };
}

test "parse + json parse" {
    const json_string =
        \\{
        \\  "ipv4": "127.0.0.1",
        \\  "address": "10.0.0.1",
        \\  "endpoint": "8.8.4.4:53",
        \\  "ipv6_endpoint": "::1:53"
        \\}
    ;

    const Wrapper = struct {
        ipv4: network.Address.IPv4,
        address: network.Address,
        endpoint: network.EndPoint,
        ipv6_endpoint: network.EndPoint,
    };

    const wrapper = try std.json.parseFromSliceLeaky(
        Wrapper,
        std.testing.allocator, // our address parser does not leak
        json_string,
        .{},
    );

    try std.testing.expectEqual(network.Address.IPv4.init(127, 0, 0, 1), wrapper.ipv4);
    try std.testing.expectEqual(network.Address{ .ipv4 = network.Address.IPv4.init(10, 0, 0, 1) }, wrapper.address);
    try std.testing.expectEqual(network.EndPoint{
        .address = .{ .ipv4 = network.Address.IPv4.init(8, 8, 4, 4) },
        .port = 53,
    }, wrapper.endpoint);

    var expected_addr = network.Address.IPv6.init(.{0} ** 16, 0);
    expected_addr.value[15] = 1;
    try std.testing.expectEqual(network.EndPoint{
        .address = .{ .ipv6 = expected_addr },
        .port = 53,
    }, wrapper.ipv6_endpoint);
}

test "Darwin: connection-mode socket was connected already" {
    const port: u16 = 12345;
    const Server = struct {
        const Self = @This();
        port: u16 = port,
        socket: network.Socket = undefined,
        thread: std.Thread = undefined,

        fn start(srv: *Self) !void {
            try network.init();
            errdefer network.deinit();

            srv.socket = try network.Socket.create(.ipv4, .udp);
            errdefer srv.socket.close();
            _ = try srv.socket.enablePortReuse(true);

            const bindAddr = network.EndPoint{
                .address = network.Address{ .ipv4 = network.Address.IPv4.any },
                .port = srv.port,
            };

            try srv.socket.bind(bindAddr);
            srv.thread = std.Thread.spawn(.{}, run, .{srv}) catch unreachable;
            return;
        }

        fn run(srv: *Self) void {
            defer {
                srv.socket.close();
                network.deinit();
            }
            var buff: [128]u8 = undefined;
            _ = srv.socket.receive(buff[0..]) catch return;
            return;
        }

        fn waitFinish(srv: *Self) void {
            srv.thread.join();
        }
    };

    var srv: Server = .{};
    try srv.start();
    defer srv.waitFinish();

    const addr: []const u8 = "127.0.0.1";

    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(std.testing.allocator, addr, port, .udp);
    defer sock.close();

    var buff: [128]u8 = undefined;
    _ = try sock.send(buff[0..]);

    std.debug.print("Darwin: connection-mode socket test - finished\n", .{});
    return;
}
