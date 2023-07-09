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
