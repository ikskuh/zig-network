const std = @import("std");
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
        .address = .{
            .ipv4 = network.Address.IPv4.init(1, 1, 1, 1)
        },
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
