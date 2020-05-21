const std = @import("std");
const network = @import("network.zig");

test "addrlist" {
    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(std.heap.page_allocator, "tcpbin.com", 4242, .tcp);
    defer sock.close();

    const msg = "Hi from socket!\n";
    try sock.outStream().writeAll(msg);

    var buf: [128]u8 = undefined;
    std.debug.warn("Echo: {}", .{buf[0..try sock.inStream().readAll(buf[0..msg.len])]});
}
