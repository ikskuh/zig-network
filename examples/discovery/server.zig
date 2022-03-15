const std = @import("std");
const network = @import("network");

// Discovery Server
// Emits a UDP to the multicast address 224.0.0.1 on port 8080
// with the name of this server

// See examples/discover/client.zig for code that
// collects these emitted messages

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // get the name of the server
    var args_iter = try std.process.argsWithAllocator(allocator);
    const exe_name = args_iter.next() orelse return error.MissingArgument;
    defer allocator.free(exe_name);

    const server_name = args_iter.next() orelse "Server Name";
    defer allocator.free(server_name);

    // Create a UDP socket
    try network.init();
    defer network.deinit();
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    const endpoint = network.EndPoint{
        .address = network.Address{
            .ipv4 = network.Address.IPv4.multicast_all,
        },
        .port = 8080,
    };

    // Setup the readloop
    std.debug.print("Sending UDP messages to multicast address {}\n", .{endpoint});
    while (true) {
        _ = try sock.sendTo(endpoint, server_name);
        std.time.sleep(2 * std.time.ns_per_s);
    }
}
