const std = @import("std");
const network = @import("network");

// Simple TCP echo server:
// Accepts a single incoming connection and will echo any received data back to the
// client. Increasing the buffer size might improve throughput.

// using 1000 here yields roughly 54 MBit/s
// using 100_00 yields 150 MB/s
const buffer_size = 1000;

pub fn main() !void {
    try network.init();
    defer network.deinit();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    var args_iter = try std.process.argsWithAllocator(allocator);
    const exe_name = args_iter.next() orelse return error.MissingArgument;
    defer allocator.free(exe_name);

    const port_name = args_iter.next() orelse return error.MissingArgument;
    defer allocator.free(port_name);

    const port_number = try std.fmt.parseInt(u16, port_name, 10);

    var sock = try network.Socket.create(.ipv4, .tcp);
    defer sock.close();

    try sock.bindToPort(port_number);

    try sock.listen();

    while (true) {
        var client = try sock.accept();
        defer client.close();

        std.debug.print("Client connected from {}.\n", .{
            try client.getLocalEndPoint(),
        });

        runEchoClient(client) catch |err| {
            std.debug.print("Client disconnected with msg {s}.\n", .{
                @errorName(err),
            });
            continue;
        };
        std.debug.print("Client disconnected.\n", .{});
    }
}

fn runEchoClient(client: network.Socket) !void {
    while (true) {
        var buffer: [buffer_size]u8 = undefined;

        const len = try client.receive(&buffer);
        if (len == 0)
            break;
        // we ignore the amount of data sent.
        _ = try client.send(buffer[0..len]);
    }
}
