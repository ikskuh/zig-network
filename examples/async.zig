const std = @import("std");
const network = @import("network");

pub const io_mode = .evented;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    try network.init();
    defer network.deinit();

    var server = try network.Socket.create(.ipv4, .tcp);
    defer server.close();

    try server.bind(.{
        .address = .{ .ipv4 = network.Address.IPv4.any },
        .port = 2501,
    });

    try server.listen();
    std.log.info("listening at {}\n", .{try server.getLocalEndPoint()});
    while (true) {
        std.debug.print("Waiting for connection\n", .{});
        const client = try allocator.create(Client);
        client.* = Client{
            .conn = try server.accept(),
            .handle_frame = async client.handle(),
        };
    }
}

const Client = struct {
    conn: network.Socket,
    handle_frame: @Frame(Client.handle),

    fn handle(self: *Client) !void {
        try self.conn.writer().writeAll("server: welcome to the chat server\n");

        while (true) {
            var buf: [100]u8 = undefined;
            const amt = try self.conn.receive(&buf);
            if (amt == 0)
                break; // We're done, end of connection
            const msg = buf[0..amt];
            std.debug.print("Client wrote: {s}", .{msg});
        }
    }
};
