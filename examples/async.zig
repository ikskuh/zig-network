const std = @import("std");
const network = @import("network");

pub const io_mode = .evented;

pub fn main() !void {
    // Make sure async is on
    if (!std.io.is_async)
        return error.NO_ASYNC;
    const allocator = std.heap.page_allocator;

    // Start the network (only executes code under Windows)
    try network.init();
    defer network.deinit();

    // Start the server and bind it to a port
    var server = try network.Socket.create(.ipv4, .tcp);
    defer server.close();
    try server.bindToPort(2505);

    // start to listen on the port
    try server.listen();
    std.debug.warn("listening at {}\n", .{try server.getLocalEndPoint()});

    // Setup clients to accept incoming connections
    const N_CLIENTS = 4;
    var clients = std.ArrayList(*Client).init(allocator);
    try clients.resize(N_CLIENTS);
    for (clients.items) |*it| {
        it.* = try Client.createAndStart(allocator, &server);
    }

    // Main event loop
    while (true) {
        for (clients.items) |client| {
            if (!client.done) {
                resume client.handle_frame;
            } else {
                //restart a closed client
                await client.handle_frame catch |e| {
                    std.debug.warn("client ended with error: {}, restarting client\n", .{e});
                };
                client.start(&server);
            }
        }

        // take some breath
        std.os.nanosleep(0, 30000000);
    }
}

const Client = struct {
    conn: network.Socket = undefined,
    handle_frame: @Frame(Client.handle) = undefined,
    done: bool = false,

    fn createAndStart(allocator: *std.mem.Allocator, server: *network.Socket) !*Client {
        const client = try allocator.create(Client);
        client.start(server);
        return client;
    }

    fn start(self: *Client, server: *network.Socket) void {
        self.* = Client{};
        self.handle_frame = async self.handle(server);
    }

    fn handle(self: *Client, server: *network.Socket) !void {
        std.debug.warn("accepting\n", .{});

        while (true) {
            self.conn = server.accept() catch |e| {
                switch (e) {
                    error.WouldBlock => {
                        suspend;
                        continue;
                    },
                    else => {
                        std.debug.warn("error: {}\n", .{e});
                        self.done = true;
                        return e;
                    },
                }
            };
            break;
        }
        try self.conn.writer().writeAll("server: welcome to the chat server\n");
        std.debug.warn("remote ip:{}\n", .{self.conn.getRemoteEndPoint()});

        while (true) {
            var buf: [100]u8 = undefined;
            const amt = self.conn.receive(&buf) catch |e| {
                switch (e) {
                    error.WouldBlock => {
                        suspend;
                        continue;
                    },
                    else => {
                        std.debug.warn("error: {}\n", .{e});
                        self.done = true;
                        return e;
                    },
                }
            };
            if (amt == 0) {
                self.done = true;
                break; // We're done, end of connection
            }
            const msg = buf[0..amt];
            std.debug.print("Client wrote: {s}", .{msg});
        }
    }
};
