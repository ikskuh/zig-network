const std = @import("std");
const network = @import("network");

// Multicast UDP example, using threads + sync IO

// Scanner Thread :
// Listens on 224.0.0.1:8080 for UDP broadcasts from Game Servers
// that advertise their address, and add them to the list

// main thread:
// periodically print the list of known servers

// Server is a container for holding data on servers discovered on the network
const Server = struct {
    const Self = @This();
    address: network.Address,
    name: []u8,

    pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print("Server: {} : {s}", .{
            value.address,
            value.name,
        });
    }
};

// ServerList is a thread safe list of Server structs
const ServerList = struct {
    const Self = @This();
    list: std.ArrayList(Server),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .list = std.ArrayList(Server).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(value: Self) void {
        value.list.deinit();
    }

    pub fn append(value: *Self, data: Server) !void {
        value.mutex.lock();
        defer value.mutex.unlock();
        for (value.list.items) |item| {
            if (std.meta.eql(item.address, data.address)) {
                // is already in the list, dont add it again
                return;
            }
        }
        std.debug.print(">> Discovered {}\n", .{data});
        try value.list.append(data);
    }

    pub fn getServers(value: Self) []Server {
        return value.list.items;
    }
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    try network.init();
    defer network.deinit();

    var server_list = ServerList.init(allocator);
    defer server_list.deinit();

    // background task to collect servers via UDP broadcasts
    var server_thread = try std.Thread.spawn(.{ .stack_size = 1024 }, scanServersThread, .{
        allocator,
        &server_list,
    });
    server_thread.detach();

    // Show the found servers every 5 seconds
    var last_count: usize = 0;
    while (true) {
        server_list.mutex.lock();
        const servers = server_list.getServers();
        if (servers.len != last_count) {
            std.debug.print("\nDiscovered Servers:\n===================\n", .{});
            for (servers) |s| {
                std.debug.print("{}\n", .{s});
            }
            last_count = servers.len;
        }
        server_list.mutex.unlock();
        std.time.sleep(1 * std.time.ns_per_s);
    }
}

// scanServersThread - runs in a thread
// Listens for broadcast UDP packets to collect server information
// and add the details to the ServerList passed in
fn scanServersThread(allocator: std.mem.Allocator, server_list: *ServerList) !void {
    std.debug.print("Scanning for Servers to connect to ....\n", .{});

    const port_number = 8080;

    // Create a UDP socket
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    // Bind to 224.0.0.1:8080, allow port re-use so that multiple instances
    // of this program can all subscribe to the UDP broadcasts
    try sock.enablePortReuse(true);
    const incoming_endpoint = network.EndPoint{
        .address = network.Address{ .ipv4 = network.Address.IPv4.multicast_all },
        .port = port_number,
    };
    sock.bind(incoming_endpoint) catch |err| {
        std.debug.print("failed to bind to {}:{}\n", .{ incoming_endpoint, err });
    };

    // Join the multicast group on 224.0.0.1
    const all_group = network.Socket.MulticastGroup{
        .group = network.Address.IPv4.multicast_all,
        .interface = network.Address.IPv4.any,
    };
    sock.joinMulticastGroup(all_group) catch |err| {
        std.debug.print("Failed to join mcast group {}:{}\n", .{ all_group, err });
    };

    const buflen: usize = 128;
    var msg: [buflen]u8 = undefined;

    while (true) {
        const recv_msg = try sock.receiveFrom(msg[0..buflen]);
        var last_char = recv_msg.numberOfBytes;

        // dirty hack to trim any trailing CR/LF from the input
        // could use std.mem.trimRight twice ?
        if (msg[last_char - 1] == 10) {
            last_char -= 1;
        }
        if (msg[last_char - 1] == 13) {
            last_char -= 1;
        }

        const name = msg[0..last_char];

        try server_list.append(Server{
            .address = recv_msg.sender.address,
            .name = try allocator.dupe(u8, name),
        });
    }
}
