const std = @import("std");
const network = @import("network");

// Multicast UDP example
// listens on 224.0.0.1 (all machines on subnet) on port 9999

// You can run this on any node on your local network,
// each instance will receive UDPs sent to the multicast address

// You can run multiple instances of this program, all listening
// for the same UDP broadcast on the same port.

// test this by doing this from any machine on the network
// echo "this is a test" | nc -u -w0 224.0.0.1 9999

pub fn main() !void {
    try network.init();
    defer network.deinit();

    // Create a UDP socket
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    // Bind to 224.0.0.1:9999, allow port re-use so that multiple instances
    // of this program can all subscribe to the UDP broadcasts
    try sock.enablePortReuse(true);
    const incoming_endpoint = network.EndPoint{
        .address = network.Address{ .ipv4 = network.Address.IPv4.multicast_all },
        .port = 9999,
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

    // Setup the readloop
    std.debug.print("Waiting for UDP messages from socket {!}\n", .{sock.getLocalEndPoint()});
    const buflen = 4096;
    var msg: [buflen]u8 = undefined;
    const r = sock.reader();
    while (true) {
        const bytes = try r.read(msg[0..buflen]);
        std.debug.print(">> {s}\n", .{msg[0..bytes]});
    }
}
