const std = @import("std");
const network = @import("network");

// Broadcast UDP example
// Broadcasts a 64 byte UDP packet to port 60000 and waits for a reply.

// Test this by listening for a UDP broadcast on any machine on the same network segment:
// nc -lu 60000 | xxd

const BUFFER_SIZE = 1024;

pub fn main() !void {
    std.debug.print("   UDP broadcast example\n\n", .{});
    try network.init();
    defer network.deinit();

    // Create a UDP socket with SO_BROADCAST enabled
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    try sock.setBroadcast(true);

    // Bind to 0.0.0.0:0
    const bindAddr = network.EndPoint{
        .address = network.Address{ .ipv4 = network.Address.IPv4.any },
        .port = 0,
    };

    const destAddr = network.EndPoint{
        .address = network.Address{ .ipv4 = network.Address.IPv4.broadcast },
        .port = 60000,
    };

    try sock.bind(bindAddr);

    // Send broadcast packet
    const packet = [64]u8{
        0x17, 0x94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };

    const N = try sock.sendTo(destAddr, &packet);

    std.debug.print("   sent {any} bytes\n", .{N});
    dump(packet);
}

fn dump(packet: [64]u8) void {
    const offsets = [_]usize{ 0, 16, 32, 48 };
    for (offsets) |ix| {
        const f = "{x:0<2} {x:0<2} {x:0<2} {x:0<2} {x:0<2} {x:0<2} {x:0<2} {x:0<2}";
        const u = packet[ix .. ix + 8];
        const v = packet[ix + 8 .. ix + 16];
        std.debug.print("   ", .{});
        std.debug.print(f, .{ u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7] });
        std.debug.print("  ", .{});
        std.debug.print(f, .{ v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7] });
        std.debug.print("\n", .{});
    }

    std.debug.print("\n", .{});
}
