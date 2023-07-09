const std = @import("std");
const network = @import("network");
const debug = std.debug;

pub fn main() !void {
    try network.init();
    defer network.deinit();
    var request: [48]u8 = std.mem.zeroes([48]u8);
    request[0] = 0b00100011; // NTP version 4, mode 3 (client)

    var sock = try network.connectToHost(std.heap.page_allocator, "pool.ntp.org", 123, .udp);
    defer sock.close();

    try sock.writer().writeAll(&request);

    var response: [48]u8 = undefined;
    _ = try sock.reader().readAll(&response);

    // The timestamp is stored in bytes 40-43 of the response
    const seconds = @divFloor(std.time.milliTimestamp(), std.time.ms_per_s);

    // zig fmt: off
    const fractionalSeconds = @as(u64, @intCast(response[40])) << 24
    | @as(u64, @intCast(response[41])) << 16
    | @as(u64, @intCast(response[42])) << 8
    | @as(u64, @intCast(response[43]));
    
    var timestamp = @divFloor(seconds, 2_208_988_800) * std.time.ms_per_s + fractionalSeconds * (std.time.ns_per_s / 4_294_967_296);

    debug.print("NTP timestamp: {}\n", .{timestamp}); //0

    // result: 1970 -1 -1  0: 0: 0 (UTC 1970-01-01)
    debug.print("{s}\n", .{try convertTimestampToTime(@as(u64, @intCast(timestamp)))});
}

pub const secs_per_day: u17 = 24 * 60 * 60;

pub const EpochSeconds = struct {
    secs: u64,

    pub fn getEpochDay(self: EpochSeconds) std.time.epoch.EpochDay {
        return .{ .day = @as(u47, @intCast(self.secs / secs_per_day)) };
    }

    pub fn getDaySeconds(self: EpochSeconds) std.time.epoch.DaySeconds {
        return .{ .secs = std.math.comptimeMod(self.secs, secs_per_day) };
    }
};

pub fn convertTimestampToTime(timestamp: u64) ![]const u8 {
    const epochSeconds = EpochSeconds{ .secs = timestamp };
    const epochDay = epochSeconds.getEpochDay();
    const daySeconds = epochSeconds.getDaySeconds();
    const yearDay = epochDay.calculateYearDay();
    const monthDay = yearDay.calculateMonthDay();
    var buf: [80:0]u8 = undefined;

    return std.fmt.bufPrint(&buf, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}", .{ yearDay.year, monthDay.month.numeric(), monthDay.day_index + 1, daySeconds.getHoursIntoDay(), daySeconds.getMinutesIntoHour(), daySeconds.getSecondsIntoMinute() });
}
