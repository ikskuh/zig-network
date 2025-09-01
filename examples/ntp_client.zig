const std = @import("std");
const network = @import("network");
const debug = std.debug;

pub fn main() !void {
    try network.init();
    defer network.deinit();

    const request = std.mem.zeroInit(NtpHeader, .{
        .flags = .{ .mode = .client },
    });

    var sock = try network.connectToHost(std.heap.page_allocator, "pool.ntp.org", 123, .udp);
    defer sock.close();

    var work_buf: [@sizeOf(NtpHeader)]u8 = undefined;
    {
        var writer = sock.writer(&work_buf);
        try writer.interface.writeStruct(request, .big);
        try writer.interface.flush();
    }

    const response: NtpHeader = blk: {
        var reader = sock.reader(&work_buf);
        break :blk try reader.interface.takeStruct(NtpHeader, .big);
    };

    std.log.info("NTP Response:", .{});
    std.log.info("  flags > version        = {}", .{response.flags.version});
    std.log.info("  flags > mode           = .{s}", .{@tagName(response.flags.mode)});
    std.log.info("  flags > leap indicator = .{s}", .{@tagName(response.flags.leap_indicator)});
    std.log.info("  peer clock stratum     = .{s}", .{@tagName(response.peer_clock_stratum)});
    std.log.info("  polling interval       = {}", .{response.polling_interval});
    std.log.info("  peer clock precision   = {}", .{response.peer_clock_precision});
    std.log.info("  root delay             = {d}", .{response.root_delay});
    std.log.info("  root dispersion        = {d}", .{response.root_dispersion});
    std.log.info("  reference id           = {d}", .{response.reference_id});
    std.log.info("  reference timestamp    = {d}", .{response.reference_timestamp});
    std.log.info("  origin timestamp       = {d}", .{response.origin_timestamp});
    std.log.info("  receive timestamp      = {d}", .{response.receive_timestamp});
    std.log.info("  transmit timestamp     = {d}", .{response.transmit_timestamp});
    std.log.info("", .{});

    // 1 Jan 1970
    const unix_epoch_in_ntp_epoch = 2_208_988_800; //  First day UNIX

    const unix_timestamp = response.transmit_timestamp.seconds -| unix_epoch_in_ntp_epoch;

    var buf: [80:0]u8 = undefined;
    std.log.info("UNIX UTC timestamp: {s}", .{try convertTimestampToTime(&buf, unix_timestamp)});
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

pub fn convertTimestampToTime(buf: []u8, timestamp: u64) ![]const u8 {
    const epochSeconds = EpochSeconds{ .secs = timestamp };
    const epochDay = epochSeconds.getEpochDay();
    const daySeconds = epochSeconds.getDaySeconds();
    const yearDay = epochDay.calculateYearDay();
    const monthDay = yearDay.calculateMonthDay();

    return std.fmt.bufPrint(buf, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}", .{ yearDay.year, monthDay.month.numeric(), monthDay.day_index + 1, daySeconds.getHoursIntoDay(), daySeconds.getMinutesIntoHour(), daySeconds.getSecondsIntoMinute() });
}

comptime {
    std.debug.assert(@sizeOf(NtpHeader) == 48);
}
pub const NtpHeader = extern struct {
    const Flags = packed struct(u8) {
        mode: enum(u3) {
            reserved = 0,
            symmetric_active = 1,
            symmetric_passive = 2,
            client = 3,
            server = 4,
            broadcast = 5,
            ntp_control_message = 6,
            reserved_for_private_use = 7,
        },
        version: u3 = 4,
        leap_indicator: enum(u2) {
            no_warning = 0,
            /// last minute of the day has 61 seconds
            last_minute_61 = 1,
            /// last minute of the day has 59 seconds
            last_minute_59 = 2,
            /// unknown (clock unsynchronized)
            unknown = 3,
        } = .unknown,
    };
    flags: Flags,
    peer_clock_stratum: enum(u8) {
        unspecified = 0, // unspecified or invalid
        primary_server = 1, // primary server (e.g., equipped with a GPS receiver)
        secondary_server_0 = 2, // secondary server (via NTP)
        secondary_server_1 = 3, // secondary server (via NTP)
        secondary_server_2 = 4, // secondary server (via NTP)
        secondary_server_3 = 5, // secondary server (via NTP)
        secondary_server_4 = 6, // secondary server (via NTP)
        secondary_server_5 = 7, // secondary server (via NTP)
        secondary_server_6 = 8, // secondary server (via NTP)
        secondary_server_7 = 9, // secondary server (via NTP)
        secondary_server_8 = 10, // secondary server (via NTP)
        secondary_server_9 = 11, // secondary server (via NTP)
        secondary_server_10 = 12, // secondary server (via NTP)
        secondary_server_11 = 13, // secondary server (via NTP)
        secondary_server_12 = 14, // secondary server (via NTP)
        secondary_server_13 = 15, // secondary server (via NTP)
        unsynchronized = 16,
        _, // 17 .. 255 reserved
    },

    /// Poll: 8-bit signed integer representing the maximum interval between
    /// successive messages, in log2 seconds.  Suggested default limits for
    /// minimum and maximum poll intervals are 6 and 10, respectively.
    polling_interval: i8,

    /// Precision: 8-bit signed integer representing the precision of the
    /// system clock, in log2 seconds.  For instance, a value of -18
    /// corresponds to a precision of about one microsecond.  The precision
    /// can be determined when the service first starts up as the minimum
    /// time of several iterations to read the system clock.
    peer_clock_precision: i8,

    // Root Delay (rootdelay): Total round-trip delay to the reference clock, in NTP short format.
    root_delay: NtpShort,

    // Root Dispersion (rootdisp): Total dispersion to the reference clock, in NTP short format.
    root_dispersion: NtpShort,

    /// 32-bit code identifying the particular server
    /// or reference clock.  The interpretation depends on the value in the
    /// stratum field.
    reference_id: u32,

    /// Reference Timestamp: Time when the system clock was last set or
    /// corrected, in NTP timestamp format.
    reference_timestamp: NtpTimestamp,

    /// Origin Timestamp (org): Time at the client when the request departed
    /// for the server, in NTP timestamp format.
    origin_timestamp: NtpTimestamp,

    /// Receive Timestamp (rec): Time at the server when the request arrived
    /// from the client, in NTP timestamp format.
    receive_timestamp: NtpTimestamp,

    /// Transmit Timestamp (xmt): Time at the server when the response left
    /// for the client, in NTP timestamp format.
    transmit_timestamp: NtpTimestamp,
};

const NtpShort = packed struct(u32) {
    seconds: u16,
    fraction: u16,

    pub fn get_seconds(ts: NtpShort) f32 {
        const secs: f32 = @floatFromInt(ts.seconds);
        const frac: f32 = @floatFromInt(ts.fraction);

        return secs + frac / std.math.maxInt(u16);
    }

    pub fn formatNumber(ts: NtpShort, writer: *std.io.Writer, opt: std.fmt.Number) !void {
        try writer.printFloat(ts.get_seconds(), opt);
    }
};

/// In the date and timestamp formats, the prime epoch, or base date of
/// era 0, is 0 h 1 January 1900 UTC, when all bits are zero.
const NtpTimestamp = extern struct {
    seconds: u32,
    fraction: u32,

    pub fn get_seconds(ts: NtpTimestamp) f64 {
        const secs: f64 = @floatFromInt(ts.seconds);
        const frac: f64 = @floatFromInt(ts.fraction);

        return secs + frac / std.math.maxInt(u32);
    }

    pub fn formatNumber(ts: NtpTimestamp, writer: *std.io.Writer, opt: std.fmt.Number) !void {
        try writer.printFloat(ts.get_seconds(), opt);
    }
};
