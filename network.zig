const std = @import("std");

comptime {
    std.debug.assert(@sizeOf(std.os.sockaddr) >= @sizeOf(std.os.sockaddr_in));
    // std.debug.assert(@sizeOf(std.os.sockaddr) >= @sizeOf(std.os.sockaddr_in6));
}

const is_windows = std.builtin.os.tag == .windows;

pub fn init() error{InitializationError}!void {
    if (is_windows) {
        _ = windows_data.WSAStartup(2, 2) catch return error.InitializationError;
    }
}

pub fn deinit() void {
    if (is_windows) {
        windows_data.WSACleanup() catch return;
    }
}

/// A network address abstraction. Contains one member for each possible type of address.
pub const Address = union(AddressFamily) {
    ipv4: IPv4,
    ipv6: IPv6,

    pub const IPv4 = struct {
        const Self = @This();

        pub const any = IPv4.init(0, 0, 0, 0);
        pub const broadcast = IPv4.init(255, 255, 255, 255);

        value: [4]u8,

        pub fn init(a: u8, b: u8, c: u8, d: u8) Self {
            return Self{
                .value = [4]u8{ a, b, c, d },
            };
        }

        pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, out_stream: var) !void {
            try out_stream.print("{}.{}.{}.{}", .{
                value.value[0],
                value.value[1],
                value.value[2],
                value.value[3],
            });
        }
    };

    pub const IPv6 = struct {
        const Self = @This();

        pub const any = Self{};

        pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, out_stream: var) !void {
            unreachable;
        }
    };

    pub fn format(value: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, out_stream: var) !void {
        switch (value) {
            .ipv4 => |a| try a.format(fmt, options, out_stream),
            .ipv6 => |a| try a.format(fmt, options, out_stream),
        }
    }
};

pub const AddressFamily = enum {
    const Self = @This();

    ipv4,
    ipv6,

    fn toNativeAddressFamily(af: Self) u32 {
        return switch (af) {
            .ipv4 => std.os.AF_INET,
            .ipv6 => std.os.AF_INET6,
        };
    }

    fn fromNativeAddressFamily(af: i32) !Self {
        return switch (af) {
            std.os.AF_INET => .ipv4,
            std.os.AF_INET6 => .ipv6,
            else => return error.UnsupportedAddressFamily,
        };
    }
};

/// Protocols supported by this library.
pub const Protocol = enum {
    const Self = @This();

    tcp,
    udp,

    fn toSocketType(proto: Self) u32 {
        return switch (proto) {
            .tcp => std.os.SOCK_STREAM,
            .udp => std.os.SOCK_DGRAM,
        };
    }
};

/// A network end point. Is composed of an address and a port.
pub const EndPoint = struct {
    const Self = @This();

    address: Address,
    port: u16,

    pub fn format(value: Self, comptime fmt: []const u8, options: std.fmt.FormatOptions, out_stream: var) !void {
        try out_stream.print("{}:{}", .{
            value.address,
            value.port,
        });
    }

    pub fn fromSocketAddress(src: *const std.os.sockaddr, size: usize) !Self {
        switch (src.family) {
            std.os.AF_INET => {
                if (size < @sizeOf(std.os.sockaddr_in))
                    return error.InsufficientBytes;
                const value = @ptrCast(*const std.os.sockaddr_in, @alignCast(4, src));
                return EndPoint{
                    .port = std.mem.bigToNative(u16, value.port),
                    .address = Address{
                        .ipv4 = Address.IPv4{
                            .value = @bitCast([4]u8, value.addr),
                        },
                    },
                };
            },
            std.os.AF_INET6 => {
                return error.UnsupportedAddressFamily;
            },
            else => {
                std.debug.warn("got invalid socket address: {}\n", .{src});
                return error.UnsupportedAddressFamily;
            },
        }
    }

    fn toSocketAddress(self: Self) std.os.sockaddr {
        var result: std.os.sockaddr align(8) = undefined;
        switch (self.address) {
            .ipv4 => |addr| {
                @ptrCast(*std.os.sockaddr_in, &result).* = std.os.sockaddr_in{
                    .family = std.os.AF_INET,
                    .port = std.mem.nativeToBig(u16, self.port),
                    .addr = @bitCast(u32, addr.value),
                    .zero = [_]u8{0} ** 8,
                };
            },
            .ipv6 => |addr| {
                unreachable;
            },
        }
        return result;
    }
};

/// A network socket, can receive and send data for TCP/UDP and accept
/// incoming connections if bound as a TCP server.
pub const Socket = struct {
    pub const Error = error{
        AccessDenied,
        WouldBlock,
        FastOpenAlreadyInProgress,
        ConnectionResetByPeer,
        MessageTooBig,
        SystemResources,
        BrokenPipe,
        Unexpected,
    };
    const Self = @This();

    const NativeSocket = if (is_windows) windows_data.ws2_32.SOCKET else std.os.fd_t;

    family: AddressFamily,
    internal: NativeSocket,

    /// Spawns a new socket that must be freed with `close()`.
    /// `family` defines the socket family, `protocol` the protocol used.
    pub fn create(family: AddressFamily, protocol: Protocol) !Self {
        const socket_fn = if (is_windows) windows_data.windows_socket else std.os.socket;

        return Self{
            .family = family,
            .internal = try socket_fn(family.toNativeAddressFamily(), protocol.toSocketType(), 0),
        };
    }

    /// Closes the socket and releases its resources.
    pub fn close(self: Self) void {
        const close_fn = if (is_windows) windows_data.windows_close else std.os.close;
        close_fn(self.internal);
    }

    /// Binds the socket to the given end point.
    pub fn bind(self: Self, ep: EndPoint) !void {
        const bind_fn = if (is_windows) windows_data.windows_bind else std.os.bind;

        var sockaddr = ep.toSocketAddress();
        try bind_fn(self.internal, &sockaddr, @sizeOf(@TypeOf(sockaddr)));
    }

    /// Binds the socket to all supported addresses on the local device.
    /// This will use the any IP (`0.0.0.0` for IPv4).
    pub fn bindToPort(self: Self, port: u16) !void {
        return switch (self.family) {
            .ipv4 => self.bind(EndPoint{
                .address = Address{ .ipv4 = Address.IPv4.any },
                .port = port,
            }),
            .ipv6 => self.bind(EndPoint{
                .address = Address{ .ipv6 = Address.IPv6.any },
                .port = port,
            }),
        };
    }

    /// Connects the UDP or TCP socket to a remote server.
    /// The `target` address type must fit the address type of the socket.
    pub fn connect(self: Self, target: EndPoint) !void {
        if (target.address != self.family)
            return error.AddressFamilyMismach;

        const connect_fn = if (is_windows) windows_data.windows_connect else std.os.connect;
        const sa = target.toSocketAddress();
        try connect_fn(self.internal, &sa, @sizeOf(@TypeOf(sa)));
    }

    /// Makes this socket a TCP server and allows others to connect to
    /// this socket.
    /// Call `accept()` to handle incoming connections.
    pub fn listen(self: Self) !void {
        const listen_fn = if (is_windows) windows_data.windows_listen else std.os.listen;
        try listen_fn(self.internal, 0);
    }

    /// Waits until a new TCP client connects to this socket and accepts the incoming TCP connection.
    /// This function is only allowed for a bound TCP socket. `listen()` must have been called before!
    pub fn accept(self: Self) !Socket {
        const accept4_fn = if (is_windows) windows_data.windows_accept4 else std.os.accept4;
        const close_fn = if (is_windows) windows_data.windows_close else std.os.close;

        var addr: std.os.sockaddr = undefined;
        var addr_size: std.os.socklen_t = @sizeOf(std.os.sockaddr);

        const fd = try accept4_fn(self.internal, &addr, &addr_size, 0);
        errdefer close_fn(fd);

        return Socket{
            .family = try AddressFamily.fromNativeAddressFamily(addr.family),
            .internal = fd,
        };
    }

    /// Send some data to the connected peer. In UDP, this
    /// will always send full packets, on TCP it will append
    /// to the stream.
    pub fn send(self: Self, data: []const u8) !usize {
        const send_fn = if (is_windows) windows_data.windows_send else std.os.send;
        return try send_fn(self.internal, data, 0);
    }

    /// Blockingly receives some data from the connected peer.
    /// Will read all available data from the TCP stream or
    /// a UDP packet.
    pub fn receive(self: Self, data: []u8) !usize {
        const recvfrom_fn = if (is_windows) windows_data.windows_recvfrom else std.os.recvfrom;

        return try recvfrom_fn(self.internal, data, 0, null, null);
    }

    const ReceiveFrom = struct { numberOfBytes: usize, sender: EndPoint };

    /// Same as ´receive`, but will also return the end point from which the data
    /// was received. This is only a valid operation on UDP sockets.
    pub fn receiveFrom(self: Self, data: []u8) !ReceiveFrom {
        const recvfrom_fn = if (is_windows) windows_data.windows_recvfrom else std.os.recvfrom;

        var addr: std.os.sockaddr align(4) = undefined;
        var size: std.os.socklen_t = @sizeOf(std.os.sockaddr);

        const len = try recvfrom_fn(self.internal, data, 0, &addr, &size);

        return ReceiveFrom{
            .numberOfBytes = len,
            .sender = try EndPoint.fromSocketAddress(&addr, size),
        };
    }

    /// Sends a packet to a given network end point. Behaves the same as `send()`, but will only work for
    /// for UDP sockets.
    pub fn sendTo(self: Self, receiver: EndPoint, data: []const u8) !usize {
        const sendto_fn = if (is_windows) windows_data.windows_sendto else std.os.sendto;

        const sa = receiver.toSocketAddress();
        return try sendto_fn(self.internal, data, 0, &sa, @sizeOf(std.os.sockaddr));
    }

    /// Sets the socket option `SO_REUSEPORT` which allows
    /// multiple bindings of the same socket to the same address
    /// on UDP sockets and allows quicker re-binding of TCP sockets.
    pub fn enablePortReuse(self: Self, enabled: bool) !void {
        const setsockopt_fn = if (is_windows) windows_data.windows_setsockopt else std.os.setsockopt;

        var opt: c_int = if (enabled) 1 else 0;
        try setsockopt_fn(self.internal, std.os.SOL_SOCKET, std.os.SO_REUSEADDR, std.mem.asBytes(&opt));
    }

    /// Retrieves the end point to which the socket is bound.
    pub fn getLocalEndPoint(self: Self) !EndPoint {
        const getsockname_fn = if (is_windows) windows_data.windows_getsockname else std.os.getsockname;

        var addr: std.os.sockaddr align(4) = undefined;
        var size: std.os.socklen_t = @sizeOf(@TypeOf(addr));

        try getsockname_fn(self.internal, &addr, &size);

        return try EndPoint.fromSocketAddress(&addr, size);
    }

    /// Retrieves the end point to which the socket is connected.
    pub fn getRemoteEndPoint(self: Self) !EndPoint {
        const getpeername_fn = if (is_windows) windows_data.windows_getpeername else getpeername;

        var addr: std.os.sockaddr align(4) = undefined;
        var size: std.os.socklen_t = @sizeOf(@TypeOf(addr));

        try getpeername_fn(self.internal, &addr, &size);

        return try EndPoint.fromSocketAddress(&addr, size);
    }

    pub const MulticastGroup = struct {
        interface: Address.IPv4,
        group: Address.IPv4,
    };

    /// Joins the UDP socket into a multicast group.
    /// Multicast enables sending packets to the group and all joined peers
    /// will receive the sent data.
    pub fn joinMulticastGroup(self: Self, group: MulticastGroup) !void {
        const setsockopt_fn = if (is_windows) windows_data.windows_setsockopt else std.os.setsockopt;

        const ip_mreq = extern struct {
            imr_multiaddr: u32,
            imr_address: u32,
            imr_ifindex: u32,
        };

        const request = ip_mreq{
            .imr_multiaddr = @bitCast(u32, group.group.value),
            .imr_address = @bitCast(u32, group.interface.value),
            .imr_ifindex = 0, // this cannot be crossplatform, so we set it to zero
        };

        const IP_ADD_MEMBERSHIP = if (is_windows) 5 else 35;

        try setsockopt_fn(self.internal, std.os.SOL_SOCKET, IP_ADD_MEMBERSHIP, std.mem.asBytes(&request));
    }

    /// Gets an input stream that allows reading data from the socket.
    pub fn inStream(self: Self) std.io.InStream(Socket, std.os.RecvFromError, receive) {
        return .{
            .context = self,
        };
    }

    /// Gets an output stream that allows writing data to the socket.
    pub fn outStream(self: Self) std.io.OutStream(Socket, Error, send) {
        return .{
            .context = self,
        };
    }
};

/// A socket event that can be waited for.
pub const SocketEvent = struct {
    /// Wait for data ready to be read.
    read: bool,

    /// Wait for all pending data to be sent and the socket accepting
    /// non-blocking writes.
    write: bool,
};

/// A set of sockets that can be used to query socket readiness.
/// This is similar to `select()´ or `poll()` and provides a way to
/// create non-blocking socket I/O.
/// This is intented to be used with `waitForSocketEvents()`.
pub const SocketSet = struct {
    const Self = @This();

    internal: OSLogic,

    /// Initialize a new socket set. This can be reused for
    /// multiple queries without having to reset the set every time.
    /// Call `deinit()` to free the socket set.
    pub fn init(allocator: *std.mem.Allocator) !Self {
        return Self{
            .internal = try OSLogic.init(allocator),
        };
    }

    /// Frees the contained resources.
    pub fn deinit(self: *Self) void {
        self.internal.deinit();
    }

    /// Removes all sockets from the set.
    pub fn clear(self: *Self) void {
        self.internal.clear();
    }

    /// Adds a socket to the set and enables waiting for any of the events
    /// in `events`.
    pub fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
        try self.internal.add(sock, events);
    }

    /// Removes the socket from the set.
    pub fn remove(self: *Self, sock: Socket) void {
        self.internal.remove(sock);
    }

    /// Checks if the socket is ready to be read.
    /// Only valid after the first call to `waitForSocketEvents()`.
    pub fn isReadyRead(self: Self, sock: Socket) bool {
        return self.internal.isReadyRead(sock);
    }

    /// Checks if the socket is ready to be written.
    /// Only valid after the first call to `waitForSocketEvents()`.
    pub fn isReadyWrite(self: Self, sock: Socket) bool {
        return self.internal.isReadyWrite(sock);
    }

    /// Checks if the socket is faulty and cannot be used anymore.
    /// Only valid after the first call to `waitForSocketEvents()`.
    pub fn isFaulted(self: Self, sock: Socket) bool {
        return self.internal.isFaulted(sock);
    }
};

/// Implementation of SocketSet for each platform,
/// keeps the thing above nice and clean, all functions get inlined.
const OSLogic = switch (std.builtin.os.tag) {
    // Linux uses `poll()` syscall to wait for socket events.
    // This allows an arbitrary number of sockets to be handled.
    .linux => struct {
        const Self = @This();
        // use poll on linux

        fds: std.ArrayList(std.os.pollfd),

        inline fn init(allocator: *std.mem.Allocator) Self {
            return Self{
                .fds = std.ArrayList(std.os.pollfd).init(allocator),
            };
        }

        inline fn deinit(self: Self) void {
            self.fds.deinit();
        }

        inline fn clear(self: *Self) void {
            self.fds.shrink(0);
        }

        inline fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
            // Always poll for errors as this is done anyways
            var mask: i16 = std.os.POLLERR;

            if (events.read)
                mask |= std.os.POLLIN;
            if (events.write)
                mask |= std.os.POLLOUT;

            for (self.fds.items) |*pfd| {
                if (pfd.fd == sock.internal) {
                    pfd.events |= mask;
                    return;
                }
            }

            try self.fds.append(std.os.pollfd{
                .fd = sock.internal,
                .events = mask,
                .revents = 0,
            });
        }

        inline fn remove(self: *Self, sock: Socket) void {
            const index = for (self.fds.items) |item, i| {
                if (item.fd == sock.internal)
                    break i;
            } else null;

            if (index) |idx| {
                _ = self.fds.swapRemove(idx);
            }
        }

        inline fn checkMaskAnyBit(self: Self, sock: Socket, mask: i16) bool {
            for (self.fds.items) |item| {
                if (item.fd != sock.internal)
                    continue;

                if ((item.revents & mask) != 0) {
                    return true;
                }

                return false;
            }
            return false;
        }

        inline fn isReadyRead(self: Self, sock: Socket) bool {
            return self.checkMaskAnyBit(sock, std.os.POLLIN);
        }

        inline fn isReadyWrite(self: Self, sock: Socket) bool {
            return self.checkMaskAnyBit(sock, std.os.POLLOUT);
        }

        inline fn isFaulted(self: Self, sock: Socket) bool {
            return self.checkMaskAnyBit(sock, std.os.POLLERR);
        }
    },
    .windows => struct {
        // The windows struct fd_set uses a statically size array of 64 sockets by default.
        // However, it is documented that one can create bigger sets and pass them into the functions that use them.
        // Instead, we dynamically allocate the sets and reallocate them as needed.
        // See https://docs.microsoft.com/en-us/windows/win32/winsock/maximum-number-of-sockets-supported-2
        const FdSet = extern struct {
            capacity: c_uint,
            size: c_uint,

            fn fdSlice(self: *align(8) FdSet) []windows_data.ws2_32.SOCKET {
                return @ptrCast([*]windows_data.ws2_32.SOCKET, @ptrCast([*]u8, self) + 2 * @sizeOf(c_uint))[0..self.size];
            }

            fn make(allocator: *std.mem.Allocator) !*align(8) FdSet {
                // Initialize with enough space for 8 sockets.
                var mem = try allocator.alignedAlloc(u8, 8, 2 * @sizeOf(c_uint) + 8 * @sizeOf(windows_data.ws2_32.SOCKET));
                @ptrCast(*c_uint, mem.ptr).* = 8;
                @ptrCast(*c_uint, mem.ptr + @sizeOf(c_uint)).* = 0;
                return @ptrCast(*FdSet, mem);
            }

            fn clear(self: *align(8) FdSet) void {
                self.size = 0;
            }

            fn memSlice(self: *align(8) FdSet) []u8 {
                return @ptrCast([*]u8, self)[0..(2 * @sizeOf(c_uint) + self.capacity * @sizeOf(windows_data.ws2_32.SOCKET))];
            }

            fn deinit(self: *align(8) FdSet, allocator: *std.mem.Allocator) void {
                allocator.free(self.memSlice());
            }

            fn containsFd(self: *align(8) FdSet, fd: windows_data.ws2_32.SOCKET) bool {
                for (self.fdSlice()) |ex_fd| {
                    if (ex_fd == fd) return true;
                }
                return false;
            }

            fn addFd(fd_set: **align(8) FdSet, allocator: *std.mem.Allocator, new_fd: windows_data.ws2_32.SOCKET) !void {
                if (fd_set.*.size == fd_set.*.capacity) {
                    // Double our capacity.
                    const new_mem_size = 2 * @sizeOf(c_uint) + 2 * fd_set.*.capacity * @sizeOf(windows_data.ws2_32.SOCKET);
                    fd_set.* = @ptrCast(*align(8) FdSet, (try allocator.alignedRealloc(fd_set.*.memSlice(), 8, new_mem_size)).ptr);
                    fd_set.*.capacity *= 2;
                }

                fd_set.*.size += 1;
                fd_set.*.fdSlice()[fd_set.*.size - 1] = new_fd;
            }

            fn getSelectPointer(self: *align(8) FdSet) ?[*]u8 {
                if (self.size == 0) return null;
                return @ptrCast([*]u8, self) + @sizeOf(c_uint);
            }
        };

        const Self = @This();

        allocator: *std.mem.Allocator,

        read_fds: std.ArrayListUnmanaged(windows_data.ws2_32.SOCKET),
        write_fds: std.ArrayListUnmanaged(windows_data.ws2_32.SOCKET),

        read_fd_set: *align(8) FdSet,
        write_fd_set: *align(8) FdSet,
        except_fd_set: *align(8) FdSet,

        inline fn init(allocator: *std.mem.Allocator) !Self {
            // TODO: https://github.com/ziglang/zig/issues/5391
            var read_fds = std.ArrayListUnmanaged(windows_data.ws2_32.SOCKET){};
            var write_fds = std.ArrayListUnmanaged(windows_data.ws2_32.SOCKET){};
            try read_fds.ensureCapacity(allocator, 8);
            try write_fds.ensureCapacity(allocator, 8);

            return Self{
                .allocator = allocator,
                .read_fds = .{},
                .write_fds = .{},
                .read_fd_set = try FdSet.make(allocator),
                .write_fd_set = try FdSet.make(allocator),
                .except_fd_set = try FdSet.make(allocator),
            };
        }

        inline fn deinit(self: *Self) void {
            self.read_fds.deinit(self.allocator);
            self.write_fds.deinit(self.allocator);

            self.read_fd_set.deinit(self.allocator);
            self.write_fd_set.deinit(self.allocator);
            self.except_fd_set.deinit(self.allocator);
        }

        inline fn clear(self: *Self) void {
            self.read_fds.shrink(0);
            self.write_fds.shrink(0);

            self.read_fd_set.clear();
            self.write_fd_set.clear();
            self.except_fd_set.clear();
        }

        inline fn add(self: *Self, sock: Socket, events: SocketEvent) !void {
            if (events.read) {
                for (self.read_fds.items) |fd| {
                    if (fd == sock.internal) return;
                }
                try self.read_fds.append(self.allocator, sock.internal);
            }
            if (events.write) {
                for (self.write_fds.items) |fd| {
                    if (fd == sock.internal) return;
                }
                try self.write_fds.append(self.allocator, sock.internal);
            }
        }

        inline fn remove(self: *Self, sock: Socket) void {
            for (self.read_fds.items) |fd, idx| {
                if (fd == sock.internal) {
                    _ = self.read_fds.swapRemove(idx);
                    break;
                }
            }
            for (self.write_fds.items) |fd, idx| {
                if (fd == sock.internal) {
                    _ = self.write_fds.swapRemove(idx);
                    break;
                }
            }
        }

        const Set = enum {
            read,
            write,
            except,
        };

        inline fn getFdSet(self: *Self, comptime set_selection: Set) !?[*]u8 {
            const set_ptr = switch (set_selection) {
                .read => &self.read_fd_set,
                .write => &self.write_fd_set,
                .except => &self.except_fd_set,
            };

            set_ptr.*.clear();
            if (set_selection == .read or set_selection == .except) {
                for (self.read_fds.items) |fd| {
                    try FdSet.addFd(set_ptr, self.allocator, fd);
                }
            }

            if (set_selection == .write) {
                for (self.write_fds.items) |fd| {
                    try FdSet.addFd(set_ptr, self.allocator, fd);
                }
            } else if (set_selection == .except) {
                for (self.write_fds.items) |fd| {
                    if (set_ptr.*.containsFd(fd)) continue;
                    try FdSet.addFd(set_ptr, self.allocator, fd);
                }
            }
            return set_ptr.*.getSelectPointer();
        }

        inline fn isReadyRead(self: Self, sock: Socket) bool {
            if (self.read_fd_set.getSelectPointer()) |ptr| {
                return windows_data.__WSAFDIsSet(sock.internal, ptr);
            }
            return false;
        }

        inline fn isReadyWrite(self: Self, sock: Socket) bool {
            if (self.write_fd_set.getSelectPointer()) |ptr| {
                return windows_data.__WSAFDIsSet(sock.internal, ptr);
            }
            return false;
        }

        inline fn isFaulted(self: Self, sock: Socket) bool {
            if (self.except_fd_set.getSelectPointer()) |ptr| {
                return windows_data.__WSAFDIsSet(sock.internal, ptr);
            }
            return false;
        }
    },
    else => @compileError("unsupported os " ++ @tagName(std.builtin.os.tag) ++ " for SocketSet!"),
};

/// Waits until sockets in SocketSet are ready to read/write or have a fault condition.
/// If `timeout` is not `null`, it describes a timeout in nanoseconds until the function
/// should return.
/// Note that `timeout` granularity may not be available in nanoseconds and larger
/// granularities are used.
/// If the requested timeout interval requires a finer granularity than the implementation supports, the
/// actual timeout interval shall be rounded up to the next supported value.
pub fn waitForSocketEvent(set: *SocketSet, timeout: ?u64) !usize {
    switch (std.builtin.os.tag) {
        .windows => {
            const read_set = try set.internal.getFdSet(.read);
            const write_set = try set.internal.getFdSet(.write);
            const except_set = try set.internal.getFdSet(.except);
            if (read_set == null and write_set == null and except_set == null) return 0;

            const tm: windows_data.timeval = if (timeout) |tout| block: {
                const secs = @divFloor(tout, std.time.ns_per_s);
                const usecs = @divFloor(tout - secs * std.time.ns_per_s, 1000);
                break :block .{ .tv_sec = @intCast(c_long, secs), .tv_usec = @intCast(c_long, usecs) };
            } else .{ .tv_sec = 0, .tv_usec = 0 };

            // Windows ignores first argument.
            // return try windows_data.windows_select(0, read_set, write_set, except_set, &tm);
            return try windows_data.windows_select(0, null, write_set, null, &tm);
        },
        .linux => return try std.os.poll(
            set.internal.fds.items,
            if (timeout) |val| @intCast(i32, (val + std.time.millisecond - 1) / std.time.millisecond) else -1,
        ),
        else => @compileError("unsupported os " ++ @tagName(std.builtin.os.tag) ++ " for SocketSet!"),
    }
}

const GetPeerNameError = error{
    /// Insufficient resources were available in the system to perform the operation.
    SystemResources,
    NotConnected,
} || std.os.UnexpectedError;

fn getpeername(sockfd: std.os.fd_t, addr: *std.os.sockaddr, addrlen: *std.os.socklen_t) GetPeerNameError!void {
    switch (std.os.errno(std.os.system.getsockname(sockfd, addr, addrlen))) {
        0 => return,
        else => |err| return std.os.unexpectedErrno(err),

        std.os.EBADF => unreachable, // always a race condition
        std.os.EFAULT => unreachable,
        std.os.EINVAL => unreachable, // invalid parameters
        std.os.ENOTSOCK => unreachable,
        std.os.ENOBUFS => return error.SystemResources,
        std.os.ENOTCONN => return error.NotConnected,
    }
}

const windows_data = struct {
    usingnamespace std.os.windows;

    const timeval = extern struct {
        tv_sec: c_long,
        tv_usec: c_long,
    };

    extern "ws2_32" fn socket(af: c_int, type_0: c_int, protocol: c_int) callconv(.Stdcall) ws2_32.SOCKET;
    extern "ws2_32" fn sendto(s: ws2_32.SOCKET, buf: [*c]const u8, len: c_int, flags: c_int, to: [*c]const std.os.sockaddr, tolen: std.os.socklen_t) callconv(.Stdcall) c_int;
    extern "ws2_32" fn send(s: ws2_32.SOCKET, buf: [*c]const u8, len: c_int, flags: c_int) callconv(.Stdcall) c_int;
    extern "ws2_32" fn recvfrom(s: ws2_32.SOCKET, buf: [*c]u8, len: c_int, flags: c_int, from: [*c]std.os.sockaddr, fromlen: [*c]std.os.socklen_t) callconv(.Stdcall) c_int;
    extern "ws2_32" fn listen(s: ws2_32.SOCKET, backlog: c_int) callconv(.Stdcall) c_int;
    extern "ws2_32" fn accept(s: ws2_32.SOCKET, addr: [*c]std.os.sockaddr, addrlen: [*c]std.os.socklen_t) callconv(.Stdcall) ws2_32.SOCKET;
    extern "ws2_32" fn setsockopt(s: ws2_32.SOCKET, level: c_int, optname: c_int, optval: [*c]const u8, optlen: c_int) callconv(.Stdcall) c_int;
    extern "ws2_32" fn getsockname(s: ws2_32.SOCKET, name: [*c]std.os.sockaddr, namelen: [*c]std.os.socklen_t) callconv(.Stdcall) c_int;
    extern "ws2_32" fn getpeername(s: ws2_32.SOCKET, name: [*c]std.os.sockaddr, namelen: [*c]std.os.socklen_t) callconv(.Stdcall) c_int;
    extern "ws2_32" fn select(nfds: c_int, readfds: ?*c_void, writefds: ?*c_void, exceptfds: ?*c_void, timeout: [*c]const timeval) callconv(.Stdcall) c_int;
    extern "ws2_32" fn __WSAFDIsSet(arg0: ws2_32.SOCKET, arg1: [*]u8) c_int;
    extern "ws2_32" fn bind(s: ws2_32.SOCKET, addr: [*c]const std.os.sockaddr, namelen: std.os.socklen_t) callconv(.Stdcall) c_int;

    fn windows_socket(addr_family: u32, socket_type: u32, protocol: u32) std.os.SocketError!ws2_32.SOCKET {
        const sock = socket(@intCast(c_int, addr_family), @intCast(c_int, socket_type), @intCast(c_int, protocol));
        if (sock == ws2_32.INVALID_SOCKET) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
                .WSAEMFILE => return error.ProcessFdQuotaExceeded,
                .WSAENOBUFS => return error.SystemResources,
                .WSAEPROTONOSUPPORT => return error.ProtocolNotSupported,
                else => |err| return unexpectedWSAError(err),
            };
        }
        return sock;
    }

    fn windows_connect(sock: ws2_32.SOCKET, sock_addr: *const std.os.sockaddr, len: std.os.socklen_t) std.os.ConnectError!void {
        while (true) if (ws2_32.connect(sock, sock_addr, len) != 0) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEACCES => error.PermissionDenied,
                .WSAEADDRINUSE => error.AddressInUse,
                .WSAEINPROGRESS => error.WouldBlock,
                .WSAEALREADY => unreachable,
                .WSAEAFNOSUPPORT => error.AddressFamilyNotSupported,
                .WSAECONNREFUSED => error.ConnectionRefused,
                .WSAEFAULT => unreachable,
                .WSAEINTR => continue,
                .WSAEISCONN => unreachable,
                .WSAENETUNREACH => error.NetworkUnreachable,
                .WSAEHOSTUNREACH => error.NetworkUnreachable,
                .WSAENOTSOCK => unreachable,
                .WSAETIMEDOUT => error.ConnectionTimedOut,
                .WSAEWOULDBLOCK => error.WouldBlock,
                else => |err| return unexpectedWSAError(err),
            };
        } else return;
    }

    fn windows_close(sock: ws2_32.SOCKET) void {
        if (ws2_32.closesocket(sock) != 0) {
            switch (ws2_32.WSAGetLastError()) {
                .WSAENOTSOCK => unreachable,
                .WSAEINPROGRESS => unreachable,
                else => return,
            }
        }
    }

    fn windows_sendto(
        sock: ws2_32.SOCKET,
        buf: []const u8,
        flags: u32,
        dest_addr: ?*const std.os.sockaddr,
        addrlen: std.os.socklen_t,
    ) std.os.SendError!usize {
        while (true) {
            const result = sendto(sock, buf.ptr, @intCast(c_int, buf.len), @intCast(c_int, flags), dest_addr, addrlen);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEACCES => error.AccessDenied,
                    .WSAECONNRESET => error.ConnectionResetByPeer,
                    .WSAEDESTADDRREQ => unreachable,
                    .WSAEFAULT => unreachable,
                    .WSAEINTR => continue,
                    .WSAEINVAL => unreachable,
                    .WSAEMSGSIZE => error.MessageTooBig,
                    .WSAENOBUFS => error.SystemResources,
                    .WSAENOTCONN => unreachable,
                    .WSAENOTSOCK => unreachable,
                    .WSAEOPNOTSUPP => unreachable,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    fn windows_send(sock: ws2_32.SOCKET, buf: []const u8, flags: u32) std.os.SendError!usize {
        return windows_sendto(sock, buf, flags, null, 0);
    }

    fn windows_recvfrom(
        sock: ws2_32.SOCKET,
        buf: []u8,
        flags: u32,
        src_addr: ?*std.os.sockaddr,
        addrlen: ?*std.os.socklen_t,
    ) std.os.RecvFromError!usize {
        while (true) {
            const result = recvfrom(sock, buf.ptr, @intCast(c_int, buf.len), @intCast(c_int, flags), src_addr, addrlen);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAEISCONN => unreachable,
                    .WSAENOTSOCK => unreachable,
                    .WSAESHUTDOWN => unreachable,
                    .WSAEOPNOTSUPP => unreachable,
                    .WSAEWOULDBLOCK => error.WouldBlock,
                    .WSAEINTR => continue,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    // TODO: std.os.ListenError is not pub.
    const ListenError = error{
        AddressInUse,
        FileDescriptorNotASocket,
        OperationNotSupported,
    } || std.os.UnexpectedError;

    fn windows_listen(sock: ws2_32.SOCKET, backlog: u32) ListenError!void {
        const rc = listen(sock, @intCast(c_int, backlog));
        if (rc != 0) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEADDRINUSE => error.AddressInUse,
                .WSAENOTSOCK => error.FileDescriptorNotASocket,
                .WSAEOPNOTSUPP => error.OperationNotSupported,
                else => |err| return unexpectedWSAError(err),
            };
        }
    }

    /// Ignores flags
    fn windows_accept4(
        sock: ws2_32.SOCKET,
        addr: ?*std.os.sockaddr,
        addr_size: *std.os.socklen_t,
        flags: u32,
    ) std.os.AcceptError!ws2_32.SOCKET {
        while (true) {
            const result = accept(sock, addr, addr_size);
            if (result == ws2_32.INVALID_SOCKET) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEINTR => continue,
                    .WSAEWOULDBLOCK => error.WouldBlock,
                    .WSAECONNRESET => error.ConnectionAborted,
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAENOTSOCK => unreachable,
                    .WSAEMFILE => error.ProcessFdQuotaExceeded,
                    .WSAENOBUFS => error.SystemResources,
                    .WSAEOPNOTSUPP => unreachable,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return result;
        }
    }

    fn windows_setsockopt(sock: ws2_32.SOCKET, level: u32, optname: u32, opt: []const u8) std.os.SetSockOptError!void {
        if (setsockopt(sock, @intCast(c_int, level), @intCast(c_int, optname), opt.ptr, @intCast(c_int, opt.len)) != 0) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAENOTSOCK => unreachable,
                .WSAEINVAL => unreachable,
                .WSAEFAULT => unreachable,
                .WSAENOPROTOOPT => error.InvalidProtocolOption,
                else => |err| return unexpectedWSAError(err),
            };
        }
    }

    fn windows_getsockname(sock: ws2_32.SOCKET, addr: *std.os.sockaddr, addrlen: *std.os.socklen_t) std.os.GetSockNameError!void {
        if (getsockname(sock, addr, addrlen) != 0) {
            return unexpectedWSAError(ws2_32.WSAGetLastError());
        }
    }

    fn windows_getpeername(sock: ws2_32.SOCKET, addr: *std.os.sockaddr, addrlen: *std.os.socklen_t) GetPeerNameError!void {
        if (getpeername(sock, addr, addrlen) != 0) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAENOTCONN => error.NotConnected,
                else => |err| return unexpectedWSAError(err),
            };
        }
    }

    pub const SelectError = error{FileDescriptorNotASocket} || std.os.UnexpectedError;

    fn windows_select(nfds: usize, read_fds: ?[*]u8, write_fds: ?[*]u8, except_fds: ?[*]u8, timeout: ?*const timeval) SelectError!usize {
        while (true) {
            // Windows ignores nfds so we just pass zero here.
            const result = select(0, read_fds, write_fds, except_fds, timeout);
            if (result == ws2_32.SOCKET_ERROR) {
                return switch (ws2_32.WSAGetLastError()) {
                    .WSAEFAULT => unreachable,
                    .WSAEINVAL => unreachable,
                    .WSAEINTR => continue,
                    .WSAENOTSOCK => error.FileDescriptorNotASocket,
                    else => |err| return unexpectedWSAError(err),
                };
            }
            return @intCast(usize, result);
        }
    }

    fn windows_bind(sock: ws2_32.SOCKET, addr: *const std.os.sockaddr, namelen: std.os.socklen_t) std.os.BindError!void {
        if (bind(sock, addr, namelen) != 0) {
            return switch (ws2_32.WSAGetLastError()) {
                .WSAEACCES => error.AccessDenied,
                .WSAEADDRINUSE => error.AddressInUse,
                .WSAEINVAL => unreachable,
                .WSAENOTSOCK => unreachable,
                .WSAEADDRNOTAVAIL => error.AddressNotAvailable,
                .WSAEFAULT => unreachable,
                else => |err| return unexpectedWSAError(err),
            };
        }
    }
};
