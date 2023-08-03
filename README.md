# Zig Network Abstraction

Small network abstraction layer around TCP & UDP.

## Features
- Implements the minimal API surface for basic networking
- Makes cross-platform abstractions
- Supports blocking and non-blocking I/O via `select`/`poll`
- UDP multicast support

## Usage

### Use with the package manager

`build.zig.zon`:
```zig
.{
    .name = "appname",
    .version = "0.0.0",
    .dependencies = .{
        .network = .{
            .url = "https://github.com/MasterQ32/zig-network/archive/<COMMIT_HASH_HERE>.tar.gz",
            .hash = "HASH_GOES_HERE",
        },
    },
}
```
(To aquire the hash, please remove the line containing `.hash`, the compiler will then tell you which line to put back)

`build.zig`:
```zig
exe.addModule("network", b.dependency("network", .{}).module("network"));
```

### Usage example

```zig
const network = @import("network");

test "Connect to an echo server" {
    try network.init();
    defer network.deinit();

    const sock = try network.connectToHost(std.heap.page_allocator, "tcpbin.com", 4242, .tcp);
    defer sock.close();

    const msg = "Hi from socket!\n";
    try sock.writer().writeAll(msg);

    var buf: [128]u8 = undefined;
    std.debug.print("Echo: {}", .{buf[0..try sock.reader().readAll(buf[0..msg.len])]});
}
```

See [async.zig](examples/async.zig) for a more complete example on how to use asynchronous I/O to make a small TCP server.

## Run examples

Build all examples:

```bash
$ zig build examples
```

Build a specific example:

```bash
$ zig build sync-examples
```

To test an example, eg. `echo`:

```bash
$ ./zig-out/bin/echo 3000
``` 

in another terminal

```bash
$ nc localhost 3000
hello
hello
how are you
how are you
```

## Notes
On Windows receive and send function calls are asynchronous and cooperate with the standard library event loop
when `io_mode = .evented` is set in the root file of your program.  
Other calls (connect, listen, accept etc) are blocking.  
