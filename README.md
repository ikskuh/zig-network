# Zig Network Abstraction

Small network abstraction layer around TCP & UDP.

## Features
- Implements the minimal API surface for basic networking
- Makes cross-platform abstractions
- Supports blocking and non-blocking I/O via `select`/`poll`
- UDP multicast support

## Usage Example

```zig
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
