# Zig Network Abstraction

Small network abstraction layer around TCP & UDP.

## Features
- Implements the minimal API surface for basic networking
- Makes cross-platform abstractions
- Supports blocking and non-blocking I/O via `select`/`poll`
- UDP multicast support

## Notes
On Windows receive and send function calls are asynchronous and cooperate with the standard library event loop
when `io_mode = .evented` is set in the root file of your program.  
Other calls (connect, listen, accept etc) are blocking.  
