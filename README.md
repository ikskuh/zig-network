# Zig Network Abstraction

Small network abstraction layer around TCP & UDP.

## Features
- Implements the minimal API surface for basic networking
- Makes cross-platform abstractions
- Supports blocking and non-blocking I/O via `select`/`poll`
- UDP multicast support

## Notes
On Windows, all function calls will be blocking and will not interact with
the standard library event loop, regardless of the io_mode set in the root
file of your program.  
