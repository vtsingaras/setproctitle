# Development Cheat Sheet

## Build
- Build: `autoreconf -fi && ./configure && make`
- Install: `sudo make install`
- Clean: `make clean`

## Run
- Run utility: `sudo ./src/setproctitle -p <PID> -t <TITLE>`
  - Requires root privileges.
  - Example: `sudo ./src/setproctitle -p 1234 -t "new-title"`

## Development
- The source code is in `src/setproctitle.c`.
- Uses `ptrace` to modify process memory.
