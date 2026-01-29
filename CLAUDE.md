# CLAUDE.md - Project Instructions for Claude Code

## Project Overview

**setproctitle** is a Linux utility that changes the title/name of a running process as displayed in system monitoring tools like `htop` and `ps`. It uses ptrace system calls to modify a process's argument memory region.

## Build Instructions

This project uses GNU Autotools. To build from source:

```bash
# Generate build system (only needed once or after configure.ac changes)
aclocal && autoconf && autoheader && automake --add-missing

# Configure and build
./configure
make

# Install (requires root)
sudo make install
```

## Project Structure

```
setproctitle/
├── src/setproctitle.c    # Main implementation (single C file)
├── man/setproctitle.1    # Man page documentation
├── configure.ac          # Autoconf configuration
├── Makefile.am           # Root automake configuration
└── src/Makefile.am       # Source automake config
```

## Key Files

- `src/setproctitle.c` - The entire implementation (~149 lines of C)
- `man/setproctitle.1` - Man page with usage documentation

## Development Guidelines

- **C Standard**: GNU99 (`-std=gnu99`)
- **Compiler Flags**: Strict warnings enabled (`-Werror`)
- **Root Required**: The utility checks for root privileges at runtime via `geteuid()`
- **Linux Only**: Requires Linux kernel >= 3.5 and `/proc` filesystem

## Key System Calls Used

- `ptrace(PTRACE_ATTACH/PEEKDATA/POKEDATA/CONT)` - Process memory manipulation
- `wait()` - Synchronize after attaching to process
- `/proc/[pid]/stat` - Read process memory layout information

## Usage

```bash
setproctitle --pid PID --title TITLE
# or
setproctitle -p PID -t TITLE
```

**Limitation**: New title cannot be longer than the original process title.

## Testing

No automated test suite. Manual testing approach:
1. Start a long-running process (e.g., `sleep 1000`)
2. Run `setproctitle -p <pid> -t "new title"`
3. Verify with `ps aux | grep <pid>` or `htop`

## License

GPLv3 - See LICENSE file
