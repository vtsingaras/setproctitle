# setproctitle

A utility to change the title of a running process (as seen in `ps`, `htop`, etc.) on Linux.

## Features
- Change process title by PID.
- Supports Linux systems (requires kernel >= 3.5).
- Simple command-line interface.

## Prerequisites
- Linux Kernel >= 3.5
- Root privileges (to use `ptrace` on target processes).
- Build tools: `gcc`, `make`, `autoconf`, `automake`.

## Installation

### From Source
```bash
aclocal && autoconf && autoheader && automake --add-missing
./configure
make
sudo make install
```

## Usage

```bash
sudo setproctitle -p <PID> -t <TITLE>
```

### Options
- `-p, --pid PID`: The process ID of the target process.
- `-t, --title TITLE`: The new title to set.

### Example
Set the title of process 1234 to "my-worker":
```bash
sudo setproctitle -p 1234 -t "my-worker"
```

## Technical Details
This utility works by:
1. Reading `/proc/PID/stat` to locate the argument area in the process's memory.
2. Attaching to the process using `ptrace`.
3. Overwriting the argument area with the new title.
4. Detaching from the process.

**Note**: The new title cannot be longer than the original argument space allocated for the process.

## Troubleshooting
- **Title too long**: If the new title is longer than the original arguments, the operation will fail.
- **Permission denied**: Ensure you are running with `sudo` or as root.
- **Process format changed**: If the format of `/proc/PID/stat` is unexpected, the tool may fail to parse memory addresses.

## License
This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.
