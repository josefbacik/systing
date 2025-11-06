# Systing

To build, ensure you have installed bpftool. This only builds on linux.

Previous versions of this tool had 3 distinct sub-commands, `system`, `profile`,
and `describe`, as I was experimenting with different approaches to identifying
problems.  That code can be found in the `old-systing` branch.

The current iteration is just a single command, `systing`.

## Quick start

To build, ensure you have installed bpftool. This only builds on linux.

```bash
cargo build
sudo ./target/debug/systing --duration 60
```

This will generate a `trace.pb` file which can be uploaded to a
[Perfetto](https://perfetto.dev/) instance for further analysis.

## Development Setup

**IMPORTANT**: If you're contributing code, enable the git hooks to enforce code formatting:

```bash
./setup-hooks.sh
```

This sets up automatic `cargo fmt` checks before commits and pushes. See [CLAUDE.md](CLAUDE.md) for full development workflow details.

## Usage

Detailed options can be found [here](docs/USAGE.adoc).

### Enhanced Symbol Resolution

For improved symbol resolution, you can enable debuginfod support:

```bash
export DEBUGINFOD_URLS="https://debuginfod.fedoraproject.org/"
sudo ./target/debug/systing --enable-debuginfod --duration 60
```

This will fetch debug information from debuginfod servers, providing more accurate stack traces.

### Recorder Management

Systing includes several recorders for different types of events. You can control which recorders are active using the following options:

#### List Available Recorders

```bash
sudo ./target/debug/systing --list-recorders
```

This will display all available recorders and their default states:
- `sched` - Scheduler event tracing (on by default)
- `syscalls` - Syscall tracing
- `sleep-stacks` - Sleep stack traces (on by default)
- `cpu-stacks` - CPU perf stack traces (on by default)
- `pystacks` - Python stack tracing (requires pystacks feature)

#### Add Specific Recorders

Use `--add-recorder` to enable additional recorders on top of the defaults:

```bash
# Enable syscalls in addition to default recorders
sudo ./target/debug/systing --add-recorder syscalls --duration 60

# Enable multiple additional recorders
sudo ./target/debug/systing --add-recorder syscalls --add-recorder pystacks --duration 60
```

#### Use Only Specific Recorders

Use `--only-recorder` to disable all recorders and enable only the ones you specify:

```bash
# Only record syscalls (disable everything else)
sudo ./target/debug/systing --only-recorder syscalls --duration 60

# Only record syscalls and cpu-stacks
sudo ./target/debug/systing --only-recorder syscalls --only-recorder cpu-stacks --duration 60
```

### Debugging and Verbosity

Use multiple `-v` flags to control verbosity levels:

```bash
# Basic informational output
sudo ./target/debug/systing -v --duration 60

# Detailed debugging (useful for troubleshooting)
sudo ./target/debug/systing -vv --enable-debuginfod --duration 60

# Maximum verbosity (includes library debugging)
sudo ./target/debug/systing -vvv --enable-debuginfod --duration 60
```

This tool traces all the scheduling events on the system, cgroup, or process and
generates a [Perfetto](https://perfetto.dev/) trace.  This can be uploaded to a
local perfetto instance for further analysis, or you can use the public one
[here](https://ui.perfetto.dev/).

NOTE: With cgroup and process tracing, you will see other processes that appear
to not end, this is because the tool is tracing the scheduling events captures
the process going off the CPU or going on the CPU in addition to the process
being traced, so you will miss events for the unwanted process leaving the CPU.
Perfetto handles this appropriately, but it looks odd.

`--trace-event` - This will add an `instant` track event for each event that
this tool captures.  The format is "<trace type>:<optional
info>:<class>:<name>".  This is most easily obtained by running

```
bpftrace -lp <pid of desired program> | grep <name of usdt>
```

The currently allowed formats are

- `usdt:/path/to/executable:tracepoint_name:tracepoint_class`
- `uprobe:/path/to/executable:function_name`
- `uprobe:/path/to/executable:offset`
- `uprobe:/path/to/executable:function_name+offset`
- `uretprobe:/path/to/executable:function_name`
- `uretprobe:/path/to/executable:offset`
- `uretprobe:/path/to/executable:function_name+offset`
- `kprobe:function_name`
- `kprobe:offset`
- `kprobe:function_name+offset`
- `kretprobe:function_name`
- `kretprobe:offset`
- `tracepoint:subsystem:tracepoint_name`

For all `usdt` and `u*probe` events you *must* specify `--trace-event-pid` to to
indicate which PID's you wish to record the events for. For example, if you want
to trace when `qemu` does a v9fs create, you would run the following

```
systing --trace-event-pid <PID of qemu> --trace-event "usdt:/usr/bin/qemu-system-x86_64:qemu:v9fs_create"
````

## Custom track events

You can also add complex track event configurations to the trace.  Examples of
these configuration files can be found in the examples directory.  The format is
described in the [docs](docs/USAGE.adoc) and is a JSON file.  You can specify
these configuration files with `--track-event-config`.

The `pthread_mutex` example will add a track that shows the time spent locking
the mutex and the time that the mutex is locked by the thread.

```JSON
{
  "events": [
    {
      "name": "mutex_entry",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_entry",
      "keys": [
        {
          "key_index": 0,
          "key_type": "long"
        }
      ]
    },
    {
      "name": "mutex_acquired",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_acquired",
      "keys": [
        {
          "key_index": 0,
          "key_type": "long"
        }
      ]
    },
    {
      "name": "mutex_release",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_release",
      "keys": [
        {
          "key_index": 0,
          "key_type": "long"
        }
      ]
    },
  ],
  "tracks": [
    {
      "track_name": "pthread",
      "ranges": [
        {
          "name": "locking",
          "start": "mutex_entry",
          "end": "mutex_acquired"
        },
        {
          "name": "locked",
          "start": "mutex_acquired",
          "end": "mutex_release"
        }
      ]
    },
  ]
}
```

This results in a track that looks like this

![pthread mutex example](docs/pthread.png)
