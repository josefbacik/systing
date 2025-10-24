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
./target/debug/systing --duration 60
```

This will generate a `trace.pb` file which can be uploaded to a
[Perfetto](https://perfetto.dev/) instance for further analysis.

## Usage

Detailed options can be found [here](docs/USAGE.adoc).

### Privilege Requirements

Systing requires elevated privileges to load eBPF programs. It supports two modes:

#### Automatic Privilege Separation (Recommended)

When run as a normal user on systems with systemd, systing automatically:
1. Spawns a privileged collector process via `systemd-run` (polkit authentication)
2. Runs the data processing and file writing in your unprivileged session
3. Creates output files owned by your user (not root)
4. Uses your `~/.cache/debuginfod_client` for symbol caching

No special setup required - just run `systing` and authenticate when prompted:

```bash
./target/debug/systing --duration 60
```

#### Manual Privilege Elevation

On systems without systemd, or with `--no-privilege-separation`:
```bash
sudo ./target/debug/systing --duration 60
```

Note: Output files will be owned by root, and you may need `sudo -E` to preserve DEBUGINFOD_URLS.

#### Capability-Based (Advanced)

On Linux 5.8+, you can grant specific capabilities instead of full root:
```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource=ep $(which systing)
./target/debug/systing --duration 60  # No sudo or systemd-run needed
```

#### Troubleshooting

**"systemd-run not found"**: Install systemd or use `sudo systing`

**Polkit authentication fails**: Check polkit rules or use `sudo systing --no-privilege-separation`

**In containers**: Grant `CAP_BPF` and `CAP_PERFMON` capabilities to the container

**"Permission denied" when writing trace.pb**: If trace.pb exists from a previous root-owned run:
```bash
rm trace.pb  # Remove old root-owned file
./target/debug/systing --duration 60
```

**SELinux denials on Fedora/RHEL**: If running from home directory (e.g., `./target/debug/systing`), SELinux prevents systemd from executing user home files. Solutions:

1. **Install to system location** (recommended):
   ```bash
   sudo cp ./target/debug/systing /usr/local/bin/
   /usr/local/bin/systing --duration 60
   ```

2. **Change SELinux context**:
   ```bash
   chcon -t bin_t ./target/debug/systing
   ./target/debug/systing --duration 60
   ```

3. **Use fallback with sudo**:
   ```bash
   sudo ./target/debug/systing --no-privilege-separation --duration 60
   ```

4. **Check for denials**: `sudo ausearch -c '(systing)' --raw | audit2why`

### Enhanced Symbol Resolution

For improved symbol resolution, you can enable debuginfod support:

```bash
export DEBUGINFOD_URLS="https://debuginfod.fedoraproject.org/"
./target/debug/systing --enable-debuginfod --duration 60
```

This will fetch debug information from debuginfod servers, providing more accurate stack traces.

### Recorder Management

Systing includes several recorders for different types of events. You can control which recorders are active using the following options:

#### List Available Recorders

```bash
./target/debug/systing --list-recorders
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
./target/debug/systing --add-recorder syscalls --duration 60

# Enable multiple additional recorders
./target/debug/systing --add-recorder syscalls --add-recorder pystacks --duration 60
```

#### Use Only Specific Recorders

Use `--only-recorder` to disable all recorders and enable only the ones you specify:

```bash
# Only record syscalls (disable everything else)
./target/debug/systing --only-recorder syscalls --duration 60

# Only record syscalls and cpu-stacks
./target/debug/systing --only-recorder syscalls --only-recorder cpu-stacks --duration 60
```

### Debugging and Verbosity

Use multiple `-v` flags to control verbosity levels:

```bash
# Basic informational output
./target/debug/systing -v --duration 60

# Detailed debugging (useful for troubleshooting)
./target/debug/systing -vv --enable-debuginfod --duration 60

# Maximum verbosity (includes library debugging)
./target/debug/systing -vvv --enable-debuginfod --duration 60
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
