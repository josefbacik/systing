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

## Usage

Detailed options can be found [here](docs/USAGE.adoc).

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

For all `usdt` and `u*probe` events you *must* specify `--trace-event-pid` to to
indicate which PID's you wish to record the events for. For example, if you want
to trace when `qemu` does a v9fs create, you would run the following

```
systing --trace-event-pid <PID of qemu> --trace-event "usdt:/usr/bin/qemu-system-x86_64:qemu:v9fs_create"
````
