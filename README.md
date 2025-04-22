# Systing

To build, ensure you have installed bpftool. This only builds on linux.

Previous versions of this tool had 3 distinct sub-commands, `system`, `profile`,
and `describe`, as I was experimenting with different approaches to identifying
problems.  That code can be found in the `old-systing` branch.

The current iteration is just a single command, `systing`.

## TODO FOR SYSTEM
- [X] Separate the stack traces out into their own NUMA node bound ringbufs.
- [X] Add an option to disable the stack traces.
- [ ] Build a `perfetto` plugin to replicate the `runqueue` and `wake latency`
  tracks, then remove those tracks to slim down the trace file size.
- [ ] Figure out something better to do about cgroup and PID based tracing so it
  doesn't leave ghost tasks.
- [X] Add IRQ events.
- [X] Add normal perf sample events to trace CPU time as well.
- [ ] Add a way to trace arbitrary tracepoints.
    - [ ] Add a way to trace tracepoints in the kernel.
    - [X] Add a way to trace tracepoints in userspace.
- [ ] Determine the number of NUMA nodes on the system and set the extra ringbuf
  sizes to 0 to avoid the memory overhead.
- [ ] If there are no USDT's, set the ringbuf sizes to 0 to avoid the memory
  overhead.
- [X] Separate out the USDT recorder into it's own object so there's no lock
  contention between the event recorder and the USDT recorder.
- [X] Separate out the stack recorder into it's own object so there's no lock
  contention between the different recorders.

## Usage

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

User space tracepoints (USDT) are currently the only ones supported, and you
must specify the path to the executable/library that contains the tracepoint.
`--trace-event-pid` must also be specified.  For example, if you want to trace
when `qemu` does a v9fs create, you would run the following

```
systing --trace-event-pid <PID of qemu> --trace-event "usdt:/usr/bin/qemu-system-x86_64:qemu:v9fs_create"
````
