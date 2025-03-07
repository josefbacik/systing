# Systing

To build, ensure you have installed bpftool. This only builds on linux.

This currently is a playground tool for me to figure out what set of tools I
need in order to debug large scale applications.  There's half done things, bad
habits, half done tools.  Currently the `system` sub command is where most of my
development efforts are focused.

## TODO FOR SYSTEM
- [X] Separate the stack traces out into their own NUMA node bound ringbufs.
- [X] Add an option to disable the stack traces.
- [ ] Build a `perfetto` plugin to replicate the `runqueue` and `wake latency`
  tracks, then remove those tracks to slim down the trace file size.
- [ ] Figure out something better to do about cgroup and PID based tracing so it
  doesn't leave ghost tasks.
- [ ] Add IRQ events.
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

## System

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
systing system --trace-event-pid <PID of qemu> --trace-event "usdt:/usr/bin/qemu-system-x86_64:qemu:v9fs_create"
````

## Profile

This tool can trace a cgroup, a process and it's threads, or just the whole
system to generate a view of the time spent by the process.  This is useful for
determining where you should focus performance investigations.  It measures
actual real time spent by the application waiting for events to happen (network
traffic, polling, futexes, etc), time spent waiting on IO, time spent waiting to
get on the CPU, how much time is spent being interrupted by IRQs, and how much
time is being spent being kicked off the CPU by other processes.

To run this tool you can use it the following ways

```
target/debug/systing profile -c <path to cgroup>
target/debug/systing profile -p <pid>
target/debug/systing profile
```

You can also specify a duration to record

```
target/debug/systing profile -c <path to cgroup> -d 10
```

If you have a long running process you can compare slices of runs by specifying
an interval

```
target/debug/systing profile -c <path to cgroup> -d 10 -i 5
```

This will collect 10 seconds of data, 5 times, and group the output by the
collection periods.  There are several options for outputs

- `--aggregate` - This will aggregate the collection of the data into a single
  entry per TGID.  This is useful for large applications that have many threads.
- `--summary` - This will output a summary of the data collected.  This is
  useful for quick overviews of the data.
- `--tui` - This will output the data in a TUI format.  This is useful for
  interactive exploration of the data.

## Describe

This tool can be used to figure out what a process and it's threads are doing in
relation to each other and their usage pattern.  It tracks kernel and userspace
stack traces of wakers and wakees, and tracks the time spent asleep for each
operation.  This is useful for determining what exactly the process is doing and
what resources each thread depends on for their operation.  It is also helpful
to determine dependency chains between the different threads.
