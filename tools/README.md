# Perfetto Trace Analysis Tools

This directory contains tools for analyzing Perfetto trace files.

## analyze_packets.py

A Python script that analyzes the size distribution of packets in a Perfetto trace file converted to text format.

### Prerequisites

1. **Perfetto traceconv tool**: You need to have the `traceconv` tool from Perfetto installed.
   - Installation and usage documentation: https://perfetto.dev/docs/quickstart/traceconv

### Usage

1. **Convert your Perfetto trace to text format**:
   ```bash
   traceconv text trace.pb blah.txt
   ```
   - `trace.pb` is your generated Perfetto trace file
   - `blah.txt` is the output text file

2. **Run the packet analysis**:
   ```bash
   python3 analyze_packets.py blah.txt
   ```

### What it does

The script analyzes the converted Perfetto trace file and provides:

- **Size distribution**: Shows how much space each packet type takes up in the trace
- **Percentage breakdown**: Displays what percentage of the total trace each packet type represents
- **Visual bar chart**: Provides a visual representation of the distribution
- **Summary statistics**: Total trace size and number of packet types found

### Example Output

```
Packet Type Distribution Analysis
==================================================
Total trace size (lines): 125,432

Packet Type          Size (lines)    Percentage  Bar
------------------------------------------------------------
ftrace_events.sched  45,231          36.06%      ██████████████████
ftrace_events.block  32,145          25.62%      ████████████▌
process_tree         18,765          14.95%      ███████▌
track_event          15,432          12.31%      ██████▎
clock_sync           8,945           7.13%       ███▌
system_info          4,914           3.92%       ██

Total packet types found: 6
```

### Supported Packet Types

The script automatically detects various Perfetto packet types including:
- `ftrace_events` (with subtypes like `sched`, `block`, etc.)
- `process_tree`
- `track_event`
- `clock_sync`
- `system_info`
- And others (categorized as their detected type or "unknown" if unrecognizable)

### Error Handling

The script will display helpful error messages if:
- The input file is not found
- The file cannot be processed
- No command line argument is provided (defaults to "blah.txt")