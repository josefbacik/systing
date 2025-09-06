#!/usr/bin/env python3

import sys
from collections import defaultdict

def parse_packets(filename):
    """Parse packets from file and calculate size distribution by packet type."""
    packet_sizes = defaultdict(int)
    total_size = 0
    
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for start of packet
        if line == "packet {":
            packet_start = i
            packet_type = None
            brace_count = 1
            i += 1
            
            # Find the packet type and count lines until packet ends
            ftrace_subtype = None
            while i < len(lines) and brace_count > 0:
                line = lines[i].strip()
                
                # Track braces to know when packet ends
                if '{' in line:
                    brace_count += line.count('{')
                    # Check if this line defines a packet type
                    if packet_type is None and '{' in line:
                        # Extract the type name (word before the {)
                        parts = line.split('{')[0].strip().split()
                        if parts and parts[-1] not in ['packet']:
                            packet_type = parts[-1]
                    # If we found ftrace_events, look for subtypes
                    elif packet_type == "ftrace_events" and ftrace_subtype is None and '{' in line:
                        parts = line.split('{')[0].strip().split()
                        if parts and parts[-1] not in ['ftrace_events']:
                            ftrace_subtype = parts[-1]
                
                if '}' in line:
                    brace_count -= line.count('}')
                
                i += 1
            
            # Calculate packet size (number of lines including packet { and })
            packet_end = i
            packet_size = packet_end - packet_start
            
            # If no specific type found, categorize as "unknown"
            if packet_type is None:
                packet_type = "unknown"
            
            # Use ftrace subtype if available
            if packet_type == "ftrace_events" and ftrace_subtype is not None:
                final_type = f"ftrace_events.{ftrace_subtype}"
            else:
                final_type = packet_type
            
            packet_sizes[final_type] += packet_size
            total_size += packet_size
        else:
            i += 1
    
    return packet_sizes, total_size

def print_distribution(packet_sizes, total_size):
    """Print the distribution of packet types and their percentages."""
    print(f"\nPacket Type Distribution Analysis")
    print("=" * 50)
    print(f"Total trace size (lines): {total_size:,}")
    print()
    
    # Sort by size (descending)
    sorted_packets = sorted(packet_sizes.items(), key=lambda x: x[1], reverse=True)
    
    print(f"{'Packet Type':<20} {'Size (lines)':<15} {'Percentage':<10} {'Bar'}")
    print("-" * 60)
    
    for packet_type, size in sorted_packets:
        percentage = (size / total_size) * 100 if total_size > 0 else 0
        bar_length = int(percentage / 2)  # Scale bar to max 50 chars
        bar = '█' * bar_length
        print(f"{packet_type:<20} {size:<15,} {percentage:>6.2f}%    {bar}")
    
    print()
    print(f"Total packet types found: {len(packet_sizes)}")

if __name__ == "__main__":
    filename = sys.argv[1] if len(sys.argv) > 1 else "blah.txt"
    
    try:
        packet_sizes, total_size = parse_packets(filename)
        print_distribution(packet_sizes, total_size)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)