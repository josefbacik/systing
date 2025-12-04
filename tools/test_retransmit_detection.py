#!/usr/bin/env python3
"""
Test script to trigger TCP retransmits for testing systing's retransmit detection.

This script creates backpressure by having a server stop calling recv() while
the client continues sending. This causes the server's receive window to close,
the client's send buffer to fill, and eventually triggers retransmits when ACKs
are delayed or lost due to window pressure.

Usage:
    # Terminal 1 - Start tracing:
    sudo ./target/release/systing -p $(pgrep -f test_retransmit) -o retransmit_test.pb.gz --network

    # Terminal 2 - Run server:
    python3 tools/test_retransmit_detection.py server

    # Terminal 3 - Run client:
    python3 tools/test_retransmit_detection.py client

    # Wait 30-60 seconds for retransmits to occur
    # Stop tracing (Ctrl+C)

    # Analyze:
    ./target/release/systing-analyze retransmit_test.pb.gz -o test_retransmit.duckdb

    # Query for retransmits:
    duckdb test_retransmit.duckdb -c "SELECT COUNT(*) FROM args WHERE key = 'is_retransmit' AND int_value = 1"
"""

import socket
import sys
import time
import argparse


def run_server(port: int = 9999, pause_duration: int = 60):
    """Run the server that creates backpressure by pausing recv()."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Use a small receive buffer to speed up window closure
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)

    server.bind(('0.0.0.0', port))
    server.listen(1)

    print(f"[Server] Listening on port {port}...")
    print(f"[Server] PID: {__import__('os').getpid()}")

    conn, addr = server.accept()
    print(f"[Server] Connection from {addr}")

    # Set small receive buffer on accepted connection too
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)

    # Read a little bit to establish the connection
    initial_data = conn.recv(4096)
    print(f"[Server] Received {len(initial_data)} bytes initially")

    # Now stop reading to create backpressure
    print(f"[Server] Pausing recv() for {pause_duration} seconds to create backpressure...")
    print("[Server] This will cause the client's send buffer to fill and trigger retransmits")
    time.sleep(pause_duration)

    # Drain remaining data
    print("[Server] Resuming recv()...")
    total = len(initial_data)
    conn.setblocking(False)
    try:
        while True:
            try:
                data = conn.recv(65536)
                if not data:
                    break
                total += len(data)
            except BlockingIOError:
                break
    except Exception as e:
        print(f"[Server] Error: {e}")

    print(f"[Server] Total received: {total} bytes")
    conn.close()
    server.close()
    print("[Server] Done")


def run_client(host: str = '127.0.0.1', port: int = 9999, duration: int = 60):
    """Run the client that sends data continuously."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Use a moderate send buffer
    client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)

    print(f"[Client] Connecting to {host}:{port}...")
    print(f"[Client] PID: {__import__('os').getpid()}")
    client.connect((host, port))
    print("[Client] Connected")

    # Make socket non-blocking to detect when send buffer is full
    client.setblocking(False)

    # Create a chunk of data to send
    chunk = b'X' * 8192
    total_sent = 0
    blocked_count = 0
    start_time = time.time()

    print(f"[Client] Sending data for {duration} seconds...")
    print("[Client] Send buffer will fill up, triggering kernel retransmits")

    while time.time() - start_time < duration:
        try:
            sent = client.send(chunk)
            total_sent += sent
            blocked_count = 0  # Reset on successful send
        except BlockingIOError:
            blocked_count += 1
            if blocked_count == 1:
                elapsed = time.time() - start_time
                print(f"[Client] Send buffer full at {elapsed:.1f}s ({total_sent} bytes sent)")
            # Small sleep to avoid busy-waiting
            time.sleep(0.1)
        except BrokenPipeError:
            print("[Client] Connection closed by server")
            break

    elapsed = time.time() - start_time
    print(f"[Client] Sent {total_sent} bytes in {elapsed:.1f} seconds")

    # Check retransmit stats
    try:
        import subprocess
        result = subprocess.run(['ss', '-ti'], capture_output=True, text=True)
        print("\n[Client] TCP connection stats (look for 'retrans' and 'reordering'):")
        for line in result.stdout.split('\n'):
            if 'retrans' in line.lower() or str(port) in line:
                print(f"  {line}")
    except Exception as e:
        print(f"[Client] Could not get TCP stats: {e}")

    client.close()
    print("[Client] Done")


def main():
    parser = argparse.ArgumentParser(description='TCP retransmit test for systing')
    parser.add_argument('role', choices=['server', 'client'], help='Run as server or client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (client only)')
    parser.add_argument('--port', type=int, default=9999, help='Port to use')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')

    args = parser.parse_args()

    if args.role == 'server':
        run_server(port=args.port, pause_duration=args.duration)
    else:
        run_client(host=args.host, port=args.port, duration=args.duration)


if __name__ == '__main__':
    main()
