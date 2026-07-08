#!/usr/bin/env python3
import os
import sys
import glob
import time
import subprocess
import re
import pty
import threading
import fcntl
import termios
import struct
import argparse
from udp_proxy import UdpProxy

def find_lib_path():
    libs = glob.glob("target/release/build/libghostty-vt-sys-*/out/ghostty-install/lib")
    if not libs:
        raise Exception("libghostty-vt not found in target/release/build/. Please run 'cargo build --release' first.")
    return os.path.abspath(libs[0])

def get_cpu_usage(pid):
    try:
        out = subprocess.check_output(["ps", "-p", str(pid), "-o", "%cpu"])
        lines = out.decode().strip().split("\n")
        if len(lines) >= 2:
            return float(lines[1].strip())
    except Exception as e:
        print(f"Error getting CPU for PID {pid}: {e}")
    return 0.0

def set_pty_size(fd, rows, cols):
    size = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, size)

def drain_fd(fd, log_file):
    try:
        with open(log_file, "wb") as f:
            while True:
                data = os.read(fd, 4096)
                if not data:
                    break
                f.write(data)
                f.flush()
    except Exception:
        pass

def feed_inputs(fd, stop_event, interval):
    try:
        while not stop_event.is_set():
            os.write(fd, b" ")
            time.sleep(interval)
    except Exception as e:
        print(f"Error feeding inputs: {e}")

def extract_overlay_metrics(client_log_path):
    if not os.path.exists(client_log_path):
        return None
        
    # Regex to match: [ 12ms |  0.0% |   4.2KB/s |  1.0x | 60fps]
    pattern = re.compile(
        r"\[\s*(\d+)ms\s*\|\s*([\d.]+)%\s*\|\s*([\d.]+)KB/s\s*\|\s*([\d.]+)x\s*\|\s*(\d+)fps\]"
    )
    
    metrics_readings = []
    try:
        with open(client_log_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for m in pattern.finditer(content):
                rtt = int(m.group(1))
                loss = float(m.group(2))
                kb_s = float(m.group(3))
                ratio = float(m.group(4))
                fps = int(m.group(5))
                metrics_readings.append((rtt, loss, kb_s, ratio, fps))
    except Exception as e:
        print(f"Error reading client log for metrics: {e}")
        
    return metrics_readings

def main():
    parser = argparse.ArgumentParser(description="Rumsh CPU and Network Degradation Stress Test")
    parser.add_argument("--delay", type=float, default=0.0, help="Max random delay in seconds (jitter) between 0 and this value")
    parser.add_argument("--loss", type=float, default=0.0, help="Percentage of packets to drop (0 to 100)")
    parser.add_argument("--rate", type=float, default=20.0, help="Keystroke feeding rate in Hz (default: 20)")
    parser.add_argument("-m", "--manual", action="store_true", help="Run in manual interactive mode (starts server and proxy, waits for manual client connection)")
    args = parser.parse_args()

    server_port = 46501
    proxy_port = 46500
    
    use_proxy = (args.delay > 0.0 or args.loss > 0.0)
    if use_proxy:
        connect_port = proxy_port
        bind_server_port = server_port
    else:
        connect_port = proxy_port
        bind_server_port = proxy_port
    
    server_log = "target/server_python.log"
    client_log = "target/client_python.log"
    
    cols = 80
    rows = 24
    
    os.makedirs("target", exist_ok=True)
    for log in [server_log, client_log]:
        if os.path.exists(log):
            os.remove(log)
            
    try:
        lib_path = find_lib_path()
        print(f"Using libghostty-vt path (RELEASE): {lib_path}")
    except Exception as e:
        print(e)
        sys.exit(1)
        
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = lib_path
    env["RUST_LOG"] = "trace"
    
    # 1. Start UDP Proxy if requested
    proxy = None
    if use_proxy:
        print(f"Spawning UDP Proxy: listening on {proxy_port}, forwarding to {server_port}")
        print(f"  Network Profile: Max Delay = {args.delay:.3f}s (Jitter 0-{args.delay:.3f}s) | Packet Loss = {args.loss:.1f}%")
        proxy = UdpProxy(proxy_port, server_port, args.loss, args.delay)
        proxy.start()
    else:
        print(f"Connecting directly to server on port {bind_server_port} (no network degradation)")

    # 2. Spawn Server
    print("Spawning Server (RELEASE)...")
    server_proc = None
    try:
        server_log_file = open(server_log, "w")
        server_proc = subprocess.Popen(
            ["target/release/rumsh", "server", "--port", str(bind_server_port), "--no-daemonize", "--bind-any", "--shell", "/bin/bash -i"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=server_log_file,
            text=True
        )
    except Exception as e:
        print(f"Failed to spawn server: {e}")
        if proxy:
            proxy.stop()
        sys.exit(1)
        
    key = None
    print("Waiting for Server bootstrap...")
    for line in server_proc.stdout:
        print(f"Server: {line.strip()}")
        m = re.match(r"RUMSH_KEY=(?P<key>[0-9a-f]{64})", line.strip())
        if m:
            key = m.group("key")
            break
            
    if not key:
        print("Error: Failed to retrieve RUMSH_KEY from server stdout!")
        if server_proc:
            server_proc.terminate()
        if proxy:
            proxy.stop()
        sys.exit(1)
        
    print(f"Retrieved RUMSH_KEY: {key}")

    if args.manual:
        print("\n======================================================================")
        print("INTERACTIVE NETWORK EMULATION PLAYGROUND ACTIVE!")
        print("======================================================================")
        print(f"Network Profile:")
        if use_proxy:
            print(f"  - Max Delay (Jitter): 0.0 to {args.delay:.3f} seconds")
            print(f"  - Packet Loss: {args.loss:.1f}%")
        else:
            print(f"  - Direct loopback (no latency or packet loss)")
        print(f"\nTo connect to this server, open another terminal and run:")
        print(f"  target/release/rumsh client 127.0.0.1:{connect_port} {key} -o")
        print("======================================================================")
        print("Press Ctrl+C to terminate the server and proxy...")
        
        try:
            while True:
                time.sleep(1)
                if server_proc.poll() is not None:
                    print("Server exited unexpectedly.")
                    break
        except KeyboardInterrupt:
            print("\nShutting down interactive playground...")
        finally:
            if server_proc.poll() is None:
                server_proc.terminate()
                server_proc.wait()
            if proxy:
                proxy.stop()
            print("Playground stopped. Goodbye!")
            sys.exit(0)

    # 3. Spawn Client with PTY (enable overlay flag '-o')
    print(f"Spawning Client with terminal size {cols}x{rows} (overlay active)...")
    client_proc = None
    master_fd = None
    try:
        master_fd, slave_fd = pty.openpty()
        set_pty_size(master_fd, rows, cols)
        
        # Pass '-o' to enable debugging overlay!
        client_proc = subprocess.Popen(
            ["target/release/rumsh", f"127.0.0.1:{connect_port}", "--key", key, "-o"],
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True
        )
        os.close(slave_fd)
    except Exception as e:
        print(f"Failed to spawn client: {e}")
        if server_proc:
            server_proc.terminate()
        if proxy:
            proxy.stop()
        sys.exit(1)
        
    drain_thread = threading.Thread(target=drain_fd, args=(master_fd, client_log))
    drain_thread.daemon = True
    drain_thread.start()
    
    print("Client spawned. Waiting for connection...")
    time.sleep(2)
    
    if server_proc.poll() is not None:
        print("Error: Server exited prematurely!")
        if proxy:
            proxy.stop()
        sys.exit(1)
        
    # 4. Send 'top -d 5' command
    print("Sending 'top -d 5' command to client...")
    os.write(master_fd, b"top -d 5\n")
    time.sleep(1)
    
    # 5. Start feeding space characters
    feed_interval = 1.0 / args.rate
    print(f"Starting space character feed at {args.rate}Hz (every {feed_interval*1000:.1f}ms) to force redraws...")
    stop_feed = threading.Event()
    feed_thread = threading.Thread(target=feed_inputs, args=(master_fd, stop_feed, feed_interval))
    feed_thread.start()
    
    # 6. Monitor Server CPU
    print("Monitoring Server CPU usage under stress...")
    cpu_readings = []
    for i in range(10):
        time.sleep(1)
        cpu = get_cpu_usage(server_proc.pid)
        cpu_readings.append(cpu)
        print(f"  Sec {i+1}: Server CPU = {cpu}%")
        
    avg_cpu = sum(cpu_readings) / len(cpu_readings)
    print(f"Average Server CPU usage under stress: {avg_cpu:.1f}%")
    
    # 7. Cleanup
    print("Stopping space feed...")
    stop_feed.set()
    feed_thread.join()
    
    print("Sending 'q' to exit 'top'...")
    os.write(master_fd, b"q")
    time.sleep(1)
    
    print("Sending 'exit' to close shell...")
    os.write(master_fd, b"exit\n")
    time.sleep(1)
    
    print("Cleaning up processes...")
    if client_proc.poll() is None:
        client_proc.terminate()
        client_proc.wait()
        
    if server_proc.poll() is None:
        server_proc.terminate()
        server_proc.wait()
        
    if proxy:
        print("Stopping UDP Proxy...")
        proxy.stop()
        
    print("Test completed successfully!")
    
    # 8. Analyze and print overlay metrics from client log
    print("\n==================================================")
    print("ANALYZING CLIENT OVERLAY METRICS FROM LOG:")
    readings = extract_overlay_metrics(client_log)
    if readings:
        print(f"Total overlay frame updates recorded: {len(readings)}")
        # Print a few readings from the middle/end of the test
        sample_size = min(5, len(readings))
        print(f"Sample readings (last {sample_size} frames):")
        for rtt, loss, kb_s, ratio, fps in readings[-sample_size:]:
            print(f"  RTT: {rtt:3}ms | Loss: {loss:4.1f}% | Bandwidth: {kb_s:5.1f}KB/s | Compress: {ratio:4.1f}x | Render: {fps:2}fps")
    else:
        print("No overlay metrics found in client log. Did it render correctly?")
    print("==================================================")

if __name__ == "__main__":
    main()
