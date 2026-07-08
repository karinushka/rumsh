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

def main():
    parser = argparse.ArgumentParser(description="Rumsh Lossy Interactive Keystroke Integration Test")
    parser.add_argument("--delay", type=float, default=0.5, help="Max random delay in seconds (default: 0.5s)")
    parser.add_argument("--loss", type=float, default=10.0, help="Percentage of packets to drop (default: 10.0%)")
    args = parser.parse_args()

    server_port = 46501
    proxy_port = 46500
    
    server_log = "target/server_lossy.log"
    client_log = "target/client_lossy.log"
    
    cols = 80
    rows = 24
    
    os.makedirs("target", exist_ok=True)
    for log in [server_log, client_log]:
        if os.path.exists(log):
            os.remove(log)
            
    try:
        lib_path = find_lib_path()
    except Exception as e:
        print(e)
        sys.exit(1)
        
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = lib_path
    env["RUST_LOG"] = "debug"  # Enable debug logging to capture [ECHO] and [ARQ] traces!
    
    # 1. Start UDP Proxy
    print(f"Spawning UDP Proxy: listening on {proxy_port}, forwarding to {server_port}")
    print(f"  Network Profile: Max Delay = {args.delay:.3f}s | Packet Loss = {args.loss:.1f}%")
    proxy = UdpProxy(proxy_port, server_port, args.loss, args.delay)
    proxy.start()

    # 2. Spawn Server
    print("Spawning Server...")
    server_proc = None
    try:
        server_log_file = open(server_log, "w")
        server_proc = subprocess.Popen(
            ["target/release/rumsh", "server", "--port", str(server_port), "--no-daemonize", "--bind-any", "--shell", "/bin/bash -i"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=server_log_file,
            text=True
        )
    except Exception as e:
        print(f"Failed to spawn server: {e}")
        proxy.stop()
        sys.exit(1)
        
    key = None
    print("Waiting for Server bootstrap...")
    for line in server_proc.stdout:
        m = re.match(r"RUMSH_KEY=(?P<key>[0-9a-f]{64})", line.strip())
        if m:
            key = m.group("key")
            break
            
    if not key:
        print("Error: Failed to retrieve RUMSH_KEY from server stdout!")
        server_proc.terminate()
        proxy.stop()
        sys.exit(1)
        
    # 3. Spawn Client with PTY
    print(f"Spawning Client with terminal size {cols}x{rows}...")
    client_proc = None
    master_fd = None
    try:
        master_fd, slave_fd = pty.openpty()
        set_pty_size(master_fd, rows, cols)
        
        client_proc = subprocess.Popen(
            ["target/release/rumsh", f"127.0.0.1:{proxy_port}", "--key", key, "-o"],
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True
        )
        os.close(slave_fd)
    except Exception as e:
        print(f"Failed to spawn client: {e}")
        server_proc.terminate()
        proxy.stop()
        sys.exit(1)
        
    drain_thread = threading.Thread(target=drain_fd, args=(master_fd, client_log))
    drain_thread.daemon = True
    drain_thread.start()
    
    print("Waiting for handshake to succeed...")
    handshake_success = False
    start_wait = time.time()
    while time.time() - start_wait < 15.0:
        if os.path.exists(client_log):
            with open(client_log, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if "Handshake successful" in content:
                    handshake_success = True
                    break
        time.sleep(0.1)

    if not handshake_success:
        print("Error: Handshake did not succeed within 15 seconds! Aborting.")
        client_proc.terminate()
        server_proc.terminate()
        proxy.stop()
        sys.exit(1)

    print("Handshake succeeded! Waiting 1s for PTY raw mode to settle...")
    time.sleep(1.0)
    
    # 4. Type 'echo 12345\n' slowly (simulate typing speed: 200ms per character)
    input_str = "echo 12345\n"
    print(f"Simulating manual typing: '{input_str.strip()}'...")
    for char in input_str:
        os.write(master_fd, char.encode())
        time.sleep(0.200) # 200ms delay between keys
        
    print("Waiting 2 seconds...")
    time.sleep(2)
    
    print("Sending 'exit' to close shell...")
    os.write(master_fd, b"exit\n")
    
    print("Waiting 5 seconds for network to settle and retransmissions to finish...")
    time.sleep(5)
    
    # 5. Cleanup
    print("Cleaning up processes...")
    if client_proc.poll() is None:
        client_proc.terminate()
        client_proc.wait()
    if server_proc.poll() is None:
        server_proc.terminate()
        server_proc.wait()
    proxy.stop()
    
    # 6. Analyze client log
    print("\n==================================================")
    print("ANALYZING CLIENT LOG FOR LOCAL ECHO & ARQ TRACES:")
    print("==================================================")
    if os.path.exists(client_log):
        with open(client_log, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # Filter for [ECHO], [ARQ], and connection results
                if "[ECHO]" in line or "[ARQ]" in line or "Handshake" in line or "Decryption error" in line:
                    print(line.strip())
    else:
        print("Error: Client log not found!")
    print("==================================================")

if __name__ == "__main__":
    main()
