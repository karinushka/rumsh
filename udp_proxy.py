#!/usr/bin/env python3
import socket
import threading
import random
import argparse
import sys
import time
import os
import glob
import subprocess
import re

class UdpProxy:
    def __init__(self, proxy_port, server_port, loss_pct, max_delay_sec):
        self.proxy_port = proxy_port
        self.server_port = server_port
        self.loss_pct = loss_pct
        self.max_delay_sec = max_delay_sec
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", proxy_port))
        self.client_addr = None
        self.server_addr = ("127.0.0.1", server_port)
        self.stop_event = threading.Event()
        self.thread = None
        
    def start(self):
        self.thread = threading.Thread(target=self._run)
        self.thread.daemon = True
        self.thread.start()
        
    def stop(self):
        if self.thread is None:
            return
        self.stop_event.set()
        # Send a dummy packet to ourselves to wake up recvfrom
        dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            dummy_sock.sendto(b"WAKEUP", ("127.0.0.1", self.proxy_port))
        except Exception:
            pass
        self.thread.join()
        self.sock.close()
        
    def _forward(self, data, target):
        try:
            self.sock.sendto(data, target)
        except Exception:
            pass
            
    def _run(self):
        self.sock.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                data, src = self.sock.recvfrom(65535)
                if not data or data == b"WAKEUP":
                    continue
                    
                # Identify sender
                is_from_server = (src == self.server_addr)
                
                if not is_from_server:
                    self.client_addr = src
                    target = self.server_addr
                else:
                    target = self.client_addr
                    
                if target is None:
                    continue
                    
                # 1. Simulate packet loss
                if self.loss_pct > 0.0 and random.random() * 100.0 < self.loss_pct:
                    # Packet dropped!
                    continue
                    
                # 2. Simulate latency / jitter (uniform random delay from 0 to max_delay)
                if self.max_delay_sec > 0.0:
                    delay = random.uniform(0.0, self.max_delay_sec)
                    threading.Timer(delay, self._forward, args=(data, target)).start()
                else:
                    self._forward(data, target)
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    print(f"Proxy error: {e}")

def find_binary_and_lib():
    """
    Search for rumsh binary and libghostty-vt library path.
    Prefers release build, falls back to debug build.
    Returns (binary_path, lib_path).
    """
    # 1. Check Release Build
    release_bin = "target/release/rumsh"
    release_libs = glob.glob("target/release/build/libghostty-vt-sys-*/out/ghostty-install/lib")
    if os.path.exists(release_bin) and release_libs:
        return release_bin, os.path.abspath(release_libs[0])

    # 2. Check Debug Build
    debug_bin = "target/debug/rumsh"
    debug_libs = glob.glob("target/debug/build/libghostty-vt-sys-*/out/ghostty-install/lib")
    if os.path.exists(debug_bin) and debug_libs:
        print("Note: Release build not found. Falling back to DEBUG build.")
        return debug_bin, os.path.abspath(debug_libs[0])

    raise Exception(
        "Rosh binaries not found in target/release or target/debug.\n"
        "Please run 'cargo build' or 'cargo build --release' first."
    )

def main():
    parser = argparse.ArgumentParser(description="UDP Loss/Latency Proxy and Connection Playground")
    parser.add_argument("--proxy-port", type=int, default=46500, help="Port to listen on for client packets")
    parser.add_argument("--server-port", type=int, default=46501, help="Port where the server will run")
    parser.add_argument("--delay", type=float, default=0.0, help="Max random delay in seconds (jitter)")
    parser.add_argument("--loss", type=float, default=0.0, help="Percentage of packets to drop (0 to 100)")
    parser.add_argument("--no-server", action="store_true", help="Do not spawn the rumsh server automatically")
    parser.add_argument("--shell", type=str, default="/bin/bash -i", help="Shell to run on the server")
    args = parser.parse_args()

    server_proc = None
    proxy = None

    try:
        # 1. Resolve binaries and environment if we need to spawn the server
        if not args.no_server:
            try:
                bin_path, lib_path = find_binary_and_lib()
            except Exception as e:
                print(f"Error: {e}")
                sys.exit(1)

            env = os.environ.copy()
            env["LD_LIBRARY_PATH"] = lib_path
            env["RUST_LOG"] = "info"

            print(f"Spawning Rumsh Server ({bin_path})...")
            server_proc = subprocess.Popen(
                [bin_path, "server", "--bind", "127.0.0.1", "--port", str(args.server_port), "--no-daemonize", "--shell", args.shell],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, # Suppress server logs in interactive console
                text=True
            )

            # Wait for server key output
            key = None
            for line in server_proc.stdout:
                m = re.match(r"RUMSH_KEY=(?P<key>[0-9a-f]{64})", line.strip())
                if m:
                    key = m.group("key")
                    break

            if not key:
                print("Error: Failed to retrieve RUMSH_KEY from server!")
                server_proc.terminate()
                sys.exit(1)

        # 2. Start UDP Proxy
        print(f"Starting UDP Proxy: listening on 127.0.0.1:{args.proxy_port}, forwarding to 127.0.0.1:{args.server_port}")
        print(f"  Profile: Max Delay = {args.delay:.3f}s | Packet Loss = {args.loss:.1f}%")
        proxy = UdpProxy(args.proxy_port, args.server_port, args.loss, args.delay)
        proxy.start()

        # 3. Present Connection Command
        print("\n" + "="*80)
        print(" RUMSH NETWORK EMULATION PLAYGROUND IS ACTIVE!")
        print("="*80)
        if not args.no_server:
            print(f"A rumsh server was automatically spawned and attached to the proxy.")
            print(f"To connect to the server through the lossy proxy, run this command in another terminal:\n")
            print(f"  \033[1;32m{bin_path} 127.0.0.1:{args.proxy_port} --key {key} -o\033[0m\n")
        else:
            print(f"Proxy is running. Please start your server manually listening on port {args.server_port}.")
            print(f"Then connect your client to port {args.proxy_port}.")
        print("="*80)
        print("Press Ctrl+C to terminate the playground...")

        # 4. Wait for interrupt
        while True:
            time.sleep(1)
            if server_proc and server_proc.poll() is not None:
                print("\nServer exited unexpectedly.")
                break

    except KeyboardInterrupt:
        print("\nShutting down playground...")
    finally:
        if server_proc and server_proc.poll() is None:
            server_proc.terminate()
            server_proc.wait()
        if proxy:
            proxy.stop()
        print("Playground stopped. Goodbye!")

if __name__ == "__main__":
    main()
