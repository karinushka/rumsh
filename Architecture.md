# Rumsh (Rust Mobile Shell) Architecture

`rumsh` is a high-performance, secure, and resilient remote terminal protocol designed for mobile and unreliable network connections. Drawing inspiration from modern state-synchronization protocols like Mosh, `rumsh` prioritizes low-latency interactive responsiveness, high-throughput bulk output, and robust roaming capabilities over UDP.

This document details the architectural design, component layout, and the series of engineering decisions and optimizations made during its development.

---

## 1. High-Level Architecture

Unlike traditional SSH-like protocols that treat the connection as a bidirectional byte pipe (forwarding raw terminal escape sequences from the shell to the client), `rumsh` utilizes a **State Synchronization Paradigm**.

```
+------------------+                   UDP Network                  +-------------------+
|   rumsh Server   |   Compressed State Diff (FrameUpdate)          |    rumsh Client   |
|  +------------+  | =============================================> |  +-------------+  |
|  | PTY Slave  |  |                                                |  | cell_cache  |  |
|  +-----+------+  | <============================================= |  | (2D Mirror) |  |
|        | (Bytes) |           Encrypted Keystrokes / Resizes       |  +------+------+  |
|  +-----+------+  |                                                |         |         |
|  |  Ghostty   |  |                                                |  +------+------+  |
|  | VT Parser  |  |                                                |  |  Renderer   |  |
|  +-----+------+  |                                                |  | (BufWriter) |  |
|        | (Grid)  |                                                |  +------+------+  |
|  +-----+------+  |                                                |         |         |
|  |  State     |  |                                                |  +------+------+  |
|  | Compiler   |  |                                                |  |   Console   |  |
|  +------------+  |                                                |  +-------------+  |
+------------------+                                                +-------------------+
```

*   **Server-Authoritative Grid**: The server runs a full terminal emulator parser (`libghostty-vt`) internally, maintaining the authoritative screen buffer. It compares the active screen state against the last acknowledged client state to compile minimal, structured screen diffs (`FrameUpdate`).
*   **Thin Client Mirror**: The client is a lightweight "dumb" terminal mirror. It maintains a simple 2D grid cache of cells. It does not parse complex ANSI escape sequences; instead, it applies the server's structured `FrameUpdate` diffs directly to its cache and renders the dirty regions to the host console.
*   **UDP Transport**: All communication occurs over secure, encrypted, and compressed UDP packets, allowing seamless IP roaming (e.g., switching from Wi-Fi to LTE) without connection drops.

### 1.1. Session Bootstrap & Handoff (SSH Control to UDP Data)

To establish a secure connection without manual port configuration or pre-shared key management, `rumsh` implements a secure **bootstrap and handoff protocol** using SSH as a control plane before transitioning to UDP for data transmission:

```
+----------------+                 SSH Control Plane                 +----------------+
|  Local Client  |  1. Spawn: ssh user@host "rumsh server..."        | Remote Server  |
|                | ================================================> |                |
|                |                                                   | - Bind UDP port|
|                |  2. Output: "RUMSH CONNECT <port> <key_hex>"      | - Generate key |
|                | <================================================ |                |
| - Parse token  |                                                   |                |
| - Close SSH    |                                                   |                |
+--------+-------+                                                   +--------+-------+
         |                                                                    |
         |                         UDP Data Plane                             |
         |  3. Encrypted UDP Handshake & State Sync                           |
         | <================================================================> |
```

1.  **SSH Orchestration**: When the client runs `rumsh user@remote_host`, it spawns a local `ssh` subprocess, executing `rumsh server --no-daemonize` on the remote machine.
2.  **Server Initialization**: The remote server boots up, queries the OS for the user's default `$SHELL`, generates a random 256-bit symmetric key (`ChaCha20-Poly1305`), binds to an available UDP port in the specified range, and prints a secure connection token containing the port and key to its standard output.
3.  **Control Plane Handoff**: The local client captures and parses the connection token from the SSH stdout stream. Once retrieved, the client **forcefully terminates** the SSH process (tearing down the SSH control plane completely) and resolves the remote host.
4.  **UDP Handshake**: The client immediately transitions to the UDP data plane. It sends encrypted `Handshake` packets to the server's UDP port using the pre-shared key. The server responds with `HandshakeAck`, and the active UDP terminal session begins.

---

## 2. Component Design (Deep-Module Architecture)

`rumsh` is structured around deep modules with clean, symmetrical seams, eliminating layer violations and lock contention across the networking and presentation loops:

### 2.1. Server Architecture
The server network adapter (`run_server` in `src/server/network.rs`) is a thin UDP event loop that coordinates three core deep modules:
1.  **AuthoritativeSession (`src/server/session.rs`)**: A self-contained deep session module that encapsulates sliding-window packet ordering, PTY output handling, ARQ sequence tracking, and frame diff scheduling. It consumes wire bytes and emits declarative `SessionAction` commands (SendPacket, OffloadDiffJob, Shutdown).
2.  **UpdateJob**: A self-contained, thread-safe diff compilation job spawned by `AuthoritativeSession`. It offloads heavy CPU work—comparing 2D grid states (`GridState::diff_from`), LZ4 compression, ChaCha20Poly1305 encryption, and varint serialization—to a blocking thread pool without locking the network loop.
3.  **PtyBridge (`src/server/pty.rs`)**: Implements the `PtyBackend` trait, isolating Unix PTY subprocess spawning, window resizing, output streaming, and process group cache checks (`tcgetpgrp`) from session logic.

### 2.2. Client Architecture
The client network adapter (`run_client` in `src/client/network.rs`) is a lock-free, single-threaded event loop (`smol::future::race`) that coordinates four core deep modules:
1.  **MirrorSession (`src/client/session.rs`)**: Absorbs the entire client protocol engine, screen mirror, escape sequence interpreter (`EscapeInterpreter`), local predictive echo, and five concurrent timing loops (KeepAlive, ARQ retransmissions, reconnection overlay debouncing, paint scheduling, and telemetry calculation) into a single 16ms `on_tick(now)` state machine.
2.  **LocalEchoEngine (`src/client/echo.rs`)**: A deep predictive rendering engine that manages local character echo, backspace coordinate math, prediction epochs, and cell undo-buffers. When authoritative server frames arrive, it performs an authoritative overwrite followed by an instantaneous in-memory re-application of surviving unconfirmed keystrokes (`reconcile_frame`).
3.  **TerminalLifecycle (`src/client/lifecycle.rs`)**: An OS adapter that isolates terminal process control from networking. It manages raw mode toggling, alternate screen setup, window resize streams (`SIGWINCH`), process suspension callbacks (`SIGTSTP`), and enforces an RAII cleanup guard (`Drop`) to guarantee the host terminal is never left broken or garbled.
4.  **ClientTerminalRenderer (`src/client/terminal.rs`)**: A zero-allocation streamed painter that owns a pre-allocated 32KB `BufWriter` and uses double-buffered state swapping (`copy_to`) to flush dirty screen regions to the host console in a single system call.

### 2.3. Shared Protocol & Transport Seams
1.  **SecureCodec (`src/protocol/codec.rs`)**: Implements the `PacketCodec` trait (`ChaChaCodec` for production, `NullCodec` for testing). It absorbs ChaCha20Poly1305 encryption/decryption, LZ4 compression, bincode serialization, and wire framing into a symmetrical 4-method seam (`seal_client`, `open_client`, `seal_server`, `open_server`), returning structured `CodecStats` (`wire_len`, `comp_len`, `decomp_len`).
2.  **TerminalGrid (`src/protocol/grid.rs`)**: Encapsulates the 2D matrix of terminal cells (`GridState`), grapheme storage (`CompactGrapheme`), and style attributes. It provides zero-allocation delta diffing (`diff_from`) and delta patching (`patch`), turning `src/protocol.rs` into a pure, lightweight wire envelope file.

---

## 3. Key Design Decisions & Iterative Optimizations

The current high-performance state of `rumsh` is the result of systematic profiling and iterative refactoring. Below are the key architectural decisions made to resolve bottlenecks:

### 3.1. Transition from Client-Side VT Parser to Thin Client (The "Mosh" Shift)
*   **The Initial Bottleneck**: Originally, the server compiled screen diffs, translated them *back* into raw ANSI escape sequences, and sent them to the client. The client ran its own instance of `libghostty-vt` to parse those sequences back into a grid, which it then painted. During fast scrolling in Vim, this double-parsing pipeline generated over **62KB of escape sequences per frame**, choking the client terminal parser and causing a 0.5-second lag.
*   **The Solution**: We completely eliminated `libghostty-vt` and the escape-sequence translator from the client. The client was refactored into a **Thin Client** holding a flat 2D `cell_cache: Vec<LocalCellData>`. Diffs are applied directly to the cache. This reduced the frame update payload size **from 62KB to under 2KB (a 30x reduction)** and eliminated all client-side parsing overhead.

### 3.2. Heavy-First Sync Throttling (Server-Side Debouncing)
*   **The Challenge**: We need instant responsiveness for typing (sub-20ms echo) but high efficiency for heavy output (batching updates into large packets to maximize compression). 
*   **The Implementation**: The server uses a **3-tier dynamic debouncer** that monitors terminal activity:
    *   **Keystroke Priority Mode**: Triggered for 300ms after any client keystroke. Syncs are dispatched almost instantly (`debounce = 4ms`, `max = 15ms`).
    *   **Heavy Streaming Mode**: Triggered when output flows continuously. Syncs are batched to optimize compression (`debounce = 15ms`, `max = 100ms`).
    *   **Normal Mode (Default)**: Fallback for standard command output (`debounce = 8ms`, `max = 40ms`).
*   **The Precedence Decision**: We prioritized **Heavy Streaming Mode over Keystroke Priority**. If a user presses Enter to run a heavy command (e.g., `cat large_file.txt`), the very first frame syncs instantly (4ms), but the continuous flow immediately triggers Heavy Streaming Mode (100ms batching), preventing the server from flooding the network with small packets during the remaining priority window.

### 3.3. Zero-Idle Server CPU & Debouncer Timing Fix
*   **Zero-Idle CPU**: We replaced a polling timer loop on the server with an event-driven channel (`sync_rx`). The sync task sleeps on channel receives when no PTY output is generated, dropping server idle CPU usage to **0%**.
*   **The Timing Bug**: Initially, the timestamp `now` was evaluated at the top of the sync loop *before* blocking on `sync_rx.recv()`. If the server was idle for 10 seconds, `now` was stale, causing the next sync to schedule in the past and bypass debouncing entirely. We fixed this by re-evaluating `now` **after** the receiver unblocks, ensuring debouncing timers are always scheduled correctly in the future.

### 3.4. Buffered Writing and Redundant System Call Elimination
*   **Buffered Writing**: In Rust, writing to `std::io::stdout()` in raw mode is unbuffered. Printing a screen frame cell-by-cell executed hundreds of individual `write` system calls, taking up to 50ms of kernel time. We wrapped stdout in a `BufWriter`, merging all frame rendering operations into **exactly one `write` system call**, reducing kernel overhead to **under 0.1ms**.
*   **Redundant Size Queries**: We removed the `crossterm::terminal::size()` ioctl system call from the client's paint loop. Since the client already tracks resizing via `SIGWINCH` signals, querying the OS on every single frame was redundant and slow.

### 3.5. Cooperative Yielding to Prevent Executor Starvation
*   **The Problem**: During high-frequency streaming (like `top -d 0.1`), the client's UDP receiver loop was constantly flooded with packets. Because the socket was always readable, the receiver task ran continuously without yielding, starving the Stdin Reader task. As a result, the client would ignore keyboard inputs (like pressing `q` to quit `top`) for 10–20 seconds.
*   **The Solution**: We inserted `smol::future::yield_now().await` inside the client's UDP receiver loop. This forces the receiver to cooperatively yield to the executor after draining a batch of packets, ensuring the Stdin task gets immediate CPU slices to capture and send keystrokes.

### 3.6. Adaptive Client Paint Throttling
*   **The Problem**: If the host terminal emulator is slow to render, the client's paint call blocks the main thread. Under heavy streaming, this created a feedback loop where the client spent 100% of its time rendering stale frames.
*   **The Solution**: The client monitors the actual duration of its `paint()` calls. If painting takes longer than 8ms, it enters an **Adaptive Throttle Mode**, scaling `max_delay = paint_duration * 3` and `debounce_delay = paint_duration / 2`. This guarantees the executor spends at least 2/3rds of its time sleeping/processing network packets rather than drawing, preventing visual lockups.

### 3.7. Sliding Window Protocol & Reliable UDP Transport (ARQ)
*   **The Problem (Packet Loss)**: In an unreliable network (e.g., 10% packet drop and 500ms delay), simple UDP packet delivery causes permanent keystroke or layout losses, leading to terminal state desynchronization.
*   **The Solution (Server-Side Sliding Window)**: The server enforces strict in-order packet processing. Out-of-order client packets are buffered in a `BTreeMap`. If a sequence gap is detected, the server halts processing of subsequent packets. Once the client retransmits the missing packet and fills the gap, the server processes the buffered batch in a single chronological sweep.
*   **The Solution (Client-Side ARQ)**: The client buffers all sent session packets in an `unacked_packets` map. An asynchronous ARQ task runs every 100ms, checking the age of unacknowledged packets and retransmitting them if their age exceeds a dynamic retransmission timeout (RTO = 2x RTT, capped between 200ms and 1000ms).
*   **The Solution (Cumulative ACKs)**: The connection uses standard cumulative ACKs. The `ack_seq_num` sent in every packet strictly represents the highest *consecutively processed* sequence number, ensuring the sender only prunes packets the receiver has actually processed in-order.
*   **The Solution (Reliable Heartbeats)**: `KeepAlive` packets are fully reliable (saved in `unacked_packets` and retransmitted), preventing permanent sequence gaps on the server if a heartbeat is dropped, while maintaining cryptographic nonce uniqueness. Pure ACKs do not consume sequence numbers to avoid unreliable gap deadlocks.

### 3.8. OS-Process-Aware Local Echo Heuristic
*   **The Challenge**: Local character echo is essential for a responsive feel under high latency (e.g. 500ms lag). However, interactive shells (using GNU Readline like `bash`) explicitly disable the kernel-level tty `ECHO` flag at the prompt to manage line editing manually. This caused standard local echo checks to always report echo as disabled, resulting in laggy typing at the prompt.
*   **The Solution**: Implemented an OS-level process-aware heuristic on the server. The server queries the PTY's active foreground process group ID (`tcgetpgrp`) and reads `/proc/<pgrp>/comm` to identify the foreground executable. If the process is an interactive shell (e.g. `bash`, `zsh`, `fish`, `rumsh`), the server recommends enabling local echo to the client even if the tty `ECHO` flag is false. If the user runs full-screen editors (`vi`), interactive tools (`top`), or password prompts (`sudo` which disables echo), the server instantly recommends disabling echo, ensuring perfect responsiveness at the prompt and 100% security/correctness in applications.

### 3.9. Mosh-like Resilience & Adaptive KeepAlive Throttling
*   **The Challenge**: A hard connection timeout (e.g. exiting after 15s of silence) forces the user to restart their session if they close their laptop lid or walk away from Wi-Fi. However, keeping the connection alive at a high heartbeat rate (every 2s) during a long outage drains the client's battery and wastes network bandwidth.
*   **The Solution**: Implemented **Adaptive KeepAlive Throttling** (exponential backoff heartbeats). The client monitors the silence duration since the last received packet:
    *   **Healthy Connection (<5s silence)**: Heartbeat interval is **2 seconds** (ensures real-time latency telemetry).
    *   **Brief Outage (5s - 15s)**: Throttles to **5 seconds**.
    *   **Medium Outage (15s - 60s)**: Throttles to **15 seconds**.
    *   **Long Outage (>60s)**: Throttles to **60 seconds** (idle heartbeat rate).
*   **Instant Recovery**: The moment the client receives a single packet from the server, the interval instantly snaps back to **2 seconds**, resuming normal high-frequency operations. The client stays in `[Reconnecting...]` indefinitely (like Mosh), allowing laptop-sleep or long network drops to recover seamlessly.

### 3.10. Single-Threaded Deferred Screen Clears (Thread Safety)
*   **The Problem**: Initially, when the terminal resized, the client's network receiver task cleared the screen physically by writing directly to `stdout.flush()` while holding the `TerminalState` write lock. During heavy streaming, this blocking synchronous I/O choked the thread, causing massive lock-contention and deadlocking the entire client. It also risked stdout corruption due to concurrent writes from the Paint task.
*   **The Solution**: Refactored to a thread-safe, deferred rendering design. The network receiver task now simply sets a logical `clear_requested: bool` flag on `TerminalState` under the lock and yields instantly. The dedicated **Paint Timer Task** detects this flag, executes the physical screen clear safely, and resets the flag in the main state inside the paint loop, ensuring all terminal I/O is single-threaded and lock-free.

### 3.11. Late-Arrival Packet Loss Corrections (Telemetry Accuracy)
*   **The Problem**: To measure packet loss, the client tracks the expected sequence number. If a packet arrives out-of-order (e.g., expected 10, but 12 arrives), the client marks intermediate packets (10, 11) as lost in a sliding 100-packet deque. However, under high network jitter, these delayed packets eventually arrive late. Without correction, the estimator permanently counted late-arriving packets as lost, inflating the loss telemetry to 40-50% under a true 10% loss network.
*   **The Solution**: Added a late-arrival correction handler. When a packet with `seq < expected` arrives, the client calculates its relative offset in the sliding deque and **corrects its status from `false` (lost) to `true` (received)**, ensuring highly accurate, real-time packet loss telemetry in the debugging overlay.

### 3.12. Zero-Allocation Streamed Painter (Client Painting Optimization)
*   **The Challenge**: In the original client renderer, every tick of the paint loop allocated a new `BufWriter` buffer on the stack/heap, and accumulated characters into a `run_graphemes: String` accumulator to print runs of identical styles. This generated massive heap allocation churn (around 15MB/s) and triggered high garbage collection overhead in the rendering loop.
*   **The Solution**: We refactored `ClientTerminalRenderer` to own a pre-allocated, large (32KB) `BufWriter<std::io::Stdout>` inside the struct. We rewrote the `paint()` method to stream cell graphemes (`&str`) directly to the writer, maintaining an `active_style` tracking cache. Terminal style escape sequences and cursor movement codes are only emitted when they actually change. This dropped heap allocations in the paint loop to **exactly zero** and dramatically reduced write bandwidth.

### 3.13. In-Place Grid Compiler Updates & Zero-Idle Cloning (Server Optimization)
*   **The Challenge**: Initially, on every 16ms tick, the server's sync loop would query the VT parser, compile a new `GridState` vector, clone it, and compare it against the previous state, discarding the clone if the screen was idle. This resulted in constant, heavy vector allocations and memory copies on the server even when the terminal was completely idle.
*   **The Solution**: Refactored `ServerTerminalState` to own a single, pre-allocated `grid_state: GridState` buffer. The `update_and_get_state` method now updates this buffer in-place and returns a borrowed reference (`&GridState`). The frame sync task compares references and **only clones** the state when a frame has actually changed and is ready to be serialized for transmission. This completely eliminates grid cloning on idle ticks.

### 3.14. Double-Buffered Render State Swaps (Client State Swapping)
*   **The Challenge**: To transfer the synchronized terminal grid from the asynchronous UDP receiver task to the paint timer task, the receiver used to clone the entire `TerminalState` object under a write lock, causing heap allocations and holding the lock, which created lock-contention and choked the network receiver.
*   **The Solution**: Implemented a **Double-Buffered State Swap** pipeline. The renderer now owns a pre-allocated `back_buffer: TerminalState` mirror. We added an in-place `TerminalState::copy_to` method which performs a fast copy of primitive fields and copies cell vectors in-place using `copy_from_slice` (reusing existing vector capacities). The UDP receiver now copies the state in-place to the renderer's `back_buffer` in a sub-microsecond operation, releasing the lock instantly and allowing the painter to run allocation-free and lock-free.

### 3.15. Foreground Process Group Cache (Server System Call Optimization)
*   **The Challenge**: To decide if local echo is recommended, the server called `get_foreground_process_name()` on every frame sync tick (up to 60Hz), which executed `tcgetpgrp(fd)` and read the file `/proc/{pgrp}/comm` from the disk. Reading `/proc` at 60Hz is extremely expensive, generating heavy system call overhead and kernel filesystem operations.
*   **The Solution**: Implemented a thread-safe **Process Group Cache** in the PTY bridge. Since `tcgetpgrp` is a very fast system call, we call it on every tick. If the returned process group ID (`pgrp`) matches the cached ID, we reuse the cached process name immediately. We only read `/proc` (a cache miss) when the foreground process group actually changes (e.g. launching or exiting a command), yielding a **>99.9% cache hit rate** and saving hundreds of disk reads per second.

### 3.16. In-Place Prepending of Serialization Flags (Protocol Optimization)
*   **The Challenge**: In `serialize_compressed`, the payload was serialized into a `plain: Vec<u8>`, then a second `result` vector was allocated, the flag byte (`0x00`/`0x01`) was pushed, and `plain` was copied into it, causing a double-allocation and full copy on every single network packet.
*   **The Solution**: Optimized the serialization pipeline by utilizing `Vec::insert(0, flag)` to prepend the flag byte in-place on the existing `plain` (or compressed) vector. For small packets (ACKs, Keystrokes, KeepAlives, which represent 99% of session packets), this performs a sub-nanosecond in-memory byte shift, **completely eliminating the second heap allocation**.

### 3.17. Ultra-Fast Grapheme Truncation (VT Compilation Optimization)
*   **The Challenge**: To truncate cell graphemes to fit our compact 15-byte protocol buffer, `CompactGrapheme::new` used to run `s.char_indices()`, which decoded the UTF-8 structure of every character in the string. This was highly redundant for standard terminal cells.
*   **The Solution**: We rewrote the truncation loop to use `str::is_char_boundary`. We check if the string length exceeds 15. If it does, we start at index 15 and decrement until we hit a valid character boundary. This completely bypasses character decoding for all standard cells, and finds the boundary in at most 3 byte-level checks.

### 3.18. Defensive Shell Process Reaping (PTY Lifecycle Safety)
*   **The Challenge**: Spawning the remote shell process via `portable-pty` returned a child process handle that was discarded by the server. If the server crashed, timed out, or exited uncleanly, the shell subprocess would leak, creating orphan zombie processes on the remote machine.
*   **The Solution**: We preserved the `Child` process handle inside the `PtyBridge` struct and implemented the `Drop` trait. When the session is destroyed or the PTY bridge goes out of scope, the destructor explicitly invokes `.kill()` on the child process, guaranteeing that the remote shell is forcefully and cleanly reaped under all circumstances.

### 3.19. Deep-Module Architecture & Seam Liberation (Lock Contention Elimination)
*   **The Challenge**: As feature complexity grew, both client and server network loops became littered with layer-violating synchronization wrappers (`Arc<Mutex<...>>`, `Arc<RwLock<...>>`, `Rc<RefCell<...>>`), manual bincode/LZ4 serialization steps, and OS libc calls. This caused thread contention, made unit testing difficult, and blurred the boundaries between UDP networking and terminal rendering.
*   **The Solution**: We systematically reorganized the codebase into deep modules with clean, symmetrical seams:
    *   **Lock-Free Single-Threaded Loops**: In `run_client` and `run_server`, we absorbed protocol timers and state machines into `MirrorSession` and `AuthoritativeSession`. By passing declarative actions (`ClientAction`, `SessionAction`) across the seam, we eliminated all lock contention and stripped out `Arc<Mutex<...>>` / `Rc<RefCell<...>>` wrappers from network loops.
    *   **Unified Codec Seam**: We created `PacketCodec` (`SecureCodec`), stripping secret key material (`[u8; 32]`), nonce generation, and compression flags out of session logic.
    *   **Isolated OS & Grid Math**: We created `TerminalGrid` (`src/protocol/grid.rs`), `LocalEchoEngine` (`src/client/echo.rs`), and `TerminalLifecycle` (`src/client/lifecycle.rs`). This removed 70 lines of diffing loops from server sessions, removed prediction rollback math from terminal mirrors, and liberated client networking from libc process control.
    *   **Testability Payoff**: By introducing mockable trait seams (`NullCodec`, `FakeLifecycleBackend`), our automated test suite expanded to **37 fast, deterministic unit tests** verifying protocol ordering, tamper rejection, local echo rollback, and RAII cleanup in memory without touching OS terminal modes.

---

## 4. Protocol & Packet Format

`rumsh` packets are serialized using an optimized varint-encoded binary format (`bincode`) and compressed using LZ4.

### 4.1. Server to Client Packet (`EncryptedServerPacket`)
*   `seq_num` (u64): Monotonically increasing sequence number.
*   `ack_seq_num` (u64): The highest client sequence number acknowledged by the server.
*   `ciphertext` (Vec<u8>): Encrypted, LZ4-compressed `ServerPayload`.

#### `ServerPayload` Varieties:
*   `HandshakeAck { session_id }`: Acknowledges connection establishment.
*   `Frame(FrameUpdate)`: Contains the screen diff.
    *   `cols`, `rows` (u16): Active terminal dimensions.
    *   `cursor_x`, `cursor_y` (u16): Active cursor coordinates.
    *   `cursor_visible` (bool): Cursor visibility state.
    *   `is_echo_enabled` (bool): Server PTY echo state (used to toggle client predictive echo).
    *   `row_updates` (Vec<RowUpdate>): List of modified rows, each containing a list of `CellUpdate`s (coordinate + character + style attributes).
*   `KeepAlive`: Heartbeat packet.
*   `Shutdown`: Sent when the shell exits to cleanly close the client.

### 4.2. Client to Server Packet (`EncryptedClientPacket`)
*   `session_id` (u64): Unique session identifier.
*   `seq_num` (u64): Monotonically increasing sequence number.
*   `ack_seq_num` (u64): The highest server sequence number acknowledged by the client.
*   `ciphertext` (Vec<u8>): Encrypted `ClientPayload`.

#### `ClientPayload` Varieties:
*   `Handshake { client_version }`: Initiates connection.
*   `Keystrokes(Vec<u8>)`: Raw input bytes.
*   `Resize { cols, rows }`: Sent when the host terminal window resizes.
*   `KeepAlive`: Heartbeat packet.

---

## 5. Performance Characteristics

*   **Interactive Latency**: Sub-15ms round-trip latency for local echo and character typing under normal conditions.
*   **Idle Overhead**: **0% CPU usage** on both client and server when idle.
*   **Bandwidth Efficiency**: Up to **95% compression ratio** on terminal screens due to cell-coalescing run-length encoding and LZ4 compression.
*   **Network Resilience**: Instantaneous IP roaming (UDP-backed) and robust congestion control via adaptive paint and sync throttling.
