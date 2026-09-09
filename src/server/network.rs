use crate::crypto::CryptoManager;
use crate::protocol::codec::ChaChaCodec;
use crate::protocol::{
    ClientPayload, EncryptedClientPacket, EncryptedServerPacket, ServerPayload, deserialize,
    serialize,
};
use crate::server::pty::PtyBridge;
use crate::server::session::{AuthoritativeSession, SessionAction};
use anyhow::Result;
use async_net::UdpSocket;
use async_signal::{Signal, Signals};
use futures_lite::prelude::*;
use smol::{LocalExecutor, Timer, channel};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct HandshakeResult {
    pub client_addr: SocketAddr,
    pub session_id: u64,
    pub client_start_seq: u64,
    pub cols: u16,
    pub rows: u16,
}

type FragmentCache = Arc<Mutex<VecDeque<(u64, Vec<Vec<u8>>)>>>;

pub fn determine_bind_address(
    bind_ip_override: Option<std::net::IpAddr>,
    bind_any: bool,
) -> std::net::IpAddr {
    if let Some(ip) = bind_ip_override {
        log::info!("Using explicitly specified bind IP: {}", ip);
        return ip;
    }

    if bind_any {
        return "0.0.0.0".parse().unwrap();
    }

    if let Ok(ssh_conn) = std::env::var("SSH_CONNECTION") {
        let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
        if parts.len() >= 3
            && let Ok(server_ip) = parts[2].parse::<std::net::IpAddr>()
        {
            log::info!("Discovered server IP from SSH_CONNECTION: {}", server_ip);
            return server_ip;
        }
    }
    log::info!("SSH_CONNECTION not found or invalid, falling back to 0.0.0.0");
    "0.0.0.0".parse().unwrap()
}

pub fn parse_port_range(range_str: &str) -> Result<std::ops::RangeInclusive<u16>> {
    let parts: Vec<&str> = if range_str.contains(':') {
        range_str.split(':').collect()
    } else if range_str.contains('-') {
        range_str.split('-').collect()
    } else {
        return Err(anyhow::anyhow!(
            "Invalid port range format. Use start:end or start-end"
        ));
    };

    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid port range format. Use start:end or start-end"
        ));
    }

    let start = parts[0].parse::<u16>()?;
    let end = parts[1].parse::<u16>()?;

    if start > end {
        return Err(anyhow::anyhow!(
            "Start port cannot be greater than end port"
        ));
    }

    Ok(start..=end)
}

pub fn bind_to_available_port_sync(
    bind_ip: std::net::IpAddr,
    port_range: std::ops::RangeInclusive<u16>,
) -> Result<(std::net::UdpSocket, u16)> {
    for port in port_range {
        let addr = std::net::SocketAddr::new(bind_ip, port);
        match std::net::UdpSocket::bind(addr) {
            Ok(socket) => {
                log::info!("Successfully bound UDP socket to {}", addr);
                return Ok((socket, port));
            }
            Err(e) => {
                log::debug!(
                    "Failed to bind UDP socket to {}: {}, trying next port...",
                    addr,
                    e
                );
            }
        }
    }
    Err(anyhow::anyhow!(
        "Failed to bind to any port in the specified range"
    ))
}

async fn wait_for_client_handshake(
    socket: &UdpSocket,
    crypto_handshake: &CryptoManager,
    session_id: u64,
) -> Result<HandshakeResult> {
    let timeout_timer = Timer::after(Duration::from_secs(60));

    let handshake_future = async {
        let mut buf = [0u8; 65535];
        loop {
            let (n, src_addr) = socket.recv_from(&mut buf).await?;
            if let Ok(wire_packet) = deserialize::<EncryptedClientPacket>(&buf[..n])
                && wire_packet.session_id == 0
                && let Ok(payload_bytes) =
                    crypto_handshake.decrypt(wire_packet.seq_num, &wire_packet.ciphertext)
                && let Ok(ClientPayload::Handshake {
                    client_version,
                    cols,
                    rows,
                }) = deserialize::<ClientPayload>(&payload_bytes)
            {
                log::info!(
                    "Received handshake from client (v{}) from {}",
                    client_version,
                    src_addr
                );

                // Reply with HandshakeAck
                let ack_payload = ServerPayload::HandshakeAck { session_id };
                let ack_bytes = serialize(&ack_payload).unwrap();
                let reply_seq = 1;
                let ciphertext = crypto_handshake.encrypt(reply_seq, &ack_bytes).unwrap();
                let ack_packet = EncryptedServerPacket {
                    seq_num: reply_seq,
                    ack_seq_num: wire_packet.seq_num,
                    frag_idx: 0,
                    total_frags: 1,
                    ciphertext,
                };
                if let Ok(serialized) = serialize(&ack_packet) {
                    log::debug!("Sending HandshakeAck seq={}", reply_seq);
                    let _ = socket.send_to(&serialized, src_addr).await;
                }

                log::info!("Handshake complete for client {}", src_addr);

                return Ok(HandshakeResult {
                    client_addr: src_addr,
                    session_id,
                    client_start_seq: wire_packet.seq_num,
                    cols,
                    rows,
                });
            }
        }
    };

    let signal_future = async {
        if let Ok(mut signals) = Signals::new([Signal::Int, Signal::Term])
            && let Some(sig) = signals.next().await
        {
            log::info!(
                "Received signal {:?} during handshake countdown. Terminating gracefully.",
                sig
            );
            return Err(anyhow::Error::msg(format!(
                "Terminated by signal {:?}",
                sig
            )));
        }
        smol::future::pending::<Result<HandshakeResult>>().await
    };

    match smol::future::race(
        handshake_future,
        smol::future::race(
            async {
                timeout_timer.await;
                Err(anyhow::Error::msg("Handshake timed out"))
            },
            signal_future,
        ),
    )
    .await
    {
        Ok(res) => Ok(res),
        Err(e) => {
            log::error!("Server startup halted: {}", e);
            std::process::exit(1);
        }
    }
}

pub async fn run_server(
    std_socket: std::net::UdpSocket,
    shell_cmd: &str,
    key_bytes: [u8; 32],
) -> Result<()> {
    let local_ex = LocalExecutor::new();
    let session_id = rand::random::<u64>();
    let crypto_handshake = Arc::new(CryptoManager::new(&key_bytes, 0));

    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::try_from(std_socket)?);
    let bound_port = socket.local_addr()?.port();
    log::info!("Rumsh Server running on UDP port {}", bound_port);

    log::info!("Waiting for client handshake (60s timeout)...");
    let handshake = wait_for_client_handshake(&socket, &crypto_handshake, session_id).await?;
    log::info!(
        "Client connected from {}. Starting session tasks.",
        handshake.client_addr
    );

    let (pty_bridge, pty_rx) = PtyBridge::new(handshake.cols, handshake.rows, shell_cmd)?;

    let codec = ChaChaCodec::new(&key_bytes, handshake.session_id);
    let session = Rc::new(RefCell::new(AuthoritativeSession::new(
        handshake.session_id,
        codec,
        handshake.client_start_seq,
        handshake.client_addr,
        handshake.cols,
        handshake.rows,
        pty_bridge,
    )?));

    let (shutdown_tx, shutdown_rx) = channel::bounded::<()>(1);

    let diff_in_flight = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fragment_cache: FragmentCache = Arc::new(Mutex::new(VecDeque::new()));

    let execute_actions = {
        let diff_in_flight = diff_in_flight.clone();
        let fragment_cache = fragment_cache.clone();
        Arc::new(
            move |actions: Vec<SessionAction<ChaChaCodec>>,
                  socket: &Arc<UdpSocket>,
                  shutdown_tx: &smol::channel::Sender<()>| {
            for action in actions {
                match action {
                    SessionAction::SendPacket { bytes, target } => {
                        let socket = socket.clone();
                        let wire_bytes = bytes.len();
                        smol::spawn(async move {
                            log::info!(
                                "[SERVER] [TX_PACKET] wire_bytes={} target={}",
                                wire_bytes,
                                target
                            );
                            let _ = socket.send_to(&bytes, target).await;
                        })
                        .detach();
                    }
                    SessionAction::OffloadDiffJob { job, target } => {
                        let socket = socket.clone();
                        let in_flight = diff_in_flight.clone();
                        let frag_cache = fragment_cache.clone();
                        // If another diff job is already in flight, skip this one to prevent concurrent bursting
                        if in_flight.swap(true, std::sync::atomic::Ordering::SeqCst) {
                            log::info!(
                                "[SERVER] [DIFF_SKIPPED_IN_FLIGHT] seq={} skipped because previous diff is still in flight",
                                job.seq
                            );
                            continue;
                        }
                        let job_seq = job.seq;
                        let job_ref = job.ref_seq;
                        let job_ack = job.ack_seq;
                        smol::spawn(async move {
                            if let Ok(packets) = blocking::unblock(move || job.run()).await {
                                let num_packets = packets.len();
                                if num_packets > 1 {
                                    let mut cache = frag_cache.lock().unwrap();
                                    if cache.len() >= 4 {
                                        cache.pop_front();
                                    }
                                    cache.push_back((job_seq, packets.clone()));
                                }
                                let inter_frag_delay = if num_packets > 4 {
                                    Duration::from_millis(3)
                                } else {
                                    Duration::from_millis(1)
                                };
                                for (i, serialized) in packets.into_iter().enumerate() {
                                    log::info!(
                                        "[SERVER] [TX_PACKET] seq={} ack={} ref_seq={} frag={}/{} wire_bytes={} target={}",
                                        job_seq,
                                        job_ack,
                                        job_ref,
                                        i,
                                        num_packets,
                                        serialized.len(),
                                        target
                                    );
                                    let _ = socket.send_to(&serialized, target).await;
                                    if i + 1 < num_packets {
                                        Timer::after(inter_frag_delay).await;
                                    }
                                }
                            }
                            in_flight.store(false, std::sync::atomic::Ordering::SeqCst);
                        })
                        .detach();
                    }
                    SessionAction::ResendFragments {
                        frame_seq,
                        received_mask,
                        target,
                    } => {
                        let socket = socket.clone();
                        let cached_packets = {
                            let cache = fragment_cache.lock().unwrap();
                            cache
                                .iter()
                                .find(|(seq, _)| *seq == frame_seq)
                                .map(|(_, packets)| packets.clone())
                        };

                        if let Some(packets) = cached_packets {
                            let total_frags = packets.len();
                            log::info!(
                                "[SERVER] [RETRANSMIT_FRAGS_START] frame_seq={} total_frags={} mask_len={}",
                                frame_seq,
                                total_frags,
                                received_mask.len()
                            );
                            smol::spawn(async move {
                                for (idx, packet_bytes) in packets.into_iter().enumerate() {
                                    let word_idx = idx / 64;
                                    let bit_idx = idx % 64;
                                    let is_received = if word_idx < received_mask.len() {
                                        (received_mask[word_idx] & (1u64 << bit_idx)) != 0
                                    } else {
                                        false
                                    };

                                    if !is_received {
                                        log::info!(
                                            "[SERVER] [TX_RETRANSMIT_FRAG] seq={} frag={}/{} wire_bytes={} target={}",
                                            frame_seq,
                                            idx,
                                            total_frags,
                                            packet_bytes.len(),
                                            target
                                        );
                                        let _ = socket.send_to(&packet_bytes, target).await;
                                        Timer::after(Duration::from_millis(1)).await;
                                    }
                                }
                            })
                            .detach();
                        } else {
                            log::warn!(
                                "[SERVER] [RETRANSMIT_FRAGS_NOT_FOUND] frame_seq={} not in fragment cache",
                                frame_seq
                            );
                        }
                    }
                    SessionAction::Shutdown => {
                        let _ = shutdown_tx.try_send(());
                    }
                }
            }
        })
    };

    // Task 1: PTY Reader Task (converts PTY stream into terminal buffer inputs)
    {
        let session = session.clone();
        let pty_rx = pty_rx.clone();
        let shutdown_tx = shutdown_tx.clone();
        local_ex
            .spawn(async move {
                loop {
                    match pty_rx.recv().await {
                        Ok(data) => {
                            if let Ok(mut session_ref) = session.try_borrow_mut() {
                                session_ref.on_pty_bytes(&data, Instant::now());
                            }
                            smol::future::yield_now().await;
                        }
                        Err(_) => {
                            log::info!("PTY output channel disconnected. Exiting PTY reader.");
                            let _ = shutdown_tx.send(()).await;
                            break;
                        }
                    }
                }
            })
            .detach();
    }

    // Task 2: Frame Sync Timer Task (~60Hz periodic tick)
    {
        let session = session.clone();
        let socket = socket.clone();
        let shutdown_tx = shutdown_tx.clone();
        let diff_in_flight = diff_in_flight.clone();
        let execute_actions = execute_actions.clone();
        local_ex
            .spawn(async move {
                loop {
                    Timer::after(Duration::from_millis(16)).await;
                    if shutdown_tx.is_closed() {
                        break;
                    }
                    // Skip generating a new frame if a previous diff job is still in flight
                    if diff_in_flight.load(std::sync::atomic::Ordering::SeqCst) {
                        continue;
                    }
                    if let Ok(mut session_ref) = session.try_borrow_mut() {
                        let actions = session_ref.on_tick(Instant::now());
                        execute_actions(actions, &socket, &shutdown_tx);
                    }
                }
            })
            .detach();
    }

    // Task 3: UDP Receiver Loop
    let main_loop = async {
        let mut buf = [0u8; 65535];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    match session
                        .borrow_mut()
                        .feed_packet(&buf[..n], src_addr, Instant::now())
                    {
                        Ok(actions) => execute_actions(actions, &socket, &shutdown_tx),
                        Err(e) => {
                            log::error!("Error processing packet from {}: {:?}", src_addr, e)
                        }
                    }
                }
                Err(e) => {
                    log::error!("UDP read error: {:?}", e);
                }
            }
        }
    };

    // Shutdown Handler
    let shutdown_signal = {
        let session = session.clone();
        let socket = socket.clone();
        async move {
            let _ = shutdown_rx.recv().await;
            log::info!("PTY exited. Sending shutdown packet to client and shutting down server.");

            let action = session.borrow_mut().prepare_shutdown();
            if let Ok(SessionAction::SendPacket { bytes, target }) = action {
                for _ in 0..3 {
                    let _ = socket.send_to(&bytes, target).await;
                    Timer::after(Duration::from_millis(50)).await;
                }
            }
        }
    };

    // Signal Handler for graceful termination on SIGINT/SIGTERM
    let signal_handler = async {
        if let Ok(mut signals) = Signals::new([Signal::Int, Signal::Term])
            && let Some(sig) = signals.next().await
        {
            log::info!("Server received signal {:?}. Exiting run loop.", sig);
        }
    };

    local_ex
        .run(smol::future::race(
            main_loop,
            smol::future::race(shutdown_signal, signal_handler),
        ))
        .await;
    Ok(())
}
