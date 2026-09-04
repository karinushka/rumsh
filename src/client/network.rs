use crate::client::lifecycle::TerminalLifecycle;
use crate::client::session::{ClientAction, MirrorSession};
use crate::client::terminal::ClientTerminalRenderer;
use crate::crypto::CryptoManager;
use crate::protocol::codec::ChaChaCodec;
use crate::protocol::{
    ClientPayload, EncryptedClientPacket, EncryptedServerPacket, ServerPayload, deserialize,
    serialize,
};
use anyhow::Result;
use smol::{Async, Timer, channel};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn run_client(server_addr: SocketAddr, key_bytes: [u8; 32], overlay: bool) -> Result<()> {
    let local_bind = match server_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let std_socket = StdUdpSocket::bind(local_bind)?;
    std_socket.set_nonblocking(true)?;
    let socket = Arc::new(Async::new(std_socket)?);
    log::info!("Connecting to server at {}...", server_addr);

    // Setup Handshake Crypto (uses session ID = 0)
    let crypto_handshake = Arc::new(CryptoManager::new(&key_bytes, 0));

    // 1. Handshake Phase
    let (cols, rows) = TerminalLifecycle::query_size()?;
    let session_id;
    let mut handshake_seq = 1u64;
    let mut buf = [0u8; 65535];
    let server_seq;

    loop {
        let handshake_payload = ClientPayload::Handshake {
            client_version: 1,
            cols,
            rows,
        };
        let payload_bytes = serialize(&handshake_payload)?;
        let ciphertext = crypto_handshake.encrypt(handshake_seq, &payload_bytes)?;

        let packet = EncryptedClientPacket {
            session_id: 0,
            seq_num: handshake_seq,
            ack_seq_num: 0,
            ciphertext,
        };
        let serialized = serialize(&packet)?;
        socket.send_to(&serialized, server_addr).await?;

        // Wait for HandshakeAck with timeout
        let res = {
            let ack_future = socket.recv_from(&mut buf);
            let timer_future = Timer::after(Duration::from_millis(500));
            smol::pin!(ack_future);
            smol::pin!(timer_future);
            futures_lite::future::or(async { Some(ack_future.await) }, async {
                timer_future.await;
                None
            })
            .await
        };

        match res {
            Some(Ok((n, _src))) => {
                if let Ok(server_packet) = deserialize::<EncryptedServerPacket>(&buf[..n])
                    && server_packet.ack_seq_num == handshake_seq
                    && let Ok(payload_bytes) =
                        crypto_handshake.decrypt(server_packet.seq_num, &server_packet.ciphertext)
                    && let Ok(ServerPayload::HandshakeAck { session_id: s_id }) =
                        deserialize::<ServerPayload>(&payload_bytes)
                {
                    log::info!(
                        "Handshake successful! Session ID: {}, Server Start Seq: {}",
                        s_id,
                        server_packet.seq_num
                    );
                    session_id = s_id;
                    server_seq = server_packet.seq_num;
                    break;
                }
            }
            _ => {
                log::debug!("Handshake timeout, retrying...");
                handshake_seq += 1;
            }
        }
    }

    // 2. Initialize Alternate Screen & Raw Mode
    let (lifecycle, cols, rows) = TerminalLifecycle::new()?;

    // 3. Initialize Deep Mirror Session & Renderer
    let codec = ChaChaCodec::new(&key_bytes, session_id);
    let mut session = MirrorSession::new(
        session_id,
        codec,
        server_seq,
        cols,
        rows,
        overlay,
        Instant::now(),
    );
    let mut renderer = ClientTerminalRenderer::new();

    // Send initial resize layout to server
    let init_actions = session.on_winch(cols, rows, Instant::now())?;
    for action in init_actions {
        if let ClientAction::SendPacket(bytes) = action {
            socket.send_to(&bytes, server_addr).await?;
        }
    }

    // 4. Background Channels for Stdin and SIGWINCH
    enum ClientEvent {
        Stdin(Vec<u8>),
        Resize(u16, u16),
    }
    let (event_tx, event_rx) = channel::unbounded::<ClientEvent>();

    // Background Stdin thread
    {
        let tx = event_tx.clone();
        smol::spawn(async move {
            loop {
                let read_res = blocking::unblock(move || {
                    let mut buf = vec![0u8; 1024];
                    match std::io::stdin().read(&mut buf) {
                        Ok(n) => Ok((n, buf)),
                        Err(e) => Err(e),
                    }
                })
                .await;
                match read_res {
                    Ok((0, _)) => break,
                    Ok((n, buf)) => {
                        if tx
                            .send(ClientEvent::Stdin(buf[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
        .detach();
    }

    // Background SIGWINCH listener
    let _resize_task = {
        let tx = event_tx.clone();
        lifecycle.spawn_resize_loop(move |c, r| {
            let _ = tx.try_send(ClientEvent::Resize(c, r));
        })
    };

    // 5. Main Event & Render Loop (Single-Threaded Session without Locks!)
    let mut recv_buf = [0u8; 65535];
    let mut tick_interval = Duration::from_millis(16);

    loop {
        enum LoopEvent {
            Tick,
            Recv(std::io::Result<(usize, SocketAddr)>),
            Channel(Result<ClientEvent, smol::channel::RecvError>),
        }

        let loop_event = smol::future::race(
            async {
                Timer::after(tick_interval).await;
                LoopEvent::Tick
            },
            smol::future::race(
                async {
                    let res = socket.recv_from(&mut recv_buf).await;
                    LoopEvent::Recv(res)
                },
                async {
                    let res = event_rx.recv().await;
                    LoopEvent::Channel(res)
                },
            ),
        )
        .await;

        let now = Instant::now();
        let mut actions = Vec::new();

        match loop_event {
            LoopEvent::Tick => {
                actions.extend(session.on_tick(now)?);
            }
            LoopEvent::Recv(Ok((n, src))) => {
                if src == server_addr {
                    actions.extend(session.feed_packet(&recv_buf[..n], now)?);
                }
            }
            LoopEvent::Recv(Err(e)) => {
                log::error!("Socket receive error: {:?}", e);
                break;
            }
            LoopEvent::Channel(Ok(ClientEvent::Stdin(bytes))) => {
                actions.extend(session.feed_stdin(&bytes, now)?);
            }
            LoopEvent::Channel(Ok(ClientEvent::Resize(c, r))) => {
                actions.extend(session.on_winch(c, r, now)?);
            }
            LoopEvent::Channel(Err(_)) => {
                log::info!("Event channel closed, exiting.");
                break;
            }
        }

        // Execute declarative actions
        let mut should_exit = false;
        for action in actions {
            match action {
                ClientAction::SendPacket(bytes) => {
                    let _ = socket.send_to(&bytes, server_addr).await;
                }
                ClientAction::Paint => {
                    let paint_start = Instant::now();
                    if session.copy_frame_if_dirty(&mut renderer.back_buffer) {
                        if let Err(e) = renderer.paint() {
                            log::error!("Error painting screen: {:?}", e);
                        }
                        let paint_duration = paint_start.elapsed();
                        let target_interval = (paint_duration * 3)
                            .max(Duration::from_millis(16))
                            .min(Duration::from_millis(100));
                        if target_interval != tick_interval {
                            tick_interval = target_interval;
                        }
                    } else if tick_interval > Duration::from_millis(16) {
                        tick_interval = (tick_interval - Duration::from_millis(1))
                            .max(Duration::from_millis(16));
                    }
                }
                ClientAction::Suspend => {
                    log::info!("Suspending session...");
                    let _ = lifecycle.suspend(|cols, rows| {
                        let _ = session.on_winch(cols, rows, Instant::now());
                    });
                }
                ClientAction::ShowHelp => {
                    println!("\r\n\n--- Rumsh Local Escape Sequences ---\r");
                    println!("  ~.  - Terminate connection gracefully\r");
                    println!("  ~^Z - Suspend rumsh (return to local shell)\r");
                    println!("  ~o  - Toggle latency/loss debugging overlay\r");
                    println!("  ~?  - Display this help message\r");
                    println!("  ~~  - Send a literal '~' character\r");
                    println!("\r\nPress any key to return to session...\r");
                    let _ = std::io::stdout().flush();

                    let _ = blocking::unblock(move || {
                        let mut single_byte = [0u8; 1];
                        let _ = std::io::stdin().read(&mut single_byte);
                    })
                    .await;

                    let _ = lifecycle.clear_and_resize(|cols, rows| {
                        let _ = session.on_winch(cols, rows, Instant::now());
                    });
                }
                ClientAction::Disconnect => {
                    should_exit = true;
                    break;
                }
            }
        }

        if should_exit {
            break;
        }
    }

    Ok(())
}
