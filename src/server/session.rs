use crate::protocol::codec::PacketCodec;
use crate::protocol::{ClientPayload, GridState, ServerPayload};
use crate::server::pty::PtyBackend;
use crate::server::state::ServerTerminalState;
use anyhow::Result;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Declarative actions returned by the Authoritative Session for the network adapter to execute.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionAction<C: PacketCodec> {
    /// Send this pre-sealed, serialized packet to the specified target address immediately.
    SendPacket { bytes: Vec<u8>, target: SocketAddr },
    /// Offload compiling/compressing/encrypting a diff job to a blocking thread pool.
    /// When the job returns `Ok(bytes)`, send those bytes to `target`.
    OffloadDiffJob { job: UpdateJob<C>, target: SocketAddr },
    /// Triggered when the remote shell has exited. Tear down the UDP socket and exit.
    Shutdown,
}

/// A self-contained, thread-safe job containing all data needed to compile a frame update.
/// Designed to be offloaded to a blocking thread pool to run heavy CPU work.
pub struct UpdateJob<C: PacketCodec> {
    pub seq: u64,
    pub ack_seq: u64,
    pub ref_seq: u64,
    pub ref_state: Option<GridState>,
    pub current_state: GridState,
    pub codec: Arc<C>,
    pub is_echo_recommended: bool,
}

impl<C: PacketCodec> std::fmt::Debug for UpdateJob<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateJob")
            .field("seq", &self.seq)
            .field("ack_seq", &self.ack_seq)
            .field("ref_seq", &self.ref_seq)
            .field("is_echo_recommended", &self.is_echo_recommended)
            .finish()
    }
}

impl<C: PacketCodec> PartialEq for UpdateJob<C> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.ack_seq == other.ack_seq
            && self.ref_seq == other.ref_seq
            && self.ref_state == other.ref_state
            && self.current_state == other.current_state
            && self.is_echo_recommended == other.is_echo_recommended
    }
}

impl<C: PacketCodec> Eq for UpdateJob<C> {}

impl<C: PacketCodec> UpdateJob<C> {
    /// Runs the heavy CPU work: diffing, LZ4 compression, encryption, and serialization via codec.
    /// Returns the final serialized UDP packet bytes.
    pub fn run(self) -> Result<Vec<u8>> {
        let start = Instant::now();
        let update = self.current_state.diff_from(
            self.ref_state.as_ref(),
            self.ref_seq,
            self.is_echo_recommended,
        );
        let diff_time = start.elapsed();

        let seal_start = Instant::now();
        let frame_payload = ServerPayload::Frame(update);
        let packet_bytes = self
            .codec
            .seal_server(self.seq, self.ack_seq, &frame_payload)?;
        let seal_time = seal_start.elapsed();

        let total_time = start.elapsed();
        log::trace!(
            "[TIMING] Frame seq={}: diff={:?}, seal={:?}, total={:?}",
            self.seq,
            diff_time,
            seal_time,
            total_time
        );

        Ok(packet_bytes)
    }
}

pub struct AuthoritativeSession<P: PtyBackend, C: PacketCodec> {
    pub session_id: u64,
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub expected_client_seq: u64,
    pub out_of_order_packets: BTreeMap<u64, ClientPayload>,
    pub client_ack_seq: u64,
    pub last_sent_ack_seq: u64,
    pub state_history: VecDeque<(u64, GridState)>,
    pub codec: Arc<C>,
    pub current_client_addr: SocketAddr,
    pub last_recv_time: Instant,
    pub last_sync_time: Instant,
    pub dirty: bool,
    pub term_state: ServerTerminalState<'static>,
    pub pty: Arc<Mutex<P>>,
}

impl<P: PtyBackend, C: PacketCodec> AuthoritativeSession<P, C> {
    pub fn new(
        session_id: u64,
        codec: C,
        client_start_seq: u64,
        initial_client_addr: SocketAddr,
        cols: u16,
        rows: u16,
        pty_backend: P,
    ) -> Result<Self> {
        let codec = Arc::new(codec);
        let pty = Arc::new(Mutex::new(pty_backend));
        let mut term_state = ServerTerminalState::new(cols, rows)?;
        let pty_clone = pty.clone();
        term_state.setup_pty_callback(move |data| {
            if let Ok(p) = pty_clone.lock()
                && let Err(e) = p.write(data) {
                    log::error!("Error writing terminal back to PTY: {:?}", e);
                }
        })?;

        let now = Instant::now();
        Ok(Self {
            session_id,
            seq_num: 0,
            ack_seq_num: client_start_seq,
            expected_client_seq: client_start_seq + 1,
            out_of_order_packets: BTreeMap::new(),
            client_ack_seq: 0,
            last_sent_ack_seq: 0,
            state_history: VecDeque::new(),
            codec,
            current_client_addr: initial_client_addr,
            last_recv_time: now,
            last_sync_time: now,
            dirty: false,
            term_state,
            pty,
        })
    }

    pub fn feed_packet(
        &mut self,
        packet_bytes: &[u8],
        src_addr: SocketAddr,
        now: Instant,
    ) -> Result<Vec<SessionAction<C>>> {
        let (wire_packet, payload, _stats) = match self.codec.open_client(packet_bytes) {
            Ok(res) => res,
            Err(e) => {
                log::debug!("Failed to open packet from {}: {:?}", src_addr, e);
                return Ok(Vec::new());
            }
        };

        if wire_packet.session_id == 0 {
            let silence = now.duration_since(self.last_recv_time);
            if self.seq_num > 0 && silence < Duration::from_secs(5) {
                log::debug!("Ignoring delayed in-flight handshake packet from active session");
                return Ok(Vec::new());
            }

            log::info!("Received handshake/reconnection from {}", src_addr);
            self.current_client_addr = src_addr;
            self.last_recv_time = now;

            // Reset sequence tracking for reconnected client
            self.ack_seq_num = wire_packet.seq_num;
            self.expected_client_seq = wire_packet.seq_num + 1;
            self.client_ack_seq = 0;
            self.out_of_order_packets.clear();
            self.state_history.clear();
            self.dirty = true;

            let ack_payload = ServerPayload::HandshakeAck {
                session_id: self.session_id,
            };
            self.seq_num += 1;
            let serialized =
                self.codec
                    .seal_server(self.seq_num, wire_packet.seq_num, &ack_payload)?;
            let mut actions = vec![SessionAction::SendPacket {
                bytes: serialized,
                target: self.current_client_addr,
            }];
            actions.extend(self.check_sync(now));
            return Ok(actions);
        }

        if wire_packet.session_id != self.session_id {
            return Ok(Vec::new());
        }

        self.last_recv_time = now;
        if self.current_client_addr != src_addr {
            log::info!(
                "Client roamed from {} to {}",
                self.current_client_addr,
                src_addr
            );
            self.current_client_addr = src_addr;
        }

        let seq_num = wire_packet.seq_num;
        let ack_seq_num = wire_packet.ack_seq_num;
        let mut actions = Vec::new();

        if seq_num < self.expected_client_seq {
            self.dirty = true;
            actions.extend(self.check_sync(now));
            return Ok(actions);
        }

        if seq_num > self.expected_client_seq {
            log::debug!(
                "[SLIDING_WINDOW] Out of order packet seq={}, expected={}. Buffering.",
                seq_num,
                self.expected_client_seq
            );
            self.out_of_order_packets.insert(seq_num, payload);
            return Ok(actions);
        }

        let mut packets_to_process = vec![(seq_num, payload)];
        self.expected_client_seq += 1;

        while let Some(buffered_payload) =
            self.out_of_order_packets.remove(&self.expected_client_seq)
        {
            log::debug!(
                "[SLIDING_WINDOW] Recovered buffered packet seq={}",
                self.expected_client_seq
            );
            packets_to_process.push((self.expected_client_seq, buffered_payload));
            self.expected_client_seq += 1;
        }

        self.ack_seq_num = self.expected_client_seq - 1;
        self.client_ack_seq = ack_seq_num;

        for (seq, payload) in packets_to_process {
            match payload {
                ClientPayload::Ack => {
                    log::trace!("Received pure ACK from client");
                }
                ClientPayload::Keystrokes(keys) => {
                    log::trace!("Received keystrokes seq={}, size={}", seq, keys.len());
                    if let Ok(p) = self.pty.lock()
                        && let Err(e) = p.write(&keys) {
                            log::error!("Error writing to PTY: {:?}", e);
                        }
                }
                ClientPayload::Resize { cols, rows } => {
                    log::info!("Received resize request: {}x{} (seq={})", cols, rows, seq);
                    if let Ok(p) = self.pty.lock() {
                        let _ = p.resize(cols, rows);
                    }
                    let _ = self.term_state.resize(cols, rows);
                    self.dirty = true;
                }
                ClientPayload::KeepAlive => {
                    log::trace!("Received KeepAlive, queueing reply...");
                    let reply_payload = ServerPayload::KeepAlive;
                    self.seq_num += 1;
                    let serialized =
                        self.codec
                            .seal_server(self.seq_num, self.ack_seq_num, &reply_payload)?;
                    actions.push(SessionAction::SendPacket {
                        bytes: serialized,
                        target: self.current_client_addr,
                    });
                }
                ClientPayload::Handshake { .. } => unreachable!(),
            }
        }

        actions.extend(self.check_sync(now));
        Ok(actions)
    }

    pub fn on_pty_bytes(&mut self, data: &[u8], now: Instant) -> Vec<SessionAction<C>> {
        self.term_state.write(data);
        self.dirty = true;
        self.check_sync(now)
    }

    pub fn on_tick(&mut self, now: Instant) -> Vec<SessionAction<C>> {
        self.check_sync(now)
    }

    pub fn prepare_shutdown(&mut self) -> Result<SessionAction<C>> {
        let shutdown_payload = ServerPayload::Shutdown;
        self.seq_num += 1;
        let serialized = self.codec.seal_server(self.seq_num, 0, &shutdown_payload)?;
        Ok(SessionAction::SendPacket {
            bytes: serialized,
            target: self.current_client_addr,
        })
    }

    fn check_sync(&mut self, now: Instant) -> Vec<SessionAction<C>> {
        let mut actions = Vec::new();
        if self.seq_num > 0 && now.duration_since(self.last_sync_time) < Duration::from_millis(16) {
            return actions;
        }

        if !self.dirty && self.ack_seq_num <= self.last_sent_ack_seq {
            return actions;
        }

        let latest_grid = match self.term_state.update_and_get_state() {
            Ok(s) => s,
            Err(e) => {
                log::error!("Error updating terminal state: {:?}", e);
                return actions;
            }
        };

        let is_identical = if let Some((last_seq, last_state)) = self.state_history.back() {
            if last_state == latest_grid {
                log::trace!(
                    "Grid state identical to last sent frame (seq={}), skipping send",
                    last_seq
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        let ack_updated = self.ack_seq_num > self.last_sent_ack_seq;
        if is_identical && !ack_updated {
            self.dirty = false;
            return actions;
        }

        self.last_sent_ack_seq = self.ack_seq_num;
        self.dirty = false;
        self.last_sync_time = now;

        while !self.state_history.is_empty()
            && self.state_history.front().unwrap().0 < self.client_ack_seq
        {
            self.state_history.pop_front();
        }

        let ref_state_opt = self
            .state_history
            .iter()
            .find(|(seq, _)| *seq == self.client_ack_seq)
            .map(|(_, s)| s.clone());
        let ref_seq = if ref_state_opt.is_some() {
            self.client_ack_seq
        } else {
            0
        };

        self.seq_num += 1;
        let seq = self.seq_num;

        let latest_state_cloned = latest_grid.clone();

        self.state_history
            .push_back((seq, latest_state_cloned.clone()));

        if self.state_history.len() > 50 {
            self.state_history.pop_front();
        }

        let is_echo = if let Ok(p) = self.pty.lock() {
            p.is_echo_recommended()
        } else {
            false
        };

        let job = UpdateJob {
            seq,
            ack_seq: self.ack_seq_num,
            ref_seq,
            ref_state: ref_state_opt,
            current_state: latest_state_cloned,
            codec: self.codec.clone(),
            is_echo_recommended: is_echo,
        };

        actions.push(SessionAction::OffloadDiffJob {
            job,
            target: self.current_client_addr,
        });

        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::codec::NullCodec;
    use crate::server::pty::FakePty;

    fn make_client_packet<P: PtyBackend, C: PacketCodec>(
        session: &AuthoritativeSession<P, C>,
        seq: u64,
        payload: &ClientPayload,
    ) -> Vec<u8> {
        session
            .codec
            .seal_client(session.session_id, seq, 0, payload)
            .unwrap()
    }

    #[test]
    fn test_sliding_window_ordering() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        // 1. Feed packet 1 (in-order) -> expect PTY write internally!
        let pkt1 = make_client_packet(&session, 1, &ClientPayload::Keystrokes(b"a".to_vec()));
        let _ = session.feed_packet(&pkt1, addr, Instant::now()).unwrap();
        assert_eq!(session.ack_seq_num, 1);
        assert_eq!(
            session.pty.lock().unwrap().written.lock().unwrap().as_slice(),
            &[b"a".to_vec()]
        );

        // 2. Feed packet 3 (out-of-order, gap at 2) -> expect buffered
        let pkt3 = make_client_packet(&session, 3, &ClientPayload::Keystrokes(b"c".to_vec()));
        let _ = session.feed_packet(&pkt3, addr, Instant::now()).unwrap();
        assert_eq!(session.ack_seq_num, 1);
        assert_eq!(session.out_of_order_packets.len(), 1);

        // 3. Feed packet 2 (fills the gap) -> expect both 2 and 3 written internally!
        let pkt2 = make_client_packet(&session, 2, &ClientPayload::Keystrokes(b"b".to_vec()));
        let _ = session.feed_packet(&pkt2, addr, Instant::now()).unwrap();
        assert_eq!(session.ack_seq_num, 3);
        assert!(session.out_of_order_packets.is_empty());
        assert_eq!(
            session.pty.lock().unwrap().written.lock().unwrap().as_slice(),
            &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn test_multiple_dropped_packets_recovery() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        let pkt1 = make_client_packet(&session, 1, &ClientPayload::Keystrokes(b"1".to_vec()));
        let _ = session.feed_packet(&pkt1, addr, Instant::now()).unwrap();

        let pkt4 = make_client_packet(&session, 4, &ClientPayload::Keystrokes(b"4".to_vec()));
        let pkt5 = make_client_packet(&session, 5, &ClientPayload::Keystrokes(b"5".to_vec()));
        assert!(
            session
                .feed_packet(&pkt4, addr, Instant::now())
                .unwrap()
                .is_empty()
        );
        assert!(
            session
                .feed_packet(&pkt5, addr, Instant::now())
                .unwrap()
                .is_empty()
        );
        assert_eq!(session.ack_seq_num, 1);
        assert_eq!(session.out_of_order_packets.len(), 2);

        let pkt2 = make_client_packet(&session, 2, &ClientPayload::Keystrokes(b"2".to_vec()));
        let _ = session.feed_packet(&pkt2, addr, Instant::now()).unwrap();
        assert_eq!(session.ack_seq_num, 2);
        assert_eq!(session.out_of_order_packets.len(), 2);

        let pkt3 = make_client_packet(&session, 3, &ClientPayload::Keystrokes(b"3".to_vec()));
        let _ = session.feed_packet(&pkt3, addr, Instant::now()).unwrap();
        assert_eq!(session.ack_seq_num, 5);
        assert!(session.out_of_order_packets.is_empty());
        assert_eq!(
            session.pty.lock().unwrap().written.lock().unwrap().as_slice(),
            &[
                b"1".to_vec(),
                b"2".to_vec(),
                b"3".to_vec(),
                b"4".to_vec(),
                b"5".to_vec()
            ]
        );
    }

    #[test]
    fn test_duplicate_packet_handling() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        let pkt1 = make_client_packet(&session, 1, &ClientPayload::Keystrokes(b"a".to_vec()));
        let _ = session
            .feed_packet(&pkt1, addr, Instant::now())
            .unwrap();

        // Feed duplicate packet 1 -> expect check_sync called after cooldown
        session.term_state.write(b"x");
        session.dirty = true;
        let actions = session
            .feed_packet(&pkt1, addr, Instant::now() + Duration::from_millis(20))
            .unwrap();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SessionAction::OffloadDiffJob { .. }));
    }

    #[test]
    fn test_resize_action() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        let pkt = make_client_packet(
            &session,
            1,
            &ClientPayload::Resize {
                cols: 100,
                rows: 40,
            },
        );
        let actions = session.feed_packet(&pkt, addr, Instant::now()).unwrap();
        assert_eq!(
            session.pty.lock().unwrap().resized.lock().unwrap().as_slice(),
            &[(100, 40)]
        );
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SessionAction::OffloadDiffJob { .. }));
    }

    #[test]
    fn test_keepalive_action() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        let pkt = make_client_packet(&session, 1, &ClientPayload::KeepAlive);
        let actions = session.feed_packet(&pkt, addr, Instant::now()).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SessionAction::SendPacket { bytes, target } => {
                assert_eq!(*target, addr);
                let (server_packet, payload, _stats) = session.codec.open_server(bytes).unwrap();
                assert_eq!(server_packet.seq_num, 1);
                assert_eq!(server_packet.ack_seq_num, 1);
                assert!(matches!(payload, ServerPayload::KeepAlive));
            }
            _ => panic!("Expected SendPacket action"),
        }
    }

    #[test]
    fn test_update_job_compilation_and_pruning() {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let fake_pty = FakePty::new();
        let codec = NullCodec::new(12345);
        let mut session =
            AuthoritativeSession::new(12345, codec, 0, addr, 80, 24, fake_pty).unwrap();

        session.dirty = true;
        let actions1 = session.on_tick(Instant::now());
        assert_eq!(actions1.len(), 1);
        assert_eq!(session.state_history.len(), 1);

        session.dirty = true;
        let actions2 = session.on_tick(Instant::now());
        assert!(actions2.is_empty());

        let actions3 = session.on_pty_bytes(b"x", Instant::now() + Duration::from_millis(20));
        assert_eq!(actions3.len(), 1);
        assert_eq!(session.state_history.len(), 2);
    }
}
