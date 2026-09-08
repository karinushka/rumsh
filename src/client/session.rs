use crate::client::escape::{EscapeCommand, EscapeInterpreter, InterpreterResult};
use crate::client::terminal::{ClientTerminal, TerminalFrame};
use crate::protocol::codec::PacketCodec;
use crate::protocol::{ClientPayload, CompactGrapheme, GridState, LocalCellData, ServerPayload};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ClientAction {
    /// Transmit this encrypted UDP packet to the server.
    SendPacket(Vec<u8>),
    /// The terminal screen or overlay is dirty; copy frame from session and paint to stdout.
    Paint,
    /// (~^Z typed) Disable raw mode, leave alternate screen, send SIGTSTP to self, and upon resumption restore and mark dirty.
    Suspend,
    /// (~? typed) Print local help menu to stdout.
    ShowHelp,
    /// (~. typed or server sent Shutdown) Gracefully terminate session and exit.
    Disconnect,
}

pub struct MirrorSession<C: PacketCodec> {
    pub session_id: u64,
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub codec: Arc<C>,
    pub last_recv_time: Instant,
    pub is_echo_enabled: bool,

    // ARQ and RTT Tracking
    pub sent_packets: HashMap<u64, Instant>,
    pub unacked_packets: HashMap<u64, (Vec<u8>, Instant)>,
    pub last_arq_check: Instant,

    // KeepAlive & Reconnection Tracking
    pub last_keepalive_sent: Instant,
    pub keepalive_interval: Duration,
    pub last_ack_sent: Instant,
    pub is_reconnecting: bool,

    // Fragment NACK Tracking
    pub last_nack_check: Instant,
    pub nacked_frames: HashMap<u64, Instant>,

    // Telemetry & Loss Window
    pub expected_server_seq: u64,
    pub loss_window: VecDeque<bool>,
    pub state_history: VecDeque<(u64, GridState)>,
    pub last_telemetry_calc: Instant,
    pub bytes_recv_acc: usize,
    pub comp_acc: usize,
    pub decomp_acc: usize,
    pub paint_count_acc: u32,

    // Internal Modules
    pub mirror: ClientTerminal,
    pub interpreter: EscapeInterpreter,
}

impl<C: PacketCodec> MirrorSession<C> {
    pub fn new(
        session_id: u64,
        codec: C,
        start_server_seq: u64,
        cols: u16,
        rows: u16,
        overlay: bool,
        now: Instant,
    ) -> Self {
        let codec = Arc::new(codec);
        let mirror = ClientTerminal::new(cols, rows);
        mirror.set_overlay_enabled(overlay);

        Self {
            session_id,
            seq_num: 0,
            ack_seq_num: 0,
            codec,
            last_recv_time: now,
            is_echo_enabled: true,
            sent_packets: HashMap::new(),
            unacked_packets: HashMap::new(),
            last_arq_check: now,
            last_keepalive_sent: now,
            keepalive_interval: Duration::from_secs(2),
            last_ack_sent: now,
            is_reconnecting: false,
            last_nack_check: now,
            nacked_frames: HashMap::new(),
            expected_server_seq: start_server_seq,
            loss_window: VecDeque::new(),
            state_history: VecDeque::new(),
            last_telemetry_calc: now,
            bytes_recv_acc: 0,
            comp_acc: 0,
            decomp_acc: 0,
            paint_count_acc: 0,
            mirror,
            interpreter: EscapeInterpreter::new(),
        }
    }

    pub fn feed_packet(&mut self, packet_bytes: &[u8], now: Instant) -> Result<Vec<ClientAction>> {
        let (wire_packet, payload, stats) = match self.codec.open_server(packet_bytes) {
            Ok(Some(res)) => res,
            Ok(None) => {
                // Fragment received and buffered, waiting for remaining fragments
                return Ok(Vec::new());
            }
            Err(e) => {
                log::debug!("Failed to open server packet: {:?}", e);
                return Ok(Vec::new());
            }
        };
        self.bytes_recv_acc += stats.wire_len;
        self.comp_acc += stats.comp_len;
        self.decomp_acc += stats.decomp_len;

        let seq = wire_packet.seq_num;
        let ack = wire_packet.ack_seq_num;

        let mut actions = Vec::new();

        // Detect recovery from outage (silence > 5 seconds)
        let silence = now.duration_since(self.last_recv_time);
        let is_recovering = silence > Duration::from_secs(5);
        if is_recovering {
            log::info!(
                "Recovering from outage (silence = {:?}). Resetting telemetry.",
                silence
            );
            self.loss_window.clear();
            self.expected_server_seq = seq;
        }

        // 1. RTT and ARQ Pruning
        let mut rtt_updated = None;
        if let Some(sent_time) = self.sent_packets.remove(&ack)
            && !is_recovering
        {
            let rtt = now.duration_since(sent_time).as_millis() as u32;
            if rtt < 5000 {
                rtt_updated = Some(rtt);
            } else {
                log::debug!("Discarding bogus RTT: {}ms", rtt);
            }
        }
        self.sent_packets.retain(|&s, _| s > ack);
        self.unacked_packets.retain(|&s, _| s > ack);

        // 2. Packet Loss Estimation (Sliding Window)
        if self.expected_server_seq == 0 {
            self.expected_server_seq = seq + 1;
        } else if seq > self.expected_server_seq {
            let missed = seq - self.expected_server_seq;
            for _ in 0..missed {
                self.loss_window.push_back(false);
            }
            self.loss_window.push_back(true);
            self.expected_server_seq = seq + 1;
        } else if seq == self.expected_server_seq {
            self.loss_window.push_back(true);
            self.expected_server_seq = seq + 1;
        } else {
            // Late packet arrived! Correct the loss window in-place.
            let gap = self.expected_server_seq - 1 - seq;
            if (gap as usize) < self.loss_window.len() {
                let idx = self.loss_window.len() - 1 - (gap as usize);
                self.loss_window[idx] = true;
            }
        }

        while self.loss_window.len() > 100 {
            self.loss_window.pop_front();
        }

        let loss_pct = if !self.loss_window.is_empty() {
            let lost_count = self.loss_window.iter().filter(|&&r| !r).count();
            Some((lost_count as f32 / self.loss_window.len() as f32) * 100.0)
        } else {
            None
        };

        // 3. Acknowledge and Update Telemetry in Mirror
        self.mirror.acknowledge(ack);
        self.mirror.record_rtt_loss(rtt_updated, loss_pct);

        log::info!(
            "[CLIENT] [PAYLOAD_RECEIVED] seq={} ack={} curr_ack={} silence={:?}",
            seq,
            ack,
            self.ack_seq_num,
            silence
        );

        if seq <= self.ack_seq_num {
            log::info!(
                "[CLIENT] [FRAME_DROP_DUPLICATE] seq={} <= curr_ack={}",
                seq,
                self.ack_seq_num
            );
            return Ok(actions);
        }

        self.last_recv_time = now;
        self.ack_seq_num = seq;

        // Instant recovery of keepalive interval
        self.keepalive_interval = Duration::from_secs(2);
        if self.is_reconnecting {
            self.is_reconnecting = false;
            self.mirror.set_reconnecting(false);
        }

        match payload {
            ServerPayload::Frame(update) => {
                log::info!(
                    "[CLIENT] [FRAME_UPDATE] seq={} ref_seq={} row_updates={} cursor=({},{}) echo={}",
                    seq,
                    update.ref_seq,
                    update.row_updates.len(),
                    update.cursor_x,
                    update.cursor_y,
                    update.is_echo_enabled
                );

                let ref_state_opt = if update.ref_seq == 0 {
                    None
                } else {
                    self.state_history
                        .iter()
                        .find(|(s, _)| *s == update.ref_seq)
                };

                let mut new_state = if let Some((_, ref_grid)) = ref_state_opt {
                    ref_grid.clone()
                } else {
                    if update.ref_seq != 0 {
                        let history_seqs: Vec<u64> = self.state_history.iter().map(|(s, _)| *s).collect();
                        log::warn!(
                            "[CLIENT] [FRAME_DROP_MISSING_REF] seq={} requested ref_seq={} not in history (len={}, history={:?}). Sending immediate ACK with ack_seq_num={}",
                            seq,
                            update.ref_seq,
                            self.state_history.len(),
                            history_seqs,
                            self.ack_seq_num
                        );
                        // Promptly notify server with our latest acknowledged sequence so it can send a full frame
                        if let Ok(ack_bytes) = self.prepare_ack(now) {
                            actions.push(ClientAction::SendPacket(ack_bytes));
                        }
                        return Ok(actions);
                    }
                    GridState {
                        cols: update.cols,
                        rows: update.rows,
                        cursor_x: 0,
                        cursor_y: 0,
                        cursor_visible: false,
                        cells: vec![
                            LocalCellData {
                                graphemes: CompactGrapheme::new(" "),
                                fg: None,
                                bg: None,
                                style_flags: 0,
                            };
                            (update.cols as usize) * (update.rows as usize)
                        ],
                        row_wrapped: vec![false; update.rows as usize],
                    }
                };

                new_state.apply_diff(&update)?;
                self.is_echo_enabled = update.is_echo_enabled;

                self.mirror.apply_frame(&new_state, seq)?;
                if !self.is_echo_enabled {
                    self.mirror.abort_prediction();
                }
                self.state_history.push_back((seq, new_state));
                if self.state_history.len() > 200 {
                    self.state_history.pop_front();
                }

                log::info!(
                    "[CLIENT] [FRAME_APPLIED] seq={} history_len={}",
                    seq,
                    self.state_history.len()
                );

                actions.push(ClientAction::Paint);

                // Send rate-limited ACK packet back to server
                if now.duration_since(self.last_ack_sent) >= Duration::from_millis(30)
                    && let Ok(ack_bytes) = self.prepare_ack(now)
                {
                    actions.push(ClientAction::SendPacket(ack_bytes));
                }
            }
            ServerPayload::KeepAlive => {
                log::info!("[CLIENT] [PAYLOAD_KEEPALIVE] seq={}", seq);
            }
            ServerPayload::Shutdown => {
                log::info!("[CLIENT] [PAYLOAD_SHUTDOWN] Server initiated disconnect seq={}", seq);
                actions.push(ClientAction::Disconnect);
            }
            ServerPayload::HandshakeAck { .. } => {}
        }

        Ok(actions)
    }

    pub fn feed_stdin(&mut self, buf: &[u8], now: Instant) -> Result<Vec<ClientAction>> {
        let mut bytes_to_send = Vec::new();
        let mut actions = Vec::new();

        for &b in buf {
            match self.interpreter.handle_byte(b) {
                InterpreterResult::SendBytes(mut bs) => {
                    bytes_to_send.append(&mut bs);
                }
                InterpreterResult::Consume => {}
                InterpreterResult::Command(cmd) => match cmd {
                    EscapeCommand::Disconnect => {
                        log::info!("Graceful disconnect requested via escape sequence (~.).");
                        actions.push(ClientAction::Disconnect);
                        return Ok(actions);
                    }
                    EscapeCommand::Suspend => {
                        log::info!("Suspending session...");
                        self.mirror.mark_dirty();
                        actions.push(ClientAction::Suspend);
                    }
                    EscapeCommand::Help => {
                        self.mirror.mark_dirty();
                        actions.push(ClientAction::ShowHelp);
                    }
                    EscapeCommand::ToggleOverlay => {
                        self.mirror.toggle_overlay();
                        actions.push(ClientAction::Paint);
                    }
                },
            }
        }

        if !bytes_to_send.is_empty() {
            log::trace!(
                "[LATENCY] T1: Read keystrokes from stdin, filtered to send: {:?}",
                bytes_to_send
            );

            let (packet_bytes, seq) = self.prepare_keystrokes(bytes_to_send.clone(), now)?;
            let is_printable = bytes_to_send.iter().all(|&b| !b.is_ascii_control());
            if self.is_echo_enabled && is_printable {
                self.mirror.predict_input(&bytes_to_send, seq);
                log::debug!("[ECHO] Applied local echo for seq={}", seq);
                actions.push(ClientAction::Paint);
            }
            actions.push(ClientAction::SendPacket(packet_bytes));
        }

        Ok(actions)
    }

    pub fn on_winch(&mut self, cols: u16, rows: u16, now: Instant) -> Result<Vec<ClientAction>> {
        log::info!("Client resizing to {}x{}", cols, rows);
        let packet_bytes = self.prepare_resize(cols, rows, now)?;
        self.mirror.abort_prediction();
        self.mirror.mark_dirty();
        Ok(vec![
            ClientAction::SendPacket(packet_bytes),
            ClientAction::Paint,
        ])
    }

    pub fn on_tick(&mut self, now: Instant) -> Result<Vec<ClientAction>> {
        let mut actions = Vec::new();

        // 1. KeepAlive check (every keepalive_interval)
        if now.duration_since(self.last_keepalive_sent) >= self.keepalive_interval {
            let packet_bytes = self.prepare_keepalive(now)?;
            actions.push(ClientAction::SendPacket(packet_bytes));
        }

        // 2. ARQ Retransmission check (every 100ms)
        if now.duration_since(self.last_arq_check) >= Duration::from_millis(100) {
            self.last_arq_check = now;
            let rtt_ms = self.mirror.rtt_ms();
            let rtt_limit = Duration::from_millis((rtt_ms as u64 * 2).clamp(200, 1000));
            let mut packets_to_resend = Vec::new();

            for (&seq, (packet_bytes, sent_time)) in &self.unacked_packets {
                if now.duration_since(*sent_time) >= rtt_limit {
                    let age = now.duration_since(*sent_time);
                    log::info!(
                        "[CLIENT] [TX_PACKET] seq={} ack={} type=ARQ_Retransmit wire_bytes={} age_ms={} is_resent=true",
                        seq,
                        self.ack_seq_num,
                        packet_bytes.len(),
                        age.as_millis()
                    );
                    packets_to_resend.push((packet_bytes.clone(), seq));
                }
            }

            for (packet_bytes, seq) in packets_to_resend {
                if let Some(entry) = self.unacked_packets.get_mut(&seq) {
                    entry.1 = now;
                }
                actions.push(ClientAction::SendPacket(packet_bytes));
            }
        }

        // 3. Reconnection Overlay check (every 250ms silence check)
        let silence = now.duration_since(self.last_recv_time);
        let needs_banner = silence > Duration::from_millis(5000);
        if self.is_reconnecting != needs_banner {
            self.is_reconnecting = needs_banner;
            self.mirror.set_reconnecting(needs_banner);
            actions.push(ClientAction::Paint);

            // Adaptive heartbeat throttling during outages (slowly back off up to 3 minutes)
            self.keepalive_interval = if silence < Duration::from_secs(5) {
                Duration::from_secs(2)
            } else if silence < Duration::from_secs(15) {
                Duration::from_secs(5)
            } else if silence < Duration::from_secs(60) {
                Duration::from_secs(15)
            } else if silence < Duration::from_secs(180) {
                Duration::from_secs(60)
            } else if silence < Duration::from_secs(600) {
                Duration::from_secs(120)
            } else {
                Duration::from_secs(180)
            };
        }

        // 4. Telemetry check (once per second)
        let elapsed = now.duration_since(self.last_telemetry_calc);
        if elapsed >= Duration::from_secs(1) {
            let kb_s = (self.bytes_recv_acc as f32 / 1024.0) / elapsed.as_secs_f32();
            let ratio = if self.comp_acc > 0 && self.decomp_acc > 0 {
                self.decomp_acc as f32 / self.comp_acc as f32
            } else {
                1.0
            };
            let fps = (self.paint_count_acc as f32 / elapsed.as_secs_f32()).round() as u32;
            self.mirror.record_bandwidth_compression(kb_s, ratio);
            self.mirror.record_fps(fps);

            self.bytes_recv_acc = 0;
            self.comp_acc = 0;
            self.decomp_acc = 0;
            self.paint_count_acc = 0;
            self.last_telemetry_calc = now;
            actions.push(ClientAction::Paint);
        }

        // 5. Fragment NACK check (every 40ms)
        if now.duration_since(self.last_nack_check) >= Duration::from_millis(40) {
            self.last_nack_check = now;
            let incomplete = self.codec.get_incomplete_frames();
            for (frame_seq, received_mask) in incomplete {
                let should_nack = match self.nacked_frames.get(&frame_seq) {
                    Some(&last_sent) => now.duration_since(last_sent) >= Duration::from_millis(100),
                    None => true,
                };
                if should_nack {
                    self.nacked_frames.insert(frame_seq, now);
                    let packet_bytes = self.prepare_fragment_nack(frame_seq, received_mask, now)?;
                    actions.push(ClientAction::SendPacket(packet_bytes));
                }
            }
            // Prune nacked_frames older than 2 seconds
            self.nacked_frames.retain(|&seq, &mut time| {
                seq > self.ack_seq_num && now.duration_since(time) < Duration::from_secs(2)
            });
        }

        Ok(actions)
    }

    pub fn copy_frame_if_dirty(&mut self, dest: &mut TerminalFrame) -> bool {
        if self.mirror.consume_updates(dest) {
            self.paint_count_acc += 1;
            true
        } else {
            false
        }
    }

    fn prepare_keystrokes(&mut self, keys: Vec<u8>, now: Instant) -> Result<(Vec<u8>, u64)> {
        self.seq_num += 1;
        let seq = self.seq_num;
        self.sent_packets.insert(seq, now);

        let payload = ClientPayload::Keystrokes(keys);
        let packet_bytes =
            self.codec
                .seal_client(self.session_id, seq, self.ack_seq_num, &payload)?;

        log::info!(
            "[CLIENT] [TX_PACKET] seq={} ack={} type=Keystrokes wire_bytes={} is_resent=false",
            seq,
            self.ack_seq_num,
            packet_bytes.len()
        );

        self.unacked_packets
            .insert(seq, (packet_bytes.clone(), now));
        Ok((packet_bytes, seq))
    }

    fn prepare_ack(&mut self, now: Instant) -> Result<Vec<u8>> {
        self.seq_num += 1;
        let seq = self.seq_num;
        self.sent_packets.insert(seq, now);
        self.last_ack_sent = now;

        let payload = ClientPayload::Ack;
        let packet_bytes =
            self.codec
                .seal_client(self.session_id, seq, self.ack_seq_num, &payload)?;

        log::info!(
            "[CLIENT] [TX_PACKET] seq={} ack={} type=Ack wire_bytes={} is_resent=false",
            seq,
            self.ack_seq_num,
            packet_bytes.len()
        );

        Ok(packet_bytes)
    }

    fn prepare_keepalive(&mut self, now: Instant) -> Result<Vec<u8>> {
        self.seq_num += 1;
        let seq = self.seq_num;
        self.sent_packets.insert(seq, now);
        self.last_keepalive_sent = now;

        let payload = ClientPayload::KeepAlive;
        let packet_bytes =
            self.codec
                .seal_client(self.session_id, seq, self.ack_seq_num, &payload)?;

        log::info!(
            "[CLIENT] [TX_PACKET] seq={} ack={} type=KeepAlive wire_bytes={} is_resent=false",
            seq,
            self.ack_seq_num,
            packet_bytes.len()
        );

        self.unacked_packets
            .insert(seq, (packet_bytes.clone(), now));
        Ok(packet_bytes)
    }

    fn prepare_resize(&mut self, cols: u16, rows: u16, now: Instant) -> Result<Vec<u8>> {
        self.seq_num += 1;
        let seq = self.seq_num;
        self.sent_packets.insert(seq, now);

        let payload = ClientPayload::Resize { cols, rows };
        let packet_bytes =
            self.codec
                .seal_client(self.session_id, seq, self.ack_seq_num, &payload)?;

        log::info!(
            "[CLIENT] [TX_PACKET] seq={} ack={} type=Resize cols={} rows={} wire_bytes={} is_resent=false",
            seq,
            self.ack_seq_num,
            cols,
            rows,
            packet_bytes.len()
        );

        self.unacked_packets
            .insert(seq, (packet_bytes.clone(), now));
        Ok(packet_bytes)
    }

    fn prepare_fragment_nack(
        &mut self,
        frame_seq: u64,
        received_mask: Vec<u64>,
        now: Instant,
    ) -> Result<Vec<u8>> {
        self.seq_num += 1;
        let seq = self.seq_num;
        self.sent_packets.insert(seq, now);

        let payload = ClientPayload::FragmentNack {
            frame_seq,
            received_mask: received_mask.clone(),
        };
        let packet_bytes =
            self.codec
                .seal_client(self.session_id, seq, self.ack_seq_num, &payload)?;

        log::info!(
            "[CLIENT] [TX_PACKET] seq={} ack={} type=FragmentNack frame_seq={} mask_len={} wire_bytes={} is_resent=false",
            seq,
            self.ack_seq_num,
            frame_seq,
            received_mask.len(),
            packet_bytes.len()
        );

        Ok(packet_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::codec::NullCodec;

    #[test]
    fn test_rtt_calculation() {
        let now = Instant::now();
        let codec = NullCodec::new(12345);
        let mut session = MirrorSession::new(12345, codec, 1, 80, 24, false, now);

        // 1. Feed keystrokes (seq = 1)
        let actions = session.feed_stdin(b"a", now).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, ClientAction::SendPacket(_)))
        );
        assert_eq!(session.sent_packets.len(), 1);

        // Simulate 50ms passage of time
        let later = now + Duration::from_millis(50);

        // 2. Feed server ack (acknowledging seq = 1)
        let server_payload = ServerPayload::KeepAlive;
        let ack_bytes = session.codec.seal_server(1, 1, &server_payload).unwrap();

        let _ = session.feed_packet(&ack_bytes[0], later).unwrap();

        let rtt = session.mirror.rtt_ms();
        assert!(rtt >= 45, "RTT should be at least 45ms, got {}", rtt);
        assert!(
            rtt < 150,
            "RTT should be within reasonable bound, got {}",
            rtt
        );
        assert!(session.sent_packets.is_empty());
        assert!(session.unacked_packets.is_empty());
    }

    #[test]
    fn test_packet_loss_and_late_correction() {
        let now = Instant::now();
        let codec = NullCodec::new(12345);
        let mut session = MirrorSession::new(12345, codec, 1, 80, 24, false, now);

        let make_packet = |session: &MirrorSession<NullCodec>, seq: u64| -> Vec<u8> {
            let mut pkts = session
                .codec
                .seal_server(seq, 0, &ServerPayload::KeepAlive)
                .unwrap();
            pkts.pop().unwrap()
        };

        let _ = session.feed_packet(&make_packet(&session, 1), now).unwrap();
        assert_eq!(session.expected_server_seq, 2);
        assert_eq!(session.loss_window.len(), 1);
        assert!(session.loss_window[0]);

        let _ = session.feed_packet(&make_packet(&session, 3), now).unwrap();
        assert_eq!(session.expected_server_seq, 4);
        assert_eq!(session.loss_window.len(), 3);
        assert!(!session.loss_window[1]);
        assert!(session.loss_window[2]);

        let _ = session.feed_packet(&make_packet(&session, 2), now).unwrap();
        assert_eq!(session.loss_window.len(), 3);
        assert!(session.loss_window[1]);
    }

    #[test]
    fn test_arq_retransmission_and_pruning() {
        let now = Instant::now();
        let codec = NullCodec::new(12345);
        let mut session = MirrorSession::new(12345, codec, 1, 80, 24, false, now);

        let _ = session.feed_stdin(b"a", now).unwrap();
        assert_eq!(session.unacked_packets.len(), 1);

        let actions = session.on_tick(now + Duration::from_millis(50)).unwrap();
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, ClientAction::SendPacket(_)))
        );

        let actions = session.on_tick(now + Duration::from_millis(300)).unwrap();
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, ClientAction::SendPacket(_)))
                .count(),
            1
        );

        let ack_bytes = session
            .codec
            .seal_server(1, 1, &ServerPayload::KeepAlive)
            .unwrap();
        let _ = session
            .feed_packet(&ack_bytes[0], now + Duration::from_millis(350))
            .unwrap();

        assert!(session.unacked_packets.is_empty());
    }

    #[test]
    fn test_escape_disconnect_action() {
        let now = Instant::now();
        let codec = NullCodec::new(12345);
        let mut session = MirrorSession::new(12345, codec, 1, 80, 24, false, now);

        let actions = session.feed_stdin(b"~.", now).unwrap();
        assert!(actions.contains(&ClientAction::Disconnect));
    }

    #[test]
    fn test_escape_overlay_action() {
        let now = Instant::now();
        let codec = NullCodec::new(12345);
        let mut session = MirrorSession::new(12345, codec, 1, 80, 24, false, now);

        let actions = session.feed_stdin(b"~o", now).unwrap();
        assert!(actions.contains(&ClientAction::Paint));
        assert!(session.mirror.read_inner().frame.overlay_enabled);
    }
}
