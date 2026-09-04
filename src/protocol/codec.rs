use crate::crypto::CryptoManager;
use crate::protocol::{
    ClientPayload, EncryptedClientPacket, EncryptedServerPacket, ServerPayload, deserialize,
    deserialize_compressed_get_sizes, serialize, serialize_compressed,
};
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CodecStats {
    /// Total bytes received on the wire (including encryption header/mac and framing).
    pub wire_len: usize,
    /// Size of the compressed payload in bytes (before decompression).
    pub comp_len: usize,
    /// Size of the decompressed payload in bytes (after decompression).
    pub decomp_len: usize,
}

use crate::protocol::FRAGMENT_PAYLOAD_SIZE;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

pub trait PacketCodec: Send + Sync + 'static {
    fn seal_client(
        &self,
        session_id: u64,
        seq: u64,
        ack: u64,
        payload: &ClientPayload,
    ) -> Result<Vec<u8>>;
    fn open_client(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedClientPacket, ClientPayload, CodecStats)>;
    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<Vec<u8>>>;
    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<Option<(EncryptedServerPacket, ServerPayload, CodecStats)>>;
}

type FrameFragments = (u16, usize, HashMap<u16, Vec<u8>>);

#[derive(Default)]
struct FragmentBuffer {
    /// seq_num -> (total_frags, wire_len_acc, fragments_by_index)
    frames: BTreeMap<u64, FrameFragments>,
}

impl FragmentBuffer {
    fn insert(
        &mut self,
        packet: EncryptedServerPacket,
        wire_len: usize,
    ) -> Option<(EncryptedServerPacket, Vec<u8>, usize)> {
        if packet.total_frags <= 1 {
            // Unfragmented packet
            let ciphertext = packet.ciphertext.clone();
            return Some((packet, ciphertext, wire_len));
        }

        let seq = packet.seq_num;
        let entry = self
            .frames
            .entry(seq)
            .or_insert_with(|| (packet.total_frags, 0, HashMap::new()));
        entry.1 += wire_len;
        entry.2.insert(packet.frag_idx, packet.ciphertext);

        if entry.2.len() == entry.0 as usize {
            // Frame complete! Reassemble ciphertext in fragment order
            let (total_frags, total_wire_len, mut frags) = self.frames.remove(&seq).unwrap();
            let mut full_ciphertext = Vec::new();
            for idx in 0..total_frags {
                if let Some(mut piece) = frags.remove(&idx) {
                    full_ciphertext.append(&mut piece);
                }
            }

            // Prune any stale frames older than seq - 4
            while let Some((&old_seq, _)) = self.frames.iter().next() {
                if old_seq < seq.saturating_sub(4) {
                    self.frames.remove(&old_seq);
                } else {
                    break;
                }
            }

            let completed_packet = EncryptedServerPacket {
                seq_num: packet.seq_num,
                ack_seq_num: packet.ack_seq_num,
                frag_idx: 0,
                total_frags: 1,
                ciphertext: Vec::new(),
            };
            Some((completed_packet, full_ciphertext, total_wire_len))
        } else {
            // Partial fragment buffered
            // Prune stale frames if map gets too large
            if self.frames.len() > 10 {
                let min_seq = *self.frames.keys().next().unwrap();
                self.frames.remove(&min_seq);
            }
            None
        }
    }
}

#[derive(Clone)]
pub struct ChaChaCodec {
    crypto: Arc<CryptoManager>,
    handshake_crypto: Arc<CryptoManager>,
    session_id: u64,
    fragment_buffer: Arc<Mutex<FragmentBuffer>>,
}

impl ChaChaCodec {
    pub fn new(key: &[u8; 32], session_id: u64) -> Self {
        Self {
            crypto: Arc::new(CryptoManager::new(key, session_id)),
            handshake_crypto: Arc::new(CryptoManager::new(key, 0)),
            session_id,
            fragment_buffer: Arc::new(Mutex::new(FragmentBuffer::default())),
        }
    }
}

impl PacketCodec for ChaChaCodec {
    fn seal_client(
        &self,
        session_id: u64,
        seq: u64,
        ack: u64,
        payload: &ClientPayload,
    ) -> Result<Vec<u8>> {
        let payload_bytes = serialize(payload)?;
        let crypto_to_use = if session_id == 0 {
            &self.handshake_crypto
        } else {
            &self.crypto
        };
        let ciphertext = crypto_to_use.encrypt(seq, &payload_bytes)?;
        let packet = EncryptedClientPacket {
            session_id,
            seq_num: seq,
            ack_seq_num: ack,
            ciphertext,
        };
        Ok(serialize(&packet)?)
    }

    fn open_client(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedClientPacket, ClientPayload, CodecStats)> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedClientPacket>(bytes)?;
        let crypto_to_use = if wire_packet.session_id == 0 {
            &self.handshake_crypto
        } else if wire_packet.session_id == self.session_id {
            &self.crypto
        } else {
            return Err(anyhow::anyhow!(
                "Session ID mismatch: expected {} or 0, got {}",
                self.session_id,
                wire_packet.session_id
            ));
        };
        let payload_bytes = crypto_to_use.decrypt(wire_packet.seq_num, &wire_packet.ciphertext)?;
        let comp_len = payload_bytes.len();
        let payload = deserialize::<ClientPayload>(&payload_bytes)?;
        let decomp_len = comp_len;
        Ok((
            wire_packet,
            payload,
            CodecStats {
                wire_len,
                comp_len,
                decomp_len,
            },
        ))
    }

    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<Vec<u8>>> {
        let payload_bytes = serialize_compressed(payload)?;
        let ciphertext = self.crypto.encrypt(seq, &payload_bytes)?;

        if ciphertext.len() <= FRAGMENT_PAYLOAD_SIZE {
            let packet = EncryptedServerPacket {
                seq_num: seq,
                ack_seq_num: ack,
                frag_idx: 0,
                total_frags: 1,
                ciphertext,
            };
            return Ok(vec![serialize(&packet)?]);
        }

        let chunks: Vec<&[u8]> = ciphertext.chunks(FRAGMENT_PAYLOAD_SIZE).collect();
        let total_frags = chunks.len() as u16;
        let mut packets = Vec::with_capacity(chunks.len());
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let packet = EncryptedServerPacket {
                seq_num: seq,
                ack_seq_num: ack,
                frag_idx: idx as u16,
                total_frags,
                ciphertext: chunk.to_vec(),
            };
            packets.push(serialize(&packet)?);
        }
        Ok(packets)
    }

    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<Option<(EncryptedServerPacket, ServerPayload, CodecStats)>> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedServerPacket>(bytes)?;

        let (completed_packet, full_ciphertext, total_wire_len) = {
            let mut buf = self.fragment_buffer.lock().unwrap();
            match buf.insert(wire_packet, wire_len) {
                Some(res) => res,
                None => return Ok(None),
            }
        };

        let payload_bytes = self
            .crypto
            .decrypt(completed_packet.seq_num, &full_ciphertext)?;
        let (payload, comp_len, decomp_len) =
            deserialize_compressed_get_sizes::<ServerPayload>(&payload_bytes)?;
        Ok(Some((
            completed_packet,
            payload,
            CodecStats {
                wire_len: total_wire_len,
                comp_len,
                decomp_len,
            },
        )))
    }
}

#[derive(Clone, Default)]
pub struct NullCodec {
    session_id: u64,
    fragment_buffer: Arc<Mutex<FragmentBuffer>>,
}

impl NullCodec {
    pub fn new(session_id: u64) -> Self {
        Self {
            session_id,
            fragment_buffer: Arc::new(Mutex::new(FragmentBuffer::default())),
        }
    }
}

impl PacketCodec for NullCodec {
    fn seal_client(
        &self,
        session_id: u64,
        seq: u64,
        ack: u64,
        payload: &ClientPayload,
    ) -> Result<Vec<u8>> {
        let payload_bytes = serialize(payload)?;
        let packet = EncryptedClientPacket {
            session_id,
            seq_num: seq,
            ack_seq_num: ack,
            ciphertext: payload_bytes,
        };
        Ok(serialize(&packet)?)
    }

    fn open_client(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedClientPacket, ClientPayload, CodecStats)> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedClientPacket>(bytes)?;
        if wire_packet.session_id != 0 && wire_packet.session_id != self.session_id {
            return Err(anyhow::anyhow!("Session ID mismatch"));
        }
        let comp_len = wire_packet.ciphertext.len();
        let payload = deserialize::<ClientPayload>(&wire_packet.ciphertext)?;
        let decomp_len = comp_len;
        Ok((
            wire_packet,
            payload,
            CodecStats {
                wire_len,
                comp_len,
                decomp_len,
            },
        ))
    }

    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<Vec<u8>>> {
        let payload_bytes = serialize(payload)?;

        if payload_bytes.len() <= FRAGMENT_PAYLOAD_SIZE {
            let packet = EncryptedServerPacket {
                seq_num: seq,
                ack_seq_num: ack,
                frag_idx: 0,
                total_frags: 1,
                ciphertext: payload_bytes,
            };
            return Ok(vec![serialize(&packet)?]);
        }

        let chunks: Vec<&[u8]> = payload_bytes.chunks(FRAGMENT_PAYLOAD_SIZE).collect();
        let total_frags = chunks.len() as u16;
        let mut packets = Vec::with_capacity(chunks.len());
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let packet = EncryptedServerPacket {
                seq_num: seq,
                ack_seq_num: ack,
                frag_idx: idx as u16,
                total_frags,
                ciphertext: chunk.to_vec(),
            };
            packets.push(serialize(&packet)?);
        }
        Ok(packets)
    }

    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<Option<(EncryptedServerPacket, ServerPayload, CodecStats)>> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedServerPacket>(bytes)?;

        let (completed_packet, full_ciphertext, total_wire_len) = {
            let mut buf = self.fragment_buffer.lock().unwrap();
            match buf.insert(wire_packet, wire_len) {
                Some(res) => res,
                None => return Ok(None),
            }
        };

        let comp_len = full_ciphertext.len();
        let payload = deserialize::<ServerPayload>(&full_ciphertext)?;
        let decomp_len = comp_len;
        Ok(Some((
            completed_packet,
            payload,
            CodecStats {
                wire_len: total_wire_len,
                comp_len,
                decomp_len,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_codec_roundtrip() {
        let codec = ChaChaCodec::new(&[1u8; 32], 12345);
        let client_payload = ClientPayload::Keystrokes(b"hello".to_vec());
        let sealed_client = codec.seal_client(12345, 1, 0, &client_payload).unwrap();
        let (pkt, opened_client, stats) = codec.open_client(&sealed_client).unwrap();
        assert_eq!(pkt.seq_num, 1);
        assert_eq!(opened_client, client_payload);
        assert!(stats.wire_len > 0);

        let server_payload = ServerPayload::KeepAlive;
        let sealed_server = codec.seal_server(1, 1, &server_payload).unwrap();
        assert_eq!(sealed_server.len(), 1);
        let (pkt_srv, opened_server, stats_srv) =
            codec.open_server(&sealed_server[0]).unwrap().unwrap();
        assert_eq!(pkt_srv.seq_num, 1);
        assert!(matches!(opened_server, ServerPayload::KeepAlive));
        assert!(stats_srv.wire_len > 0);
    }

    #[test]
    fn test_null_codec_roundtrip() {
        let codec = NullCodec::new(12345);
        let client_payload = ClientPayload::Keystrokes(b"hello".to_vec());
        let sealed_client = codec.seal_client(12345, 1, 0, &client_payload).unwrap();
        let (pkt, opened_client, stats) = codec.open_client(&sealed_client).unwrap();
        assert_eq!(pkt.seq_num, 1);
        assert_eq!(opened_client, client_payload);
        assert_eq!(stats.comp_len, stats.decomp_len);

        let server_payload = ServerPayload::KeepAlive;
        let sealed_server = codec.seal_server(1, 1, &server_payload).unwrap();
        assert_eq!(sealed_server.len(), 1);
        let (pkt_srv, opened_server, stats_srv) =
            codec.open_server(&sealed_server[0]).unwrap().unwrap();
        assert_eq!(pkt_srv.seq_num, 1);
        assert!(matches!(opened_server, ServerPayload::KeepAlive));
        assert_eq!(stats_srv.comp_len, stats_srv.decomp_len);
    }

    #[test]
    fn test_fragmentation_roundtrip() {
        use crate::protocol::grid::{CompactGrapheme, GridState, LocalCellData, RgbColorUpdate};
        let codec = ChaChaCodec::new(&[2u8; 32], 9999);

        // Create a large FrameUpdate that exceeds FRAGMENT_PAYLOAD_SIZE (1024 bytes)
        let large_grid = GridState {
            cols: 80,
            rows: 50,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            cells: (0..(80 * 50))
                .map(|i| LocalCellData {
                    graphemes: CompactGrapheme::new(&format!("c{}", i % 100)),
                    fg: Some(RgbColorUpdate {
                        r: (i % 255) as u8,
                        g: ((i * 3) % 255) as u8,
                        b: ((i * 5) % 255) as u8,
                    }),
                    bg: Some(RgbColorUpdate {
                        r: ((i * 7) % 255) as u8,
                        g: ((i * 11) % 255) as u8,
                        b: ((i * 13) % 255) as u8,
                    }),
                    style_flags: (i % 4) as u8,
                })
                .collect(),
            row_wrapped: vec![false; 50],
        };
        let update = large_grid.diff_from(None, 0, true);
        let payload = ServerPayload::Frame(update);

        let fragments = codec.seal_server(42, 10, &payload).unwrap();
        assert!(
            fragments.len() > 1,
            "Large payload should be split into multiple fragments"
        );

        // Feed fragments in reverse order to test out-of-order fragment reassembly
        let mut final_result = None;
        for frag in fragments.iter().rev() {
            let res = codec.open_server(frag).unwrap();
            if res.is_some() {
                final_result = res;
            }
        }

        assert!(
            final_result.is_some(),
            "All fragments delivered should produce complete payload"
        );
        let (pkt, opened_payload, stats) = final_result.unwrap();
        assert_eq!(pkt.seq_num, 42);
        assert_eq!(pkt.ack_seq_num, 10);
        assert!(matches!(opened_payload, ServerPayload::Frame(_)));
        assert!(stats.wire_len > 1024);
    }

    #[test]
    fn test_chacha_codec_tamper_rejection() {
        let codec = ChaChaCodec::new(&[1u8; 32], 12345);
        let client_payload = ClientPayload::Keystrokes(b"hello".to_vec());
        let mut sealed_client = codec.seal_client(12345, 1, 0, &client_payload).unwrap();
        let len = sealed_client.len();
        sealed_client[len - 1] ^= 0xff;
        assert!(codec.open_client(&sealed_client).is_err());
    }
}
