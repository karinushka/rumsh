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
    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<u8>>;
    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedServerPacket, ServerPayload, CodecStats)>;
}

#[derive(Clone)]
pub struct ChaChaCodec {
    crypto: Arc<CryptoManager>,
    handshake_crypto: Arc<CryptoManager>,
    session_id: u64,
}

impl ChaChaCodec {
    pub fn new(key: &[u8; 32], session_id: u64) -> Self {
        Self {
            crypto: Arc::new(CryptoManager::new(key, session_id)),
            handshake_crypto: Arc::new(CryptoManager::new(key, 0)),
            session_id,
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

    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<u8>> {
        let payload_bytes = serialize_compressed(payload)?;
        let ciphertext = self.crypto.encrypt(seq, &payload_bytes)?;
        let packet = EncryptedServerPacket {
            seq_num: seq,
            ack_seq_num: ack,
            ciphertext,
        };
        Ok(serialize(&packet)?)
    }

    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedServerPacket, ServerPayload, CodecStats)> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedServerPacket>(bytes)?;
        let payload_bytes = self.crypto.decrypt(wire_packet.seq_num, &wire_packet.ciphertext)?;
        let (payload, comp_len, decomp_len) =
            deserialize_compressed_get_sizes::<ServerPayload>(&payload_bytes)?;
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
}

#[derive(Clone, Default)]
pub struct NullCodec {
    session_id: u64,
}

impl NullCodec {
    pub fn new(session_id: u64) -> Self {
        Self { session_id }
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

    fn seal_server(&self, seq: u64, ack: u64, payload: &ServerPayload) -> Result<Vec<u8>> {
        let payload_bytes = serialize(payload)?;
        let packet = EncryptedServerPacket {
            seq_num: seq,
            ack_seq_num: ack,
            ciphertext: payload_bytes,
        };
        Ok(serialize(&packet)?)
    }

    fn open_server(
        &self,
        bytes: &[u8],
    ) -> Result<(EncryptedServerPacket, ServerPayload, CodecStats)> {
        let wire_len = bytes.len();
        let wire_packet = deserialize::<EncryptedServerPacket>(bytes)?;
        let comp_len = wire_packet.ciphertext.len();
        let payload = deserialize::<ServerPayload>(&wire_packet.ciphertext)?;
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
        let (pkt_srv, opened_server, stats_srv) = codec.open_server(&sealed_server).unwrap();
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
        let (pkt_srv, opened_server, stats_srv) = codec.open_server(&sealed_server).unwrap();
        assert_eq!(pkt_srv.seq_num, 1);
        assert!(matches!(opened_server, ServerPayload::KeepAlive));
        assert_eq!(stats_srv.comp_len, stats_srv.decomp_len);
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
