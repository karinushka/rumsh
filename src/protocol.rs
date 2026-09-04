pub mod codec;
pub mod grid;
pub use grid::*;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ClientPayload {
    Handshake {
        client_version: u32,
        cols: u16,
        rows: u16,
    },
    Keystrokes(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    KeepAlive,
    Ack,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClientPacket {
    pub session_id: u64,
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub payload: ClientPayload,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ServerPayload {
    HandshakeAck { session_id: u64 },
    Frame(FrameUpdate),
    KeepAlive,
    Shutdown,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerPacket {
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub payload: ServerPayload,
}

pub const TARGET_MTU: usize = 1200;
pub const FRAGMENT_PAYLOAD_SIZE: usize = 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedClientPacket {
    pub session_id: u64,
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedServerPacket {
    pub seq_num: u64,
    pub ack_seq_num: u64,
    pub frag_idx: u16,
    pub total_frags: u16,
    pub ciphertext: Vec<u8>,
}

// Optimized Varint Serialization Helpers
pub fn serialize<T: ?Sized + serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    let config = bincode::config::standard().with_variable_int_encoding();
    bincode::serde::encode_to_vec(value, config)
}

pub fn deserialize<'a, T: serde::Deserialize<'a>>(
    bytes: &'a [u8],
) -> Result<T, bincode::error::DecodeError> {
    let config = bincode::config::standard().with_variable_int_encoding();
    bincode::serde::borrow_decode_from_slice(bytes, config).map(|(val, _)| val)
}

pub fn serialize_compressed<T: ?Sized + serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut plain = serialize(value)?;

    if plain.len() < 256 {
        plain.insert(0, 0x00); // Raw Bincode flag prepended in-place
        Ok(plain)
    } else {
        let mut compressed = lz4_flex::compress_prepend_size(&plain);
        compressed.insert(0, 0x01); // LZ4 Compressed flag prepended in-place
        Ok(compressed)
    }
}

pub fn deserialize_compressed_get_sizes<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<(T, usize, usize), anyhow::Error> {
    if bytes.is_empty() {
        return Err(anyhow::anyhow!("Empty payload"));
    }
    let flag = bytes[0];
    let payload = &bytes[1..];

    match flag {
        0x00 => {
            let decompressed_len = payload.len();
            let val = deserialize(payload)?;
            Ok((val, bytes.len(), decompressed_len))
        }
        0x01 => {
            let decompressed = lz4_flex::decompress_size_prepended(payload)?;
            let decompressed_len = decompressed.len();
            let val = deserialize(&decompressed)?;
            Ok((val, bytes.len(), decompressed_len))
        }
        _ => Err(anyhow::anyhow!("Unknown compression flag: {}", flag)),
    }
}

pub fn deserialize_compressed<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, anyhow::Error> {
    deserialize_compressed_get_sizes(bytes).map(|(val, _, _)| val)
}
