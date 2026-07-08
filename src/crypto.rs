use anyhow::{Result, anyhow};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

pub struct CryptoManager {
    cipher: ChaCha20Poly1305,
    salt: [u8; 4],
}

impl CryptoManager {
    pub fn new(key_bytes: &[u8; 32], session_id: u64) -> Self {
        let key = Key::from_slice(key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        let session_bytes = session_id.to_be_bytes();
        let salt = [
            session_bytes[0],
            session_bytes[1],
            session_bytes[2],
            session_bytes[3],
        ];

        Self { cipher, salt }
    }

    fn make_nonce(&self, seq_num: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..4].copy_from_slice(&self.salt);
        nonce_bytes[4..].copy_from_slice(&seq_num.to_be_bytes());
        Nonce::from(nonce_bytes)
    }

    pub fn encrypt(&self, seq_num: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("Encryption error: {:?}", e))
    }

    pub fn decrypt(&self, seq_num: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.make_nonce(seq_num);
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption error: {:?}", e))
    }
}
