use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey};

pub const FADEDBEE: &[u8; 4] = &[0xFA, 0xDE, 0xDB, 0xEE];
pub const TURNSTILE: &[u8; 9] = b"turnstile";
pub const MAX_PLAINTEXT_CHUNK: usize = 10; // 1024*1024;
pub const MAX_CIPHERTEXT_CHUNK: usize = 2*1024*1024;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn version_bytes() -> [u8; 3] {
    let parts: Vec<&str> = VERSION.split(".").collect(); // TODO: can we get rid of the Vec?
    [
        parts[0].parse().expect("a number"),
        parts[1].parse().expect("a number"),
        parts[2].parse().expect("a number"),
    ]
}

/// Produce a unique nonce for each chunk.
pub fn calculate_chunk_nonce(initial_nonce: &Nonce, chunk_num: u64) -> Nonce {
    let chunk_num_be_bytes = chunk_num.to_be_bytes();
    let mut chunk_nonce = Nonce(initial_nonce.0);
    for (i, byte) in chunk_num_be_bytes.iter().enumerate() {
        chunk_nonce.0[i] ^= byte;
        if i >= 8 {
            unreachable!("there are only 8 bytes in a u64");
        }
    }
    chunk_nonce
}

pub type PrivateKeyLookup = Box<dyn Fn(PublicKey) -> SecretKey>;

pub fn key_path(keydir: &str, b62_pkey: &str) -> String {
    format!("{keydir}/{b62_pkey}.secret") // FIXME: use a Path
}