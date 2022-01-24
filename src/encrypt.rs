use std::io::{Read, Write};
use sodiumoxide::crypto::box_::{self, PublicKey, Nonce, SecretKey};

use super::{base62, common::*};


pub fn encrypt(target_public_key: &str, input: &mut dyn Read,
                                                    output: &mut dyn Write) -> anyhow::Result<()> {
    let target_pkey = PublicKey(base62::decode(target_public_key)?);
    let (source_pkey, source_skey) = box_::gen_keypair();
    let initial_nonce = box_::gen_nonce();
    _encrypt(&target_pkey, &source_pkey, &source_skey, &initial_nonce, input, output)
}

/// Inner encryption routine, capable of deterministic (insecure) encryption for repeatable testing.
pub fn _encrypt(target_pkey: &PublicKey, source_pkey: &PublicKey, source_skey: &SecretKey,
        initial_nonce: &Nonce, input: &mut dyn Read, output: &mut dyn Write) -> anyhow::Result<()> {
    let symkey = box_::precompute(&target_pkey, &source_skey);

    write_header(source_pkey, target_pkey, initial_nonce, output)?;

    assert!(MAX_CIPHERTEXT_CHUNK <= u16::MAX as usize); 

    let mut buf = [0; MAX_PLAINTEXT_CHUNK];
    for chunk_num in 0u64.. {
        match input.read(&mut buf)? {
            0 => break,
            n => {
                let chunk_nonce = calculate_chunk_nonce(&initial_nonce, chunk_num);
                let ciphertext = box_::seal_precomputed(&buf[..n], &chunk_nonce, &symkey);
                assert!(ciphertext.len() <= MAX_CIPHERTEXT_CHUNK); 
                output.write_all(&(ciphertext.len() as u16).to_be_bytes())?;
                output.write_all(&ciphertext)?;
            }
            // TODO: should we trap "if e.kind() == ErrorKind::Interrupted" and continue?
        }
    }
    output.write_all(&0u16.to_be_bytes())?; // 0x0000 signifies end
    Ok(())
}


fn write_header(source_pkey: &PublicKey, target_pkey: &PublicKey, initial_nonce: &Nonce,
    output: &mut dyn Write) -> anyhow::Result<()> {
    output.write_all(FADEDBEE)?;
    output.write_all(TURNSTILE)?;
    output.write_all(&version_bytes())?;
    output.write_all(&source_pkey.0)?;
    output.write_all(&target_pkey.0)?;
    output.write_all(&initial_nonce.0)?;
    Ok(())
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_header() {
        let mut out = Vec::<u8>::new();
        write_header(
            &PublicKey([1u8; 32]),
            &PublicKey([2u8; 32]),
            &Nonce([3u8; 24]),
            &mut out
        ).unwrap();
        assert_eq!(out.len(), 104);
    }
}