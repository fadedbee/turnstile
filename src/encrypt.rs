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

    let mut buf = [0; MAX_PLAINTEXT_CHUNK];
    for chunk_num in 0u64.. {
        match input.read(&mut buf)? {
            0 => break,
            n => {
                let chunk_nonce = calculate_chunk_nonce(&initial_nonce, chunk_num);
                let ciphertext = box_::seal_precomputed(&buf[..n], &chunk_nonce, &symkey);
                output.write_all(&(ciphertext.len() as u64).to_be_bytes())?;
                output.write_all(&ciphertext)?;
            }
            // TODO: should we trap "if e.kind() == ErrorKind::Interrupted" and continue?
        }
    }
    output.write_all(&0u64.to_be_bytes())?; // 0xFFFFFFFFFFFFFFFF signifies end
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

    #[test]
    fn test_box() {
        let (ourpk, oursk) = box_::gen_keypair();
        let (theirpk, theirsk) = box_::gen_keypair();
        let our_precomputed_key = box_::precompute(&theirpk, &oursk);
        let nonce = box_::gen_nonce();
        let plaintext = b"plaintext";
        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &our_precomputed_key);
        // this will be identical to our_precomputed_key
        let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
        let their_plaintext = box_::open_precomputed(&ciphertext, &nonce,
                                                    &their_precomputed_key).unwrap();
        assert!(plaintext == &their_plaintext[..]); 

        println!("ourpk {ourpk:?}, oursk {oursk:?}");
        println!("theirpk {theirpk:?}, theirsk {theirsk:?}");
        println!("our_precomputed_key {our_precomputed_key:?}");
        println!("their_precomputed_key {their_precomputed_key:?}");
        println!("plainetxt {plaintext:?}");
        println!("ciphertext {ciphertext:?}");
        println!("their_plaintext {their_plaintext:?}");
    }
    #[test]
    fn test_box_integrity() {
        let (ourpk, oursk) = box_::gen_keypair();
        let (theirpk, theirsk) = box_::gen_keypair();
        let our_precomputed_key = box_::precompute(&theirpk, &oursk);
        let nonce = box_::gen_nonce();
        let plaintext = b"plaintext";
        let mut ciphertext = box_::seal_precomputed(plaintext, &nonce, &our_precomputed_key);
        ciphertext[21] = 42; // corruption

        // this will be identical to our_precomputed_key
        let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
        let result = box_::open_precomputed(&ciphertext, &nonce,
                                                    &their_precomputed_key);
        assert_eq!(result, Err(()));                    
    }
}