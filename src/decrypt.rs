use std::{io::{Read, Write}, fs};
use sodiumoxide::crypto::box_::{self, PublicKey, Nonce, SecretKey};

use super::{base62, common::*};

pub fn decrypt(keydir: &str, input: &mut dyn Read, output: &mut dyn Write) -> anyhow::Result<()> {
    let (source_pkey, target_pkey, initial_nonce) = read_header(input)?;

    // read secret key from file
    let path = key_path(keydir, &base62::encode(&target_pkey.0));
    let b62_skey = fs::read_to_string(path)?;
    let target_skey = SecretKey(base62::decode(&b62_skey)?);

    _decrypt(&source_pkey, &target_skey, &initial_nonce, input, output)
}

/// Inner decryption routine, for repeatable testing.
fn _decrypt(source_pkey: &PublicKey, target_skey: &SecretKey, initial_nonce: &Nonce,
                            input: &mut dyn Read, output: &mut dyn Write) -> anyhow::Result<()> {

    let symkey = box_::precompute(&source_pkey, &target_skey);

    let mut len_buf = [0u8; 8];
    for chunk_num in 0u64.. {
        eprintln!("chunk_num {chunk_num}");
        let chunk_nonce = calculate_chunk_nonce(initial_nonce, chunk_num);

        // read length of chunk
        input.read_exact(&mut len_buf)?;
        let len = u64::from_be_bytes(len_buf);
        eprintln!("len {len}");
        if len == 0u64 {
            return Ok(());
        }
        if len > MAX_CIPHERTEXT_CHUNK as u64 {
            return Err(anyhow::anyhow!("chunk size > MAX_CIPHERTEXT_CHUNK"));
        }

        // read chunk
        let mut buf = vec![0u8; len as usize];
        input.read_exact(&mut buf)?;

        // decipher
        let result = box_::open_precomputed(&buf, &chunk_nonce,&symkey);
        if let Ok(plaintext) = result {
            output.write_all(&plaintext)?;
        } else {
            return Err(anyhow::anyhow!("bad ciphertext"));
        }
    }
    unreachable!("loop never exits");
}

fn read_header(input: &mut dyn Read) -> anyhow::Result<(PublicKey, PublicKey, Nonce)> {
    // read and check magic and version
    let mut buf = [0u8; 16];
    input.read_exact(&mut buf)?;
    if &buf[..4] != FADEDBEE {
        return Err(anyhow::anyhow!("invalid magic"));
    }
    if &buf[4..13] != TURNSTILE {
        return Err(anyhow::anyhow!("invalid protocol"));
    }
    // FIXME: change this for a more sophisticated check, after the first version is released
    if buf[13..16] != version_bytes() {
        return Err(anyhow::anyhow!("invalid version"));
    }
    eprintln!("a");

    // read keys and intital nonce
    let mut source_pkey_buf = [0u8; 32];
    input.read_exact(&mut source_pkey_buf)?;
    let source_pkey = PublicKey(source_pkey_buf);
    eprintln!("b");
    let mut target_pkey_buf = [0u8; 32];
    input.read_exact(&mut target_pkey_buf)?;
    let target_pkey = PublicKey(target_pkey_buf);
    eprintln!("c");
    let mut initial_nonce_buf = [0u8; 24];
    input.read_exact(&mut initial_nonce_buf)?;
    let initial_nonce = Nonce(initial_nonce_buf);
    eprintln!("d");

    Ok((source_pkey, target_pkey, initial_nonce))
}