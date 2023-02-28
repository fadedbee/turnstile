use std::{io::{Read, Write}, mem::size_of};
use sodiumoxide::crypto::box_::{self, PublicKey, Nonce, SecretKey};

use crate::io::{disk_lookup};

use super::common::*;

pub fn decrypt(keydir: &str, input: &mut dyn Read, output: &mut dyn Write) -> anyhow::Result<()> {
    // disk_lookup needs to be boxed, as it can be replaced with a (boxed) capturing closure
    _decrypt(keydir, input, Box::new(disk_lookup), output)
}

/// Inner decryption routine, for repeatable testing.
pub fn _decrypt(keydir: &str, input: &mut dyn Read,
        lookup: Box<dyn Fn(&str, &PublicKey) -> anyhow::Result<SecretKey>>,
        output: &mut dyn Write) -> anyhow::Result<()> {
    let (source_pkey, target_pkey, initial_nonce) = read_header(input)?;

    let target_skey = lookup(keydir, &target_pkey)?;

    let symkey = box_::precompute(&source_pkey, &target_skey);

    let mut len_buf = [0u8; size_of::<u16>()];
    for chunk_num in 0u64.. {
        let chunk_nonce = calculate_chunk_nonce(&initial_nonce, chunk_num);

        // read length of chunk
        input.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf);
        if len == 0u16 {
            return Ok(());
        }
        if len > MAX_CIPHERTEXT_CHUNK as u16 {
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

pub fn read_header(input: &mut dyn Read) -> anyhow::Result<(PublicKey, PublicKey, Nonce)> {
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
    if buf[13..15] != version_bytes()[0..2] { // check first two bytes haven't changed
        return Err(anyhow::anyhow!("invalid version"));
    }

    // read keys and intital nonce
    let mut source_pkey_buf = [0u8; 32];
    input.read_exact(&mut source_pkey_buf)?;
    let source_pkey = PublicKey(source_pkey_buf);

    let mut target_pkey_buf = [0u8; 32];
    input.read_exact(&mut target_pkey_buf)?;
    let target_pkey = PublicKey(target_pkey_buf);

    let mut initial_nonce_buf = [0u8; 24];
    input.read_exact(&mut initial_nonce_buf)?;
    let initial_nonce = Nonce(initial_nonce_buf);

    Ok((source_pkey, target_pkey, initial_nonce))
}