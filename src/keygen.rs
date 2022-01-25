use std::fs;

use sodiumoxide::crypto::box_;
use anyhow::{self, Context};

use crate::io::key_path;

use super::base62;

pub fn keygen(keydir: &str) -> anyhow::Result<()> {
    let (target_pkey, target_skey ) = box_::gen_keypair();
    let b62_pkey = base62::encode(&target_pkey.0);
    let b62_skey = base62::encode(&target_skey.0);
    let path = key_path(keydir, &b62_pkey);

    fs::write(&path, b62_skey).context(format!("unable to open '{path}' for writing a key"))?;
    Ok(())
}