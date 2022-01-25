use std::{io::{stdin, stdout, Read, Write}, fs::{File, create_dir_all, self, OpenOptions}};
use anyhow::Context;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

use crate::base62;

/// Open the program's input file, or stdin if there is no input file.
/// Note: stdin on Windows only provides utf8.
pub fn open_input(input: Option<String>) -> anyhow::Result<Box<dyn Read>> {
    if let Some(filename) = input {
        Ok(Box::new(File::open(&filename)
            .context(format!("unable to open '{filename}' for input"))?))
    } else {
        Ok(Box::new(stdin()))
    }
}

/// Open the program's output file, or stdout if there is no input file.
/// Note: stdout on Windows only accepts utf8.
pub fn open_output(output: Option<String>) -> anyhow::Result<Box<dyn Write>> {
    if let Some(filename) = output {
        Ok(Box::new(
            OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filename)
            .context(format!("unable to open '{filename}' for output"))?
        ))
    } else {
        Ok(Box::new(stdout()))
    }
}

pub fn open_or_create_key_directory(path: &str) -> anyhow::Result<()> {
    create_dir_all(&path)
        .context(format!("unable to open/create {path}'"))
}

pub fn key_path(keydir: &str, b62_pkey: &str) -> String {
    format!("{keydir}/{b62_pkey}.secret") // FIXME: use a Path
}

/// Read secret key from file.
pub fn disk_lookup(keydir: &str, target_pkey: &PublicKey) -> anyhow::Result<SecretKey> {
    let path = key_path(keydir, &base62::encode(&target_pkey.0));
    let b62_skey = fs::read_to_string(path)?;
    Ok(SecretKey(base62::decode(&b62_skey)?))
}
