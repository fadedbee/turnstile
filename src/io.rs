use std::{io::{stdin, stdout, Read, Write}, fs::{File, create_dir_all}, path::Path};
use anyhow::Context;
use shellexpand;

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
        Ok(Box::new(File::open(&filename)
            .context(format!("unable to open '{filename}' for output"))?))
    } else {
        Ok(Box::new(stdout()))
    }
}

pub fn open_or_create_key_directory(path: &str) -> anyhow::Result<()> {
    create_dir_all(&path)
        .context(format!("unable to open/create {path}'"))
}