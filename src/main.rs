use clap::{AppSettings, Parser, Subcommand};
use anyhow;

mod common;
mod io;
mod base62;
mod encrypt;
mod decrypt;
mod keygen;
mod test;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(global_setting(AppSettings::PropagateVersion))]
#[clap(global_setting(AppSettings::UseLongFormatForHelpSubcommand))]
struct Cli {
    #[clap(short, long, default_value_t = String::from("~/.turnstile"))]
    key_directory: String,
    /// Input filename for encryption and decryption, defaults to stdin
    #[clap(short, long)]
    input: Option<String>,
    /// Output filename for encryption and decryption, defaults to stdout
    /// or <KEY_DIRECTORY>/.<PUBLIC_KEY>.secret for keygen
    #[clap(short, long)]
    output: Option<String>,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt with the given public key
    Encrypt {
        public_key: String,
    },
    /// Decrypt with a secret key
    Decrypt,
    /// Generate a KeyPair
    Keygen,
}

fn main() -> anyhow::Result<(), anyhow::Error> {
    let cli = Cli::parse();

    let mut boxed_input = io::open_input(cli.input)?;
    let input = boxed_input.as_mut();
    let mut boxed_output = io::open_output(cli.output)?;
    let output = boxed_output.as_mut();

    let keydir = shellexpand::tilde(&cli.key_directory);
    
    // encryption does not use the keydir, so it would be odd for it to create it
    match cli.command {
        Commands::Encrypt{public_key: _} => (),
        _ => io::open_or_create_key_directory(&keydir)?,
    };

    match cli.command {
        Commands::Encrypt { public_key } => encrypt::encrypt(&public_key, input, output)?,
        Commands::Decrypt => decrypt::decrypt(&keydir, input, output)?,
        Commands::Keygen => keygen::keygen(&keydir)?
    }

    Ok(())
}
