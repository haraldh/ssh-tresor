use clap::{Parser, Subcommand};
use ssh_tresor::{agent, error, format::VaultBlob};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "ssh-tresor")]
#[command(about = "Encrypt and decrypt secrets using SSH agent keys")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt data using an SSH key from the agent
    Encrypt {
        /// Input file (default: stdin, use "-" explicitly for stdin)
        input: Option<PathBuf>,

        /// SSH key fingerprint to use (default: first available key)
        #[arg(short = 'k', long = "key")]
        fingerprint: Option<String>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output as base64 with header/footer (default: binary)
        #[arg(short, long)]
        armor: bool,
    },

    /// Decrypt data using an SSH key from the agent
    Decrypt {
        /// Input file (default: stdin, use "-" explicitly for stdin)
        input: Option<PathBuf>,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List available keys in the SSH agent
    ListKeys {
        /// Show MD5 fingerprints (default: SHA256)
        #[arg(long)]
        md5: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            input,
            fingerprint,
            output,
            armor,
        } => cmd_encrypt(input, fingerprint.as_deref(), output, armor),
        Commands::Decrypt { input, output } => cmd_decrypt(input, output),
        Commands::ListKeys { md5 } => cmd_list_keys(md5),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            e.exit_code()
        }
    }
}

fn cmd_encrypt(
    input: Option<PathBuf>,
    fingerprint: Option<&str>,
    output: Option<PathBuf>,
    armor: bool,
) -> ssh_tresor::Result<()> {
    // Read input
    let plaintext = read_input(input)?;

    // Encrypt
    let blob = ssh_tresor::encrypt(&plaintext, fingerprint)?;

    // Serialize output
    let output_data = if armor {
        blob.to_armored().into_bytes()
    } else {
        blob.to_bytes()
    };

    // Write output
    write_output(output, &output_data)?;

    Ok(())
}

fn cmd_decrypt(input: Option<PathBuf>, output: Option<PathBuf>) -> ssh_tresor::Result<()> {
    // Read input
    let encrypted = read_input(input)?;

    // Parse the vault blob (auto-detects armored vs binary)
    let blob = VaultBlob::from_bytes(&encrypted)?;

    // Decrypt
    let plaintext = ssh_tresor::decrypt(&blob)?;

    // Write output
    write_output(output, &plaintext)?;

    Ok(())
}

fn cmd_list_keys(md5: bool) -> ssh_tresor::Result<()> {
    let keys = ssh_tresor::list_keys()?;

    if keys.is_empty() {
        eprintln!("No keys found in SSH agent");
        eprintln!("Hint: Try running: ssh-add");
        return Err(error::Error::NoKeysAvailable);
    }

    for key in keys {
        if md5 {
            let md5_fp = agent::format_md5_fingerprint(&key.public_key);
            println!("{} {} {}", md5_fp, key.key_type, key.comment);
        } else {
            println!("{}", key);
        }
    }

    Ok(())
}

fn read_input(path: Option<PathBuf>) -> ssh_tresor::Result<Vec<u8>> {
    match path {
        Some(p) if p.to_str() != Some("-") => Ok(fs::read(&p)?),
        _ => {
            let mut buffer = Vec::new();
            io::stdin().read_to_end(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn write_output(path: Option<PathBuf>, data: &[u8]) -> ssh_tresor::Result<()> {
    match path {
        Some(p) => {
            fs::write(&p, data)?;
        }
        None => {
            io::stdout().write_all(data)?;
        }
    }
    Ok(())
}
