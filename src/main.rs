use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use ssh_tresor::{
    agent, error,
    format::{TresorBlob, MAX_TRESOR_SIZE},
};
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
    /// Encrypt data using SSH keys from the agent
    Encrypt {
        /// Input file (default: stdin, use "-" explicitly for stdin)
        input: Option<PathBuf>,

        /// SSH key fingerprint(s) to use (can be specified multiple times)
        #[arg(short = 'k', long = "key", action = clap::ArgAction::Append)]
        fingerprints: Vec<String>,

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

    /// Add a key to an existing tresor
    AddKey {
        /// Input tresor file (default: stdin)
        input: Option<PathBuf>,

        /// SSH key fingerprint to add
        #[arg(short = 'k', long = "key", conflicts_with = "all")]
        fingerprint: Option<String>,

        /// Add all available keys from the agent (skips existing keys and errors)
        #[arg(short = 'a', long = "all", conflicts_with = "fingerprint")]
        all: bool,

        /// Modify tresor file in-place
        #[arg(
            short = 'i',
            long = "in-place",
            conflicts_with = "output",
            requires = "input"
        )]
        in_place: bool,

        /// Output file (default: stdout)
        #[arg(short, long, conflicts_with = "in_place")]
        output: Option<PathBuf>,

        /// Output as base64 with header/footer (default: preserve input format)
        #[arg(long)]
        armor: bool,
    },

    /// Remove a key from an existing tresor
    RemoveKey {
        /// Input tresor file (default: stdin)
        input: Option<PathBuf>,

        /// SSH key fingerprint to remove
        #[arg(short = 'k', long = "key", required = true)]
        fingerprint: String,

        /// Modify tresor file in-place
        #[arg(
            short = 'i',
            long = "in-place",
            conflicts_with = "output",
            requires = "input"
        )]
        in_place: bool,

        /// Output file (default: stdout)
        #[arg(short, long, conflicts_with = "in_place")]
        output: Option<PathBuf>,

        /// Output as base64 with header/footer (default: preserve input format)
        #[arg(long)]
        armor: bool,
    },

    /// List key slots in a tresor
    ListSlots {
        /// Input tresor file (default: stdin)
        input: Option<PathBuf>,
    },

    /// List available keys in the SSH agent
    ListKeys {
        /// Show MD5 fingerprints (default: SHA256)
        #[arg(long)]
        md5: bool,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            input,
            fingerprints,
            output,
            armor,
        } => cmd_encrypt(input, &fingerprints, output, armor),
        Commands::Decrypt { input, output } => cmd_decrypt(input, output),
        Commands::AddKey {
            input,
            fingerprint,
            all,
            in_place,
            output,
            armor,
        } => cmd_add_key(input, fingerprint.as_deref(), all, in_place, output, armor),
        Commands::RemoveKey {
            input,
            fingerprint,
            in_place,
            output,
            armor,
        } => cmd_remove_key(input, &fingerprint, in_place, output, armor),
        Commands::ListSlots { input } => cmd_list_slots(input),
        Commands::ListKeys { md5 } => cmd_list_keys(md5),
        Commands::Completions { shell } => {
            generate(shell, &mut Cli::command(), "ssh-tresor", &mut io::stdout());
            Ok(())
        }
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
    fingerprints: &[String],
    output: Option<PathBuf>,
    armor: bool,
) -> ssh_tresor::Result<()> {
    // Read input
    let plaintext = read_input(input)?;

    // Convert fingerprints to &str slice
    let fp_refs: Vec<&str> = fingerprints.iter().map(|s| s.as_str()).collect();

    // Encrypt
    let blob = ssh_tresor::encrypt(&plaintext, &fp_refs)?;

    // Serialize output
    let output_data = if armor {
        blob.to_armored()?.into_bytes()
    } else {
        blob.to_bytes()?
    };

    // Write output
    write_output(output, &output_data)?;

    Ok(())
}

fn cmd_decrypt(input: Option<PathBuf>, output: Option<PathBuf>) -> ssh_tresor::Result<()> {
    // Read input
    let encrypted = read_input(input)?;

    // Parse the tresor blob (auto-detects armored vs binary)
    let blob = TresorBlob::from_bytes(&encrypted)?;

    // Decrypt
    let plaintext = ssh_tresor::decrypt(&blob)?;

    // Write output
    write_output(output, &plaintext)?;

    Ok(())
}

fn cmd_add_key(
    input: Option<PathBuf>,
    fingerprint: Option<&str>,
    all: bool,
    in_place: bool,
    output: Option<PathBuf>,
    armor: bool,
) -> ssh_tresor::Result<()> {
    // Require either -k or -a
    if fingerprint.is_none() && !all {
        return Err(error::Error::InvalidFormat(
            "either --key or --all must be specified".to_string(),
        ));
    }

    // Read input
    let encrypted = read_input(input.clone())?;

    // Detect if input was armored
    let was_armored = std::str::from_utf8(&encrypted)
        .map(|s| s.trim().starts_with("-----BEGIN"))
        .unwrap_or(false);

    // Parse the tresor blob
    let blob = TresorBlob::from_bytes(&encrypted)?;

    // Add the new key(s)
    let new_blob = if all {
        let (blob, added) = ssh_tresor::add_all_keys(&blob)?;
        if added == 0 {
            eprintln!("No new keys added (all keys already present or unavailable)");
        } else {
            eprintln!("Added {} key(s)", added);
        }
        blob
    } else {
        ssh_tresor::add_key(&blob, fingerprint.unwrap())?
    };

    // Serialize output (preserve format unless --armor specified)
    let output_data = if armor || was_armored {
        new_blob.to_armored()?.into_bytes()
    } else {
        new_blob.to_bytes()?
    };

    // Write output (in-place uses input path)
    let output_path = if in_place { input } else { output };
    write_output(output_path, &output_data)?;

    Ok(())
}

fn cmd_remove_key(
    input: Option<PathBuf>,
    fingerprint: &str,
    in_place: bool,
    output: Option<PathBuf>,
    armor: bool,
) -> ssh_tresor::Result<()> {
    // Read input
    let encrypted = read_input(input.clone())?;

    // Detect if input was armored
    let was_armored = std::str::from_utf8(&encrypted)
        .map(|s| s.trim().starts_with("-----BEGIN"))
        .unwrap_or(false);

    // Parse the tresor blob
    let blob = TresorBlob::from_bytes(&encrypted)?;

    // Remove the key
    let new_blob = ssh_tresor::remove_key(&blob, fingerprint)?;

    // Serialize output (preserve format unless --armor specified)
    let output_data = if armor || was_armored {
        new_blob.to_armored()?.into_bytes()
    } else {
        new_blob.to_bytes()?
    };

    // Write output (in-place uses input path)
    let output_path = if in_place { input } else { output };
    write_output(output_path, &output_data)?;

    Ok(())
}

fn cmd_list_slots(input: Option<PathBuf>) -> ssh_tresor::Result<()> {
    // Read input
    let encrypted = read_input(input)?;

    // Parse the tresor blob
    let blob = TresorBlob::from_bytes(&encrypted)?;

    // Get slot fingerprints
    let fingerprints = ssh_tresor::list_slots(&blob);

    // Try to match with keys in agent for better display
    let agent_keys = ssh_tresor::list_keys().ok();

    println!("Tresor contains {} key slot(s):", fingerprints.len());
    for (i, fp) in fingerprints.iter().enumerate() {
        let fp_b64 = STANDARD_NO_PAD.encode(fp);

        // Try to find matching key in agent
        if let Some(ref keys) = agent_keys {
            if let Some(key) = keys.iter().find(|k| &k.fingerprint_bytes == fp) {
                println!(
                    "  Slot {}: SHA256:{} {} {} [AVAILABLE]",
                    i + 1,
                    fp_b64,
                    key.key_type,
                    key.comment
                );
                continue;
            }
        }

        println!("  Slot {}: SHA256:{}", i + 1, fp_b64);
    }

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
    let buffer = match path {
        Some(p) if p.to_str() != Some("-") => fs::read(&p)?,
        _ => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    if buffer.len() > MAX_TRESOR_SIZE {
        return Err(error::Error::InvalidFormat(format!(
            "input too large: {} bytes, maximum {} bytes (100 MB)",
            buffer.len(),
            MAX_TRESOR_SIZE
        )));
    }

    Ok(buffer)
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
