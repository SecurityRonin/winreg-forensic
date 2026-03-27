use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use winreg_format::flags::ValueType;

mod output;

#[derive(Parser)]
#[command(name = "rt-reg", about = "Windows Registry forensic toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show hive metadata (type, version, timestamps, size, checksum)
    Info {
        /// Path to the hive file
        hive: PathBuf,
    },
    /// Dump registry tree (full or subtree)
    Dump {
        /// Path to the hive file
        hive: PathBuf,
        /// Key path to dump (omit for full tree)
        #[arg(long)]
        path: Option<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
        /// Maximum depth (0 = unlimited)
        #[arg(long, default_value = "0")]
        depth: usize,
    },
    /// Search keys/values by name or data content
    Search {
        /// Path to hive file or directory
        path: PathBuf,
        /// Search in key names
        #[arg(long, alias = "key")]
        key_name: Option<String>,
        /// Search in value names
        #[arg(long, alias = "value")]
        value_name: Option<String>,
        /// Search in value data (string values only)
        #[arg(long, alias = "data")]
        value_data: Option<String>,
        /// Output format
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Jsonl,
    Csv,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Info { hive } => cmd_info(&hive),
        Command::Dump {
            hive,
            path,
            format,
            depth,
        } => cmd_dump(&hive, path.as_deref(), &format, depth),
        Command::Search {
            path,
            key_name,
            value_name,
            value_data,
            format,
        } => cmd_search(
            &path,
            key_name.as_deref(),
            value_name.as_deref(),
            value_data.as_deref(),
            &format,
        ),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn cmd_info(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::hive::Hive::from_path(path)?;
    let hive_type = hive.detect_hive_type();

    let version_str = match hive.version() {
        winreg_format::version::RegfVersion::V1_0 => "1.0",
        winreg_format::version::RegfVersion::V1_3 => "1.3",
        winreg_format::version::RegfVersion::V1_4 => "1.4",
        winreg_format::version::RegfVersion::V1_5 => "1.5",
        winreg_format::version::RegfVersion::V1_6 => "1.6",
    };

    println!("File:           {}", path.display());
    println!("Hive type:      {hive_type}");
    println!("Version:        {version_str}");
    println!(
        "Clean:          {}",
        if hive.is_clean() { "yes" } else { "NO (dirty)" }
    );
    println!("Bins:           {}", hive.bin_count());
    println!("Data size:      {} bytes", hive.hive_bins_data_size());
    println!("Internal name:  {}", hive.file_name());

    // Count keys and values via BFS
    let mut key_count = 0u64;
    let mut value_count = 0u64;
    for key_result in hive.iter_bfs()? {
        let key = key_result?;
        key_count += 1;
        value_count += u64::from(key.value_count());
    }
    println!("Keys:           {key_count}");
    println!("Values:         {value_count}");

    Ok(())
}

fn cmd_dump(
    path: &std::path::Path,
    subpath: Option<&str>,
    _format: &OutputFormat,
    max_depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::hive::Hive::from_path(path)?;

    if let Some(p) = subpath {
        let key = hive
            .open_key(p)?
            .ok_or_else(|| format!("Key not found: {p}"))?;
        dump_key(&key, 0, max_depth)?;
    } else {
        let root = hive.root_key()?;
        dump_key(&root, 0, max_depth)?;
    }

    Ok(())
}

fn dump_key(
    key: &winreg_core::key::Key<'_>,
    depth: usize,
    max_depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if max_depth > 0 && depth >= max_depth {
        return Ok(());
    }

    let indent = "  ".repeat(depth);
    println!("{indent}[{}]", key.name());

    for val in key.values()? {
        let data_preview = match val.data_type() {
            ValueType::Sz | ValueType::ExpandSz => {
                val.as_string().unwrap_or_else(|_| "<error>".into())
            }
            ValueType::Dword => val
                .as_u32()
                .map_or_else(|_| "<error>".into(), |v| format!("0x{v:08X}")),
            ValueType::Qword => val
                .as_u64()
                .map_or_else(|_| "<error>".into(), |v| format!("0x{v:016X}")),
            _ => {
                let raw = val.raw_data().unwrap_or_default();
                if raw.len() <= 16 {
                    format!("{raw:02X?}")
                } else {
                    format!("[{} bytes]", raw.len())
                }
            }
        };
        let name = val.name();
        let display_name = if name.is_empty() { "(Default)" } else { &name };
        println!(
            "{indent}  {display_name} ({}) = {data_preview}",
            val.data_type()
        );
    }

    for subkey in key.subkeys()? {
        dump_key(&subkey, depth + 1, max_depth)?;
    }

    Ok(())
}

fn cmd_search(
    path: &std::path::Path,
    key_name: Option<&str>,
    value_name: Option<&str>,
    value_data: Option<&str>,
    _format: &OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let hive = winreg_core::hive::Hive::from_path(path)?;

    let key_pattern = key_name.map(str::to_ascii_uppercase);
    let val_pattern = value_name.map(str::to_ascii_uppercase);
    let data_pattern = value_data.map(str::to_ascii_uppercase);

    for key_result in hive.iter_bfs()? {
        let key = key_result?;
        let key_name_upper = key.name().to_ascii_uppercase();

        // Match key name
        if let Some(ref pattern) = key_pattern {
            if key_name_upper.contains(pattern.as_str()) {
                println!("KEY: {}", key.name());
            }
        }

        // Match value name or data
        if val_pattern.is_some() || data_pattern.is_some() {
            for val in key.values()? {
                let name = val.name();
                let matched = if let Some(ref pattern) = val_pattern {
                    name.to_ascii_uppercase().contains(pattern.as_str())
                } else {
                    false
                };

                let data_matched = if let Some(ref pattern) = data_pattern {
                    val.as_string()
                        .map(|s| s.to_ascii_uppercase().contains(pattern.as_str()))
                        .unwrap_or(false)
                } else {
                    false
                };

                if matched || data_matched {
                    println!(
                        "VALUE: {}\\{} ({}) = {}",
                        key.name(),
                        name,
                        val.data_type(),
                        val.as_string().unwrap_or_else(|_| "<binary>".into())
                    );
                }
            }
        }
    }

    Ok(())
}
