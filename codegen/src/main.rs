use atrium_codegen::genapi;
use clap::Parser;
use std::{fs, path::PathBuf};

/// Generate Rust types from lexicon schemas
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing lexicon schemas
    #[arg(short, long, default_value = "../lexicon")]
    lexdir: PathBuf,

    /// Output directory for generated code
    #[arg(short, long, default_value = "../server/src")]
    outdir: PathBuf,
}

fn patch_atproto_bytes(
    paths: &[impl AsRef<std::path::Path>],
) -> Result<usize, Box<dyn std::error::Error>> {
    // atrium-codegen currently renders lexicon `bytes` as `#[serde(with = "serde_bytes")]`,
    // but ATProto JSON uses `{ "$bytes": "base64..." }`.
    //
    // Note: some lexicon bytes fields are optional; those need `crate::atproto_bytes::option`.
    let needle = "#[serde(with = \"serde_bytes\")]";

    let mut changed = 0;
    for p in paths {
        let p = p.as_ref();
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }

        let content = fs::read_to_string(p)?;
        if !content.contains(needle) {
            continue;
        }

        let lines: Vec<&str> = content.lines().collect();
        let mut out = String::with_capacity(content.len());

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.contains(needle) {
                // Look ahead to the field declaration to decide Vec<u8> vs Option<Vec<u8>>.
                let mut is_option = false;
                for j in i + 1..lines.len() {
                    let next = lines[j].trim_start();
                    if next.starts_with("pub ") {
                        if next.contains("Option<Vec<u8>>") {
                            is_option = true;
                        }
                        break;
                    }
                    if !next.starts_with("#") && !next.is_empty() {
                        break;
                    }
                }

                if is_option {
                    out.push_str(
                        &line.replace(needle, "#[serde(with = \"crate::atproto_bytes::option\")]"),
                    );
                } else {
                    out.push_str(
                        &line.replace(needle, "#[serde(with = \"crate::atproto_bytes\")]"),
                    );
                }
                out.push('\n');
                i += 1;
                continue;
            }

            out.push_str(line);
            out.push('\n');
            i += 1;
        }

        if out != content {
            fs::write(p, out)?;
            changed += 1;
        }
    }

    Ok(changed)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating Rust types from lexicons...");
    println!("  Input:  {}", args.lexdir.display());
    println!("  Output: {}", args.outdir.display());

    let results = genapi(&args.lexdir, &args.outdir, &[("blue.catbird.mls", None)])?;

    let patched = patch_atproto_bytes(&results)?;
    if patched > 0 {
        println!("Patched {patched} generated files to use ATProto $bytes deserialization");
    }

    println!("\nGenerated {} files:", results.len());
    for path in &results {
        println!(
            "  {} ({} bytes)",
            path.as_ref().display(),
            std::fs::metadata(path.as_ref())?.len()
        );
    }

    println!("\n✓ Code generation complete!");
    Ok(())
}
