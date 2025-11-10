use atrium_codegen::genapi;
use clap::Parser;
use std::path::PathBuf;
use std::fs;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating Rust types from lexicons...");
    println!("  Input:  {}", args.lexdir.display());
    println!("  Output: {}", args.outdir.display());

    let results = genapi(
        &args.lexdir,
        &args.outdir,
        &[
            // Your custom namespace
            ("blue.catbird.mls", None),
        ],
    )?;

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
