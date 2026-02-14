use clap::Parser;
use jacquard_lexicon::codegen::CodeGenerator;
use jacquard_lexicon::corpus::LexiconCorpus;
use std::path::PathBuf;

/// Generate Rust types from lexicon schemas
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing lexicon schemas
    #[arg(short, long, default_value = "../lexicon")]
    lexdir: PathBuf,

    /// Output directory for generated code
    #[arg(short, long, default_value = "../server/src/generated")]
    outdir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating Rust types from lexicons...");
    println!("  Input:  {}", args.lexdir.display());
    println!("  Output: {}", args.outdir.display());

    let corpus = LexiconCorpus::load_from_dir(&args.lexdir)?;
    let codegen = CodeGenerator::new(&corpus, "crate::generated");
    codegen.write_to_disk(&args.outdir)?;

    println!("✓ Code generation complete!");
    Ok(())
}
