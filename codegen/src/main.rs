use clap::Parser;
use jacquard_lexicon::codegen::CodeGenerator;
use jacquard_lexicon::corpus::LexiconCorpus;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

/// Generate Rust types from lexicon schemas
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing lexicon schemas
    #[arg(short, long, default_value = "../lexicon")]
    lexdir: PathBuf,

    /// Output directory for generated code
    #[arg(short, long, default_value = "../../catbird-atproto/src/generated")]
    outdir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating Rust types from lexicons...");
    println!("  Input:  {}", args.lexdir.display());
    println!("  Output: {}", args.outdir.display());

    let normalized_lexdir = normalize_lexicon_dir(&args.lexdir)?;
    let corpus = LexiconCorpus::load_from_dir(normalized_lexdir.path())?;
    let codegen = CodeGenerator::new(&corpus, "crate::generated");
    codegen.write_to_disk(&args.outdir)?;

    println!("✓ Code generation complete!");
    Ok(())
}

fn normalize_lexicon_dir(lexdir: &Path) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let tempdir = tempfile::tempdir()?;
    let normalized = copy_and_normalize_lexicons(lexdir, tempdir.path())?;

    if normalized > 0 {
        println!("  Normalized {normalized} raw-byte XRPC body schema(s) for Jacquard");
    }

    Ok(tempdir)
}

fn copy_and_normalize_lexicons(
    source: &Path,
    destination: &Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    fs::create_dir_all(destination)?;

    let mut normalized = 0usize;

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            normalized += copy_and_normalize_lexicons(&source_path, &destination_path)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        if source_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &destination_path)?;
            continue;
        }

        let content = fs::read_to_string(&source_path)?;
        let (normalized_content, normalized_count) = normalize_lexicon_json(&content)?;
        normalized += normalized_count;

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination_path, normalized_content)?;
    }

    Ok(normalized)
}

fn normalize_lexicon_json(content: &str) -> Result<(String, usize), serde_json::Error> {
    let mut value: Value = serde_json::from_str(content)?;
    let normalized_count = normalize_raw_byte_xrpc_bodies(&mut value);
    let normalized_content = serde_json::to_string_pretty(&value)?;
    Ok((normalized_content, normalized_count))
}

fn normalize_raw_byte_xrpc_bodies(value: &mut Value) -> usize {
    let Some(defs) = value.get_mut("defs").and_then(Value::as_object_mut) else {
        return 0;
    };

    let mut normalized = 0usize;

    for def in defs.values_mut() {
        let Some(definition) = def.as_object_mut() else {
            continue;
        };

        for key in ["input", "output"] {
            let Some(body) = definition.get_mut(key).and_then(Value::as_object_mut) else {
                continue;
            };

            if normalize_raw_byte_body_schema(body) {
                normalized += 1;
            }
        }
    }

    normalized
}

fn normalize_raw_byte_body_schema(body: &mut serde_json::Map<String, Value>) -> bool {
    let schema = match body.get("schema").and_then(Value::as_object) {
        Some(schema) => schema,
        None => return false,
    };

    let is_bytes_schema = schema
        .get("type")
        .and_then(Value::as_str)
        .map(|value| value == "bytes")
        .unwrap_or(false);

    if !is_bytes_schema {
        return false;
    }

    if !body.contains_key("description") {
        if let Some(description) = schema.get("description").cloned() {
            body.insert("description".to_string(), description);
        }
    }

    body.remove("schema");
    true
}

#[cfg(test)]
mod tests {
    use super::normalize_raw_byte_xrpc_bodies;
    use serde_json::json;

    #[test]
    fn strips_raw_byte_body_schemas() {
        let mut lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.mlsChat.testBinary",
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": {
                        "encoding": "*/*",
                        "schema": {
                            "type": "bytes",
                            "description": "Binary upload"
                        }
                    },
                    "output": {
                        "encoding": "*/*",
                        "schema": {
                            "type": "bytes",
                            "description": "Binary download"
                        }
                    }
                }
            }
        });

        let normalized = normalize_raw_byte_xrpc_bodies(&mut lexicon);

        assert_eq!(normalized, 2);
        assert!(lexicon["defs"]["main"]["input"].get("schema").is_none());
        assert!(lexicon["defs"]["main"]["output"].get("schema").is_none());
    }

    #[test]
    fn leaves_non_byte_schemas_unchanged() {
        let mut lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.mlsChat.testJson",
            "defs": {
                "main": {
                    "type": "query",
                    "output": {
                        "encoding": "application/json",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "value": { "type": "string" }
                            }
                        }
                    }
                }
            }
        });

        let normalized = normalize_raw_byte_xrpc_bodies(&mut lexicon);

        assert_eq!(normalized, 0);
        assert_eq!(
            lexicon["defs"]["main"]["output"]["schema"]["type"],
            "object"
        );
    }
}
