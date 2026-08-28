use clap::Parser;
use jacquard_lexicon::codegen::CodeGenerator;
use jacquard_lexicon::corpus::LexiconCorpus;
use jacquard_lexicon::lexicon::LexStringFormat;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Generate Rust types from lexicon schemas
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory containing lexicon schemas. May be repeated; later dirs overlay earlier dirs.
    #[arg(short, long, value_name = "DIR", default_value = "../lexicon")]
    lexdir: Vec<PathBuf>,

    /// Output directory for generated code
    #[arg(short, long, default_value = "../../catbird-atproto/src/generated")]
    outdir: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating Rust types from lexicons...");
    for lexdir in &args.lexdir {
        println!("  Input:  {}", lexdir.display());
    }
    println!("  Output: {}", args.outdir.display());

    let normalized_lexdir = normalize_lexicon_dirs(&args.lexdir)?;
    validate_strict_union_contracts(normalized_lexdir.path())?;
    let corpus = LexiconCorpus::load_from_dir(normalized_lexdir.path())?;
    let codegen = CodeGenerator::new(&corpus, "crate::generated");
    codegen.write_to_disk(&args.outdir)?;

    println!("✓ Code generation complete!");
    Ok(())
}

fn normalize_lexicon_dirs(
    lexdirs: &[PathBuf],
) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let tempdir = tempfile::tempdir()?;
    let mut normalized = 0usize;

    for lexdir in lexdirs {
        normalized += copy_and_normalize_lexicons(lexdir, tempdir.path())?;
    }

    if normalized > 0 {
        println!("  Normalized {normalized} lexicon schema(s) for Jacquard");
    }

    Ok(tempdir)
}

fn validate_strict_union_contracts(lexicon_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let documents = load_preflight_documents(lexicon_dir)?;

    for document in documents.values() {
        for (definition_name, definition) in &document.defs {
            validate_union_value(
                definition,
                document,
                &documents,
                &format!("{}#{definition_name}", document.id),
                true,
            )
            .map_err(invalid_union_contract)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
struct PreflightDocument {
    id: String,
    defs: serde_json::Map<String, Value>,
    source_path: PathBuf,
}

fn load_preflight_documents(
    lexicon_dir: &Path,
) -> Result<BTreeMap<String, PreflightDocument>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_json_files(lexicon_dir, &mut files)?;
    files.sort();

    let mut documents: BTreeMap<String, PreflightDocument> = BTreeMap::new();
    for path in files {
        let content = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&content).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse JSON file {}: {error}", path.display()),
            )
        })?;

        // Well-formed JSON without a lexicon marker is outside the codegen corpus.
        if value.get("lexicon").is_none() {
            continue;
        }

        let id = value
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("lexicon {} has no string id", path.display()),
                )
            })?
            .to_owned();
        let defs = value
            .get("defs")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("lexicon {id} has no defs object"),
                )
            })?
            .clone();

        if let Some(existing) = documents.get(&id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "duplicate lexicon id {id}: first defined at {}, also defined at {}",
                    existing.source_path.display(),
                    path.display()
                ),
            )
            .into());
        }

        documents.insert(
            id.clone(),
            PreflightDocument {
                id,
                defs,
                source_path: path,
            },
        );
    }

    Ok(documents)
}

fn collect_json_files(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_json_files(&path, files)?;
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            files.push(path);
        }
    }

    Ok(())
}

fn validate_union_value(
    value: &Value,
    current_document: &PreflightDocument,
    documents: &BTreeMap<String, PreflightDocument>,
    location: &str,
    is_named_definition: bool,
) -> Result<(), String> {
    if let Some(object) = value.as_object() {
        let is_union = object.get("type").and_then(Value::as_str) == Some("union");
        let is_closed = object.get("closed").and_then(Value::as_bool) == Some(true);

        if is_union && is_named_definition && !is_closed {
            return Err(format!(
                "strict union preflight at {location}: named union must set closed to true"
            ));
        }

        if is_union && (is_named_definition || is_closed) {
            validate_closed_union(object, current_document, documents, location)?;
        }

        for (key, child) in object {
            validate_union_value(
                child,
                current_document,
                documents,
                &format!("{location}.{key}"),
                false,
            )?;
        }
    } else if let Some(array) = value.as_array() {
        for (index, child) in array.iter().enumerate() {
            validate_union_value(
                child,
                current_document,
                documents,
                &format!("{location}[{index}]"),
                false,
            )?;
        }
    }

    Ok(())
}

fn validate_closed_union(
    union: &serde_json::Map<String, Value>,
    current_document: &PreflightDocument,
    documents: &BTreeMap<String, PreflightDocument>,
    location: &str,
) -> Result<(), String> {
    let refs = union.get("refs").and_then(Value::as_array).ok_or_else(|| {
        format!("strict union preflight at {location}: closed union must contain a refs array")
    })?;

    if refs.is_empty() {
        return Err(format!(
            "strict union preflight at {location}: closed union must contain at least one ref"
        ));
    }

    let mut canonical_refs = HashSet::new();
    for (index, reference) in refs.iter().enumerate() {
        let raw_reference = reference.as_str().ok_or_else(|| {
            format!("strict union preflight at {location}.refs[{index}]: ref must be a string")
        })?;
        let canonical = canonicalize_ref(&current_document.id, raw_reference).map_err(|reason| {
            format!(
                "strict union preflight at {location}.refs[{index}]: invalid ref {raw_reference:?}: {reason}"
            )
        })?;

        if !canonical_refs.insert(canonical.clone()) {
            return Err(format!(
                "strict union preflight at {location}.refs[{index}]: {raw_reference:?} duplicates canonical ref {canonical}"
            ));
        }

        let (target_nsid, target_def) = canonical
            .split_once('#')
            .expect("canonical refs always contain one fragment separator");
        let target = documents
            .get(target_nsid)
            .and_then(|document| document.defs.get(target_def))
            .ok_or_else(|| {
                format!(
                    "strict union preflight at {location}.refs[{index}]: {raw_reference:?} canonicalizes to {canonical}, which does not resolve"
                )
            })?;
        let target_type = target
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("<missing>");

        if target_type != "object" {
            return Err(format!(
                "strict union preflight at {location}.refs[{index}]: {canonical} resolves to {target_type}, expected object"
            ));
        }
    }

    Ok(())
}

fn canonicalize_ref(current_nsid: &str, reference: &str) -> Result<String, &'static str> {
    if reference.is_empty() {
        return Err("ref is empty");
    }

    let (nsid, definition) = if let Some(definition) = reference.strip_prefix('#') {
        (current_nsid, definition)
    } else if let Some((nsid, definition)) = reference.split_once('#') {
        (nsid, definition)
    } else {
        (reference, "main")
    };

    if nsid.is_empty() {
        return Err("NSID is empty");
    }
    if definition.is_empty() {
        return Err("definition fragment is empty");
    }
    if definition.contains('#') {
        return Err("ref contains more than one fragment separator");
    }

    Ok(format!("{nsid}#{definition}"))
}

fn invalid_union_contract(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn copy_and_normalize_lexicons(
    source: &Path,
    destination: &Path,
) -> Result<usize, Box<dyn std::error::Error>> {
    fs::create_dir_all(destination)?;

    let mut normalized = 0usize;

    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
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
            continue;
        }

        let content = fs::read_to_string(&source_path)?;
        let (normalized_content, normalized_count) =
            normalize_lexicon_json(&content, &source_path)?;
        normalized += normalized_count;

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination_path, normalized_content)?;
    }

    Ok(normalized)
}

fn normalize_lexicon_json(content: &str, source_path: &Path) -> Result<(String, usize), io::Error> {
    let mut value: Value = serde_json::from_str(content).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse JSON file {}: {error}", source_path.display()),
        )
    })?;

    if value.get("lexicon").is_none() {
        let serialized = serde_json::to_string_pretty(&value).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, error.to_string())
        })?;
        return Ok((serialized, 0));
    }

    let doc_id = value.get("id").and_then(Value::as_str).map(String::from);
    let mut normalized_count = normalize_raw_byte_xrpc_bodies(&mut value);
    normalized_count +=
        normalize_string_formats(&mut value, source_path, doc_id.as_deref(), "$")?;
    let normalized_content = serde_json::to_string_pretty(&value).map_err(|error| {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    })?;
    Ok((normalized_content, normalized_count))
}

fn normalize_string_formats(
    value: &mut Value,
    source_path: &Path,
    doc_id: Option<&str>,
    location: &str,
) -> Result<usize, io::Error> {
    let mut normalized = 0usize;
    match value {
        Value::Object(map) => {
            let is_string_type = map.get("type").and_then(Value::as_str) == Some("string");
            if is_string_type {
                if let Some(format_val) = map.get("format") {
                    let format_loc = format!("{location}.format");
                    let Some(format_str) = format_val.as_str() else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "invalid non-string format value at {format_loc} in {}",
                                source_path.display()
                            ),
                        ));
                    };

                    let is_supported = serde_json::from_value::<LexStringFormat>(Value::String(
                        format_str.to_string(),
                    ))
                    .is_ok();
                    if is_supported {
                        // Supported format, preserved as-is.
                    } else if format_str == "space-ref" && is_known_space_schema(source_path, doc_id)
                    {
                        map.remove("format");
                        normalized += 1;
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "unsupported or unrecognized string format {format_str:?} at {format_loc} in {}",
                                source_path.display()
                            ),
                        ));
                    }
                }
            }

            for (key, child) in map.iter_mut() {
                let child_loc = format!("{location}.{key}");
                normalized += normalize_string_formats(child, source_path, doc_id, &child_loc)?;
            }
        }
        Value::Array(list) => {
            for (index, child) in list.iter_mut().enumerate() {
                let child_loc = format!("{location}[{index}]");
                normalized += normalize_string_formats(child, source_path, doc_id, &child_loc)?;
            }
        }
        _ => {}
    }
    Ok(normalized)
}

fn is_known_space_schema(source_path: &Path, doc_id: Option<&str>) -> bool {
    if let Some(id) = doc_id {
        if id.starts_with("com.atproto.space.") || id.starts_with("com.atproto.simplespace.") {
            return true;
        }
    }
    let path_str = source_path.to_string_lossy();
    path_str.contains("com/atproto/space") || path_str.contains("com/atproto/simplespace")
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
    use super::load_preflight_documents;
    use super::normalize_lexicon_dirs;
    use super::normalize_raw_byte_xrpc_bodies;
    use super::normalize_string_formats;
    use super::validate_strict_union_contracts;
    use std::path::Path;
    use jacquard_lexicon::codegen::CodeGenerator;
    use jacquard_lexicon::corpus::LexiconCorpus;
    use serde_json::json;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    const FIXTURE_ID: &str = "blue.catbird.chat.unionFixture";

    fn object_definition() -> Value {
        json!({
            "type": "object",
            "properties": {}
        })
    }

    fn fixture_with_defs(defs: Value) -> Value {
        json!({
            "lexicon": 1,
            "id": FIXTURE_ID,
            "defs": defs
        })
    }

    fn write_fixture(lexicon: &Value) -> tempfile::TempDir {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        write_lexicon_at(fixture.path(), "fixture.json", lexicon);
        fixture
    }

    fn write_lexicon_at(root: &std::path::Path, relative: &str, lexicon: &Value) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("lexicon parent")).expect("lexicon dirs");
        fs::write(
            &path,
            serde_json::to_vec_pretty(lexicon).expect("serialize fixture"),
        )
        .expect("write fixture");
        path
    }

    fn validate_fixture(lexicon: Value) -> Result<(), String> {
        let fixture = write_fixture(&lexicon);
        validate_strict_union_contracts(fixture.path()).map_err(|error| error.to_string())
    }

    fn assert_rejected(lexicon: Value, expected: &str) {
        let error = validate_fixture(lexicon).expect_err("fixture must be rejected");
        assert!(
            error.contains(expected),
            "expected error containing {expected:?}, got {error:?}"
        );
    }

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

    #[test]
    fn preserves_supported_string_formats() {
        let mut lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.testSupportedFormats",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "at": { "type": "string", "format": "datetime" },
                        "user": { "type": "string", "format": "did" },
                        "handle": { "type": "string", "format": "handle" },
                        "link": { "type": "string", "format": "uri" },
                        "record": { "type": "string", "format": "at-uri" },
                        "blob": { "type": "string", "format": "cid" },
                        "rkey": { "type": "string", "format": "record-key" },
                        "tid": { "type": "string", "format": "tid" },
                        "nsid": { "type": "string", "format": "nsid" },
                        "lang": { "type": "string", "format": "language" },
                        "ident": { "type": "string", "format": "at-identifier" }
                    }
                }
            }
        });

        let count = normalize_string_formats(
            &mut lexicon,
            Path::new("blue/catbird/testSupportedFormats.json"),
            Some("blue.catbird.testSupportedFormats"),
            "$",
        )
        .expect("supported formats must succeed");

        assert_eq!(count, 0);
        assert_eq!(lexicon["defs"]["main"]["properties"]["user"]["format"], "did");
        assert_eq!(lexicon["defs"]["main"]["properties"]["at"]["format"], "datetime");
        assert_eq!(lexicon["defs"]["main"]["properties"]["blob"]["format"], "cid");
    }

    #[test]
    fn strips_space_ref_only_from_known_space_lexicons() {
        let mut space_lexicon = json!({
            "lexicon": 1,
            "id": "com.atproto.space.getSpace",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "space": { "type": "string", "format": "space-ref" }
                    }
                }
            }
        });

        let count = normalize_string_formats(
            &mut space_lexicon,
            Path::new("Petrel/generator/lexicons/com/atproto/space/getSpace.json"),
            Some("com.atproto.space.getSpace"),
            "$",
        )
        .expect("known space lexicon space-ref must be normalized");

        assert_eq!(count, 1);
        assert!(space_lexicon["defs"]["main"]["properties"]["space"].get("format").is_none());
        assert_eq!(space_lexicon["defs"]["main"]["properties"]["space"]["type"], "string");

        // Outside known space lexicons, space-ref must be rejected
        let mut other_lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.other",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "space": { "type": "string", "format": "space-ref" }
                    }
                }
            }
        });

        let err = normalize_string_formats(
            &mut other_lexicon,
            Path::new("blue/catbird/other.json"),
            Some("blue.catbird.other"),
            "$",
        )
        .expect_err("space-ref in non-space lexicon must be rejected");

        assert!(err.to_string().contains("unsupported or unrecognized string format \"space-ref\""));
    }

    #[test]
    fn rejects_unknown_string_format_or_typo() {
        let mut lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.testTypo",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "badField": { "type": "string", "format": "date-time" }
                    }
                }
            }
        });

        let err = normalize_string_formats(
            &mut lexicon,
            Path::new("blue/catbird/testTypo.json"),
            Some("blue.catbird.testTypo"),
            "$",
        )
        .expect_err("typo in format must be rejected");

        assert!(err.to_string().contains("unsupported or unrecognized string format \"date-time\""));
        assert!(err.to_string().contains("$.defs.main.properties.badField.format"));
        assert!(err.to_string().contains("blue/catbird/testTypo.json"));

        // Also non-string format value
        let mut non_string_lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.testNonString",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "badField": { "type": "string", "format": 123 }
                    }
                }
            }
        });

        let err2 = normalize_string_formats(
            &mut non_string_lexicon,
            Path::new("blue/catbird/testNonString.json"),
            Some("blue.catbird.testNonString"),
            "$",
        )
        .expect_err("non-string format must be rejected");

        assert!(err2.to_string().contains("invalid non-string format value"));
    }

    #[test]
    fn preserves_object_or_property_named_format() {
        let mut lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.testFormatProperty",
            "defs": {
                "main": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "description": "A property whose name happens to be format"
                        },
                        "typedFormat": {
                            "type": "string",
                            "format": "did"
                        }
                    }
                },
                "customObj": {
                    "type": "object",
                    "format": "video-container",
                    "properties": {
                        "width": { "type": "integer" }
                    }
                }
            }
        });

        let count = normalize_string_formats(
            &mut lexicon,
            Path::new("blue/catbird/testFormatProperty.json"),
            Some("blue.catbird.testFormatProperty"),
            "$",
        )
        .expect("format property must succeed");

        assert_eq!(count, 0);
        assert_eq!(
            lexicon["defs"]["main"]["properties"]["format"]["description"],
            "A property whose name happens to be format"
        );
        assert_eq!(lexicon["defs"]["main"]["properties"]["typedFormat"]["format"], "did");
        assert_eq!(lexicon["defs"]["customObj"]["format"], "video-container");
    }

    #[test]
    fn later_lexicon_dirs_overlay_earlier_dirs() {
        let reference = tempfile::tempdir().expect("reference tempdir");
        let overlay = tempfile::tempdir().expect("overlay tempdir");

        let relative = "blue/catbird/mlsChat/blue.catbird.mlsChat.example.json";
        let reference_file = reference.path().join(relative);
        let overlay_file = overlay.path().join(relative);
        fs::create_dir_all(reference_file.parent().unwrap()).expect("reference dirs");
        fs::create_dir_all(overlay_file.parent().unwrap()).expect("overlay dirs");

        fs::write(
            &reference_file,
            r#"{"lexicon":1,"id":"blue.catbird.mlsChat.example","defs":{"main":{"type":"query","description":"reference"}}}"#,
        )
        .expect("write reference");
        fs::write(
            &overlay_file,
            r#"{"lexicon":1,"id":"blue.catbird.mlsChat.example","defs":{"main":{"type":"query","description":"overlay"}}}"#,
        )
        .expect("write overlay");
        fs::write(reference.path().join(".DS_Store"), "metadata").expect("write metadata");

        let normalized =
            normalize_lexicon_dirs(&[reference.path().to_path_buf(), overlay.path().to_path_buf()])
                .expect("normalize lexicon dirs");

        let output = fs::read_to_string(normalized.path().join(relative)).expect("read output");
        assert!(output.contains("overlay"));
        assert!(!normalized.path().join(".DS_Store").exists());
    }

    #[test]
    fn accepts_named_closed_union_of_concrete_objects() {
        let lexicon = fixture_with_defs(json!({
            "first": object_definition(),
            "second": object_definition(),
            "choice": {
                "type": "union",
                "refs": ["#first", format!("{FIXTURE_ID}#second")],
                "closed": true
            }
        }));

        validate_fixture(lexicon).expect("valid named closed union");
    }

    #[test]
    fn accepts_explicit_cross_nsid_closed_union_arm() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        let external_id = "blue.catbird.chat.externalFixture";
        write_lexicon_at(
            fixture.path(),
            "primary.json",
            &fixture_with_defs(json!({
                "choice": {
                    "type": "union",
                    "refs": [format!("{external_id}#variant")],
                    "closed": true
                }
            })),
        );
        write_lexicon_at(
            fixture.path(),
            "external.json",
            &json!({
                "lexicon": 1,
                "id": external_id,
                "defs": {
                    "variant": object_definition()
                }
            }),
        );

        validate_strict_union_contracts(fixture.path())
            .expect("explicit cross-NSID object arm is valid");
    }

    #[test]
    fn current_mls_lexicon_corpus_passes_strict_union_preflight() {
        let lexicon_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../lexicon");

        validate_strict_union_contracts(&lexicon_dir).expect("validate current MLS lexicons");
    }

    #[test]
    fn configured_generation_corpus_passes_strict_union_preflight() {
        let codegen_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let normalized = normalize_lexicon_dirs(&[
            codegen_dir.join("../../Petrel/generator/lexicons"),
            codegen_dir.join("../../PetrelCatbird/lexicons"),
        ])
        .expect("normalize configured generation corpus");

        validate_strict_union_contracts(normalized.path())
            .expect("validate configured generation corpus");
    }

    #[test]
    fn configured_generation_corpus_has_unique_lexicon_ids() {
        let codegen_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let normalized = normalize_lexicon_dirs(&[
            codegen_dir.join("../../Petrel/generator/lexicons"),
            codegen_dir.join("../../PetrelCatbird/lexicons"),
        ])
        .expect("normalize configured generation corpus");

        let documents = load_preflight_documents(normalized.path())
            .expect("configured generation corpus lexicon IDs are unique");
        assert!(!documents.is_empty());
    }

    #[test]
    fn rejects_duplicate_lexicon_ids_from_distinct_paths_even_when_identical() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        let first_path = fixture.path().join("first/one.json");
        let second_path = fixture.path().join("second/two.json");
        let lexicon = fixture_with_defs(json!({
            "main": object_definition()
        }));
        let content = serde_json::to_vec_pretty(&lexicon).expect("serialize fixture");
        fs::create_dir_all(first_path.parent().expect("first parent")).expect("first dirs");
        fs::create_dir_all(second_path.parent().expect("second parent")).expect("second dirs");
        fs::write(&first_path, &content).expect("write first fixture");
        fs::write(&second_path, &content).expect("write second fixture");

        let error = validate_strict_union_contracts(fixture.path())
            .expect_err("duplicate lexicon IDs must reject")
            .to_string();

        assert!(error.contains("duplicate lexicon id blue.catbird.chat.unionFixture"));
        assert!(error.contains(&first_path.display().to_string()));
        assert!(error.contains(&second_path.display().to_string()));
    }

    #[test]
    fn reports_json_parse_error_with_offending_preflight_path() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        let malformed_path = fixture.path().join("nested/malformed.json");
        fs::create_dir_all(malformed_path.parent().expect("malformed parent"))
            .expect("malformed dirs");
        fs::write(&malformed_path, "{not-json").expect("write malformed JSON");

        let error = validate_strict_union_contracts(fixture.path())
            .expect_err("malformed JSON must reject")
            .to_string();

        assert!(error.contains(&malformed_path.display().to_string()));
    }

    #[test]
    fn reports_json_parse_error_with_offending_normalization_path() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        let malformed_path = fixture.path().join("nested/malformed.json");
        fs::create_dir_all(malformed_path.parent().expect("malformed parent"))
            .expect("malformed dirs");
        fs::write(&malformed_path, "{not-json").expect("write malformed JSON");

        let error = normalize_lexicon_dirs(&[fixture.path().to_path_buf()])
            .expect_err("malformed JSON must reject during normalization")
            .to_string();

        assert!(error.contains(&malformed_path.display().to_string()));
    }

    #[test]
    fn rejects_named_union_that_is_not_closed() {
        assert_rejected(
            fixture_with_defs(json!({
                "first": object_definition(),
                "choice": { "type": "union", "refs": ["#first"] }
            })),
            "named union must set closed to true",
        );
    }

    #[test]
    fn rejects_empty_closed_union() {
        assert_rejected(
            fixture_with_defs(json!({
                "choice": { "type": "union", "refs": [], "closed": true }
            })),
            "must contain at least one ref",
        );
    }

    #[test]
    fn rejects_closed_union_with_missing_refs() {
        assert_rejected(
            fixture_with_defs(json!({
                "choice": { "type": "union", "closed": true }
            })),
            "must contain a refs array",
        );
    }

    #[test]
    fn rejects_closed_union_with_wrong_refs_type() {
        assert_rejected(
            fixture_with_defs(json!({
                "choice": { "type": "union", "refs": "#first", "closed": true }
            })),
            "must contain a refs array",
        );
    }

    #[test]
    fn rejects_closed_union_with_non_string_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "choice": { "type": "union", "refs": [42], "closed": true }
            })),
            "ref must be a string",
        );
    }

    #[test]
    fn rejects_unresolved_closed_union_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "choice": {
                    "type": "union",
                    "refs": ["blue.catbird.chat.missing#variant"],
                    "closed": true
                }
            })),
            "does not resolve",
        );
    }

    #[test]
    fn rejects_duplicate_canonical_closed_union_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "first": object_definition(),
                "choice": {
                    "type": "union",
                    "refs": ["#first", format!("{FIXTURE_ID}#first")],
                    "closed": true
                }
            })),
            "duplicates canonical ref",
        );
    }

    #[test]
    fn rejects_implicit_main_and_explicit_main_as_canonical_duplicates() {
        assert_rejected(
            fixture_with_defs(json!({
                "main": object_definition(),
                "choice": {
                    "type": "union",
                    "refs": [FIXTURE_ID, format!("{FIXTURE_ID}#main")],
                    "closed": true
                }
            })),
            "duplicates canonical ref",
        );
    }

    #[test]
    fn rejects_malformed_closed_union_refs() {
        for (reference, expected) in [
            ("", "ref is empty"),
            ("blue.catbird.chat.target#", "definition fragment is empty"),
            (
                "blue.catbird.chat.target#variant#extra",
                "more than one fragment separator",
            ),
        ] {
            assert_rejected(
                fixture_with_defs(json!({
                    "choice": { "type": "union", "refs": [reference], "closed": true }
                })),
                expected,
            );
        }
    }

    #[test]
    fn rejects_union_to_union_arm_without_flattening() {
        assert_rejected(
            fixture_with_defs(json!({
                "first": object_definition(),
                "inner": { "type": "union", "refs": ["#first"], "closed": true },
                "outer": { "type": "union", "refs": ["#inner"], "closed": true }
            })),
            "resolves to union, expected object",
        );
    }

    #[test]
    fn rejects_record_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "recordArm": {
                    "type": "record",
                    "key": "tid",
                    "record": object_definition()
                },
                "choice": { "type": "union", "refs": ["#recordArm"], "closed": true }
            })),
            "resolves to record, expected object",
        );
    }

    #[test]
    fn rejects_array_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "arrayArm": { "type": "array", "items": { "type": "string" } },
                "choice": { "type": "union", "refs": ["#arrayArm"], "closed": true }
            })),
            "resolves to array, expected object",
        );
    }

    #[test]
    fn rejects_primitive_arm() {
        assert_rejected(
            fixture_with_defs(json!({
                "primitiveArm": { "type": "string" },
                "choice": { "type": "union", "refs": ["#primitiveArm"], "closed": true }
            })),
            "resolves to string, expected object",
        );
    }

    #[test]
    fn validates_closed_inline_unions_too() {
        assert_rejected(
            fixture_with_defs(json!({
                "main": {
                    "type": "object",
                    "properties": {
                        "choice": {
                            "type": "union",
                            "refs": ["#missing"],
                            "closed": true
                        }
                    }
                }
            })),
            "does not resolve",
        );
    }

    #[test]
    fn leaves_open_inline_primitive_unions_compatible() {
        let lexicon = fixture_with_defs(json!({
            "primitiveArm": { "type": "string" },
            "main": {
                "type": "object",
                "properties": {
                    "choice": {
                        "type": "union",
                        "refs": ["#primitiveArm"]
                    }
                }
            }
        }));
        let fixture = write_fixture(&lexicon);
        validate_strict_union_contracts(fixture.path())
            .expect("open inline primitive union passes preflight");
        let corpus = LexiconCorpus::load_from_dir(fixture.path()).expect("load fixture corpus");
        let codegen = CodeGenerator::new(&corpus, "crate::generated");
        let output = tempfile::tempdir().expect("generated output tempdir");

        codegen
            .write_to_disk(output.path())
            .expect("open inline primitive union remains supported by codegen");
    }

    #[test]
    fn jacquard_generates_closed_enum_with_canonical_serde_tags() {
        let lexicon = fixture_with_defs(json!({
            "first": object_definition(),
            "second": object_definition(),
            "choice": {
                "type": "union",
                "refs": ["#first", format!("{FIXTURE_ID}#second")],
                "closed": true
            }
        }));
        let fixture = write_fixture(&lexicon);
        validate_strict_union_contracts(fixture.path()).expect("preflight valid fixture");
        let corpus = LexiconCorpus::load_from_dir(fixture.path()).expect("load fixture corpus");
        let codegen = CodeGenerator::new(&corpus, "crate::generated");
        let output = tempfile::tempdir().expect("generated output tempdir");
        codegen
            .write_to_disk(output.path())
            .expect("generate fixture corpus");
        let generated =
            fs::read_to_string(output.path().join("blue_catbird/chat/union_fixture.rs"))
                .expect("read generated fixture module");

        assert!(generated.contains(&format!("rename = \"{FIXTURE_ID}#first\"")));
        assert!(generated.contains(&format!("rename = \"{FIXTURE_ID}#second\"")));
        assert!(!generated.contains("open_union"));
    }
}
