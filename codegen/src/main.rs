use clap::Parser;
use jacquard_lexicon::codegen::CodeGenerator;
use jacquard_lexicon::corpus::LexiconCorpus;
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
    let patched = patch_schemaless_json_outputs(&args.outdir)?;
    if patched > 0 {
        println!("  Gave {patched} schemaless application/json output(s) raw-byte codecs");
    }
    let renamed = disambiguate_union_variants(&args.outdir)?;
    if renamed > 0 {
        println!("  Renamed {renamed} colliding union variant(s) by their NSID");
    }

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
        println!("  Normalized {normalized} raw-byte XRPC body schema(s) for Jacquard");
    }
    let inlined = inline_bytes_alias_refs(tempdir.path())?;
    if inlined > 0 {
        println!("  Inlined {inlined} ref(s) to top-level bytes definitions for Jacquard");
    }

    Ok(tempdir)
}

/// Jacquard attaches its DAG-JSON `{"$bytes":…}` serde helper only to
/// properties whose own schema is `bytes`; a ref to a top-level `bytes` def
/// becomes a bare `bytes::Bytes` alias field that neither accepts nor emits
/// the lexicon JSON byte form. Inline each such ref (keeping the referring
/// description) so every byte field gets the helper; the alias type itself is
/// still generated and names the identical Rust type.
fn inline_bytes_alias_refs(lexicon_dir: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let documents = load_preflight_documents(lexicon_dir)?;
    let aliases: BTreeMap<String, Value> = documents
        .values()
        .flat_map(|document| {
            document.defs.iter().filter_map(|(name, schema)| {
                (schema.get("type").and_then(Value::as_str) == Some("bytes"))
                    .then(|| (format!("{}#{name}", document.id), schema.clone()))
            })
        })
        .collect();
    let mut inlined = 0usize;
    for document in documents.values() {
        let mut value: Value = serde_json::from_str(&fs::read_to_string(&document.source_path)?)?;
        let count = inline_bytes_refs(&mut value["defs"], &document.id, &aliases)?;
        if count > 0 {
            fs::write(&document.source_path, serde_json::to_string_pretty(&value)?)?;
            inlined += count;
        }
    }
    Ok(inlined)
}

fn inline_bytes_refs(
    value: &mut Value,
    nsid: &str,
    aliases: &BTreeMap<String, Value>,
) -> Result<usize, Box<dyn std::error::Error>> {
    match value {
        Value::Object(map) if map.get("type").and_then(Value::as_str) == Some("ref") => {
            let reference = map.get("ref").and_then(Value::as_str).unwrap_or_default();
            let target = canonicalize_ref(nsid, reference).map_err(|error| {
                invalid_union_contract(format!("{nsid} ref {reference}: {error}"))
            })?;
            let Some(schema) = aliases.get(&target) else {
                return Ok(0);
            };
            let mut inlined = schema.clone();
            if let Some(description) = map.get("description") {
                inlined["description"] = description.clone();
            }
            *value = inlined;
            Ok(1)
        }
        Value::Object(map) => map
            .values_mut()
            .map(|child| inline_bytes_refs(child, nsid, aliases))
            .sum(),
        Value::Array(items) => items
            .iter_mut()
            .map(|child| inline_bytes_refs(child, nsid, aliases))
            .sum(),
        _ => Ok(0),
    }
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
    collect_files_with_extension(directory, "json", files)
}

fn collect_files_with_extension(
    directory: &Path,
    wanted: &str,
    files: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files_with_extension(&path, wanted, files)?;
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some(wanted)
        {
            files.push(path);
        }
    }

    Ok(())
}

const XRPC_RESP_IMPL: &str = "impl jacquard_common::xrpc::XrpcResp for ";
const JSON_OUTPUT_ENCODING: &str = "const ENCODING: &'static str = \"application/json\";";
const OUTPUT_TYPE_DECL: &str = "type Output<S: jacquard_common::BosStr> = ";

/// Jacquard gives an output with no schema a raw `body: Bytes` struct, and
/// for every encoding except `application/json` it also emits raw
/// `encode_output`/`decode_output`. For a schemaless `application/json`
/// output (a byte-for-byte JSON body, like `labyrinthRelay`'s) it keeps the
/// default JSON codec, which tries to parse the body as `{"body": …}` and
/// fails. Add the same raw codecs to those responses. Returns how many
/// responses were patched; a second run patches none.
fn patch_schemaless_json_outputs(outdir: &Path) -> io::Result<usize> {
    let mut files = Vec::new();
    collect_files_with_extension(outdir, "rs", &mut files)?;
    let mut patched = 0usize;
    for file in files {
        let source = fs::read_to_string(&file)?;
        let (rewritten, count) = patch_schemaless_json_output_source(&source);
        if count > 0 {
            fs::write(&file, rewritten)?;
            patched += count;
        }
    }
    Ok(patched)
}

fn patch_schemaless_json_output_source(source: &str) -> (String, usize) {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    let mut count = 0usize;
    while let Some(start) = rest.find(XRPC_RESP_IMPL) {
        // The impl sits at column 0, so its closing brace is the first
        // `\n}` after it.
        let Some(len) = rest[start..].find("\n}") else {
            break;
        };
        let end = start + len;
        out.push_str(&rest[..end]);
        if let Some(output) = schemaless_json_output(&rest[start..end]) {
            out.push_str(&raw_output_codecs(output));
            count += 1;
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    (out, count)
}

/// The output struct of an `XrpcResp` impl block whose output is schemaless
/// `application/json` without its own codecs.
fn schemaless_json_output(block: &str) -> Option<&str> {
    if !block.contains(JSON_OUTPUT_ENCODING)
        || block.contains("fn encode_output")
        || block.contains("fn decode_output")
    {
        return None;
    }
    let after = &block[block.find(OUTPUT_TYPE_DECL)? + OUTPUT_TYPE_DECL.len()..];
    let ty = after[..after.find(';')?].trim();
    // A schema output is generic (`FooOutput<S>`) and a unit output is `()`.
    let raw = ty.ends_with("Output") && ty.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    raw.then_some(ty)
}

/// The codecs Jacquard emits for a raw output (as in `getAttachmentBlob`).
fn raw_output_codecs(output: &str) -> String {
    format!(
        "
    fn encode_output<S: jacquard_common::BosStr>(
        output: &Self::Output<S>,
    ) -> Result<Vec<u8>, jacquard_common::xrpc::EncodeError>
    where
        Self::Output<S>: serde::Serialize,
    {{
        Ok(output.body.to_vec())
    }}
    fn decode_output<'de, S>(
        body: &'de [u8],
    ) -> Result<Self::Output<S>, jacquard_common::error::DecodeError>
    where
        S: jacquard_common::BosStr + serde::Deserialize<'de>,
        Self::Output<S>: serde::Deserialize<'de>,
    {{
        Ok({output} {{
            body: jacquard_common::deps::bytes::Bytes::copy_from_slice(body),
        }})
    }}"
    )
}

const SERDE_RENAME_PREFIX: &str = "#[serde(rename = \"";

/// Jacquard names a union variant that refers to another lexicon's `main`
/// definition after the last NSID segment, and only disambiguates collisions
/// for refs outside the current two-segment namespace. A union inside
/// `com.atproto` whose arms are `com.atproto.personalspace.policy`,
/// `com.atproto.memberspace.policy` and `com.atproto.managedspace.policy`
/// therefore gets three variants named `Policy`, which does not compile.
/// Prefix each colliding variant with the NSID segment before the one Jacquard
/// used (`PersonalspacePolicy`, ...). The serde tag, and so the wire format,
/// is unchanged. Returns how many variants were renamed; a second run renames
/// none.
fn disambiguate_union_variants(outdir: &Path) -> io::Result<usize> {
    let mut files = Vec::new();
    collect_files_with_extension(outdir, "rs", &mut files)?;
    let mut renamed = 0usize;
    for file in files {
        let source = fs::read_to_string(&file)?;
        let (rewritten, count) = disambiguate_union_variant_source(&source).map_err(|reason| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {reason}", file.display()),
            )
        })?;
        if count > 0 {
            fs::write(&file, rewritten)?;
            renamed += count;
        }
    }
    Ok(renamed)
}

struct TaggedVariant {
    tag: String,
    ident: String,
    ident_start: usize,
}

fn disambiguate_union_variant_source(source: &str) -> Result<(String, usize), String> {
    let mut replacements: Vec<(usize, usize, String)> = Vec::new();
    let mut search = 0usize;
    while let Some(found) = source[search..].find("pub enum ") {
        let name_start = search + found + "pub enum ".len();
        let name_len = source[name_start..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(source.len() - name_start);
        let enum_name = &source[name_start..name_start + name_len];
        let Some(open) = source[name_start..].find('{').map(|i| name_start + i) else {
            break;
        };
        let close =
            matching_brace(source, open).ok_or_else(|| format!("unterminated enum {enum_name}"))?;
        let variants = tagged_variants(source, open, close);
        search = close;

        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for variant in &variants {
            *counts.entry(variant.ident.as_str()).or_default() += 1;
        }
        if counts.values().all(|count| *count == 1) {
            continue;
        }

        let mut final_names: HashSet<String> = HashSet::new();
        let mut planned = Vec::new();
        for variant in &variants {
            let name = if counts[variant.ident.as_str()] > 1 {
                let nsid = variant.tag.split('#').next().unwrap_or_default();
                let segments: Vec<&str> = nsid.split('.').collect();
                if segments.len() < 2 {
                    return Err(format!(
                        "cannot disambiguate {enum_name}::{} for tag {:?}",
                        variant.ident, variant.tag
                    ));
                }
                let qualifier = pascal_case(segments[segments.len() - 2]);
                planned.push((
                    variant.ident_start,
                    variant.ident.clone(),
                    qualifier.clone(),
                ));
                format!("{qualifier}{}", variant.ident)
            } else {
                variant.ident.clone()
            };
            if !final_names.insert(name.clone()) {
                return Err(format!(
                    "union variant {enum_name}::{name} still collides after disambiguation"
                ));
            }
        }
        for ident in counts
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(ident, _)| ident)
        {
            let path = format!("{enum_name}::{ident}");
            if source.contains(&path) {
                return Err(format!(
                    "ambiguous variant reference {path} in generated code"
                ));
            }
        }
        for (start, ident, qualifier) in planned {
            replacements.push((start, start + ident.len(), format!("{qualifier}{ident}")));
        }
    }

    if replacements.is_empty() {
        return Ok((source.to_string(), 0));
    }
    let count = replacements.len();
    let mut out = String::with_capacity(source.len() + count * 16);
    let mut cursor = 0usize;
    for (start, end, replacement) in replacements {
        out.push_str(&source[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(&source[cursor..]);
    Ok((out, count))
}

fn matching_brace(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The `#[serde(rename = "tag")] Ident(` variants between `open` and `close`.
fn tagged_variants(source: &str, open: usize, close: usize) -> Vec<TaggedVariant> {
    let mut variants = Vec::new();
    let mut cursor = open;
    while let Some(found) = source[cursor..close].find(SERDE_RENAME_PREFIX) {
        let tag_start = cursor + found + SERDE_RENAME_PREFIX.len();
        let Some(tag_len) = source[tag_start..close].find('"') else {
            break;
        };
        let tag = &source[tag_start..tag_start + tag_len];
        let after_attr = tag_start + tag_len;
        cursor = after_attr;
        let Some(attr_end) = source[after_attr..close].find(")]") else {
            break;
        };
        let rest = &source[after_attr + attr_end + 2..close];
        let ident_start = after_attr + attr_end + 2 + (rest.len() - rest.trim_start().len());
        let ident_len = source[ident_start..close]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(0);
        let ident = &source[ident_start..ident_start + ident_len];
        if ident.is_empty() || !source[ident_start + ident_len..close].starts_with('(') {
            continue;
        }
        variants.push(TaggedVariant {
            tag: tag.to_string(),
            ident: ident.to_string(),
            ident_start,
        });
        cursor = ident_start + ident_len;
    }
    variants
}

fn pascal_case(segment: &str) -> String {
    let mut chars = segment.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
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
        let value: Value = serde_json::from_str(&content).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "failed to parse JSON file {}: {error}",
                    source_path.display()
                ),
            )
        })?;
        if is_unsupported_space_definition(&value) {
            continue;
        }
        let (normalized_content, normalized_count) =
            normalize_lexicon_value(value).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "failed to parse JSON file {}: {error}",
                        source_path.display()
                    ),
                )
            })?;
        normalized += normalized_count;
        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination_path, normalized_content)?;
    }

    Ok(normalized)
}
fn is_unsupported_space_definition(value: &Value) -> bool {
    let Some(defs) = value.get("defs").and_then(Value::as_object) else {
        return false;
    };
    defs.values()
        .any(|def| def.get("type").and_then(Value::as_str) == Some("space"))
}

fn normalize_lexicon_value(mut value: Value) -> Result<(String, usize), serde_json::Error> {
    let normalized_count = normalize_raw_byte_xrpc_bodies(&mut value);
    let normalized_content = serde_json::to_string_pretty(&value)?;
    Ok((normalized_content, normalized_count))
}

#[allow(dead_code)]
fn normalize_lexicon_json(content: &str) -> Result<(String, usize), serde_json::Error> {
    let value: Value = serde_json::from_str(content)?;
    normalize_lexicon_value(value)
}

#[allow(dead_code)]
fn normalize_unsupported_string_formats(value: &mut Value) -> usize {
    let mut normalized = 0usize;
    match value {
        Value::Object(map) => {
            if let Some(format_val) = map.get("format") {
                if format_val.as_str() == Some("space-ref") {
                    map.remove("format");
                    normalized += 1;
                }
            }
            for child in map.values_mut() {
                normalized += normalize_unsupported_string_formats(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                normalized += normalize_unsupported_string_formats(item);
            }
        }
        _ => {}
    }
    normalized
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
    use super::disambiguate_union_variants;
    use super::load_preflight_documents;
    use super::normalize_lexicon_dirs;
    use super::normalize_raw_byte_xrpc_bodies;
    use super::patch_schemaless_json_outputs;
    use super::validate_strict_union_contracts;
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
    fn test_jacquard_corpus_with_space_type() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        let lexicon = json!({
            "lexicon": 1,
            "id": "blue.catbird.circle",
            "defs": {
                "main": {
                    "type": "space",
                    "key": "tid",
                    "name": "Catbird Circle",
                    "description": "An author-owned private posting audience",
                    "collections": [
                        "blue.catbird.circle.metadata",
                        "app.bsky.feed.post",
                        "app.bsky.feed.like"
                    ]
                }
            }
        });
        write_lexicon_at(fixture.path(), "circle.json", &lexicon);
        let err = LexiconCorpus::load_from_dir(fixture.path()).unwrap_err();
        println!("load_from_dir error: {:?}", err);
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

    #[test]
    fn bytes_alias_refs_get_the_dag_json_bytes_helper() {
        let lexicon = fixture_with_defs(json!({
            "digest": { "type": "bytes", "minLength": 32, "maxLength": 32 },
            "main": {
                "type": "object",
                "required": ["local"],
                "properties": {
                    "local": { "type": "ref", "ref": "#digest", "description": "kept" },
                    "absolute": { "type": "ref", "ref": format!("{FIXTURE_ID}#digest") }
                }
            }
        }));
        let fixture = write_fixture(&lexicon);
        let normalized =
            normalize_lexicon_dirs(&[fixture.path().to_path_buf()]).expect("normalize fixture");
        let corpus = LexiconCorpus::load_from_dir(normalized.path()).expect("load fixture corpus");
        let output = tempfile::tempdir().expect("generated output tempdir");
        CodeGenerator::new(&corpus, "crate::generated")
            .write_to_disk(output.path())
            .expect("generate fixture corpus");
        let generated =
            fs::read_to_string(output.path().join("blue_catbird/chat/union_fixture.rs"))
                .expect("read generated fixture module");
        let compact: String = generated.split_whitespace().collect();
        assert!(compact.contains(
            "#[serde(default,with=\"jacquard_common::opt_serde_bytes_helper\")]pubabsolute:"
        ));
        assert!(compact.contains("#[serde(with=\"jacquard_common::serde_bytes_helper\")]publocal:"));
        assert!(generated.contains("kept"));
    }

    fn procedure_fixture(output: Value) -> Value {
        json!({
            "lexicon": 1,
            "id": FIXTURE_ID,
            "defs": {
                "main": {
                    "type": "procedure",
                    "input": { "encoding": "application/json", "schema": object_definition() },
                    "output": output
                }
            }
        })
    }

    fn generate_and_patch(lexicon: &Value) -> (String, usize, usize) {
        let fixture = write_fixture(lexicon);
        let corpus = LexiconCorpus::load_from_dir(fixture.path()).expect("load fixture corpus");
        let output = tempfile::tempdir().expect("generated output tempdir");
        CodeGenerator::new(&corpus, "crate::generated")
            .write_to_disk(output.path())
            .expect("generate fixture corpus");
        let first = patch_schemaless_json_outputs(output.path()).expect("patch outputs");
        let second = patch_schemaless_json_outputs(output.path()).expect("patch outputs again");
        let generated =
            fs::read_to_string(output.path().join("blue_catbird/chat/union_fixture.rs"))
                .expect("read generated fixture module");
        (generated, first, second)
    }

    #[test]
    fn schemaless_json_outputs_get_raw_byte_codecs() {
        let (generated, first, second) = generate_and_patch(&procedure_fixture(
            json!({ "encoding": "application/json", "description": "byte for byte" }),
        ));
        assert_eq!((first, second), (1, 0));
        let compact: String = generated.split_whitespace().collect();
        assert!(compact.contains("Ok(output.body.to_vec())"));
        assert!(compact.contains(
            "Ok(UnionFixtureOutput{body:jacquard_common::deps::bytes::Bytes::copy_from_slice(body),})"
        ));
    }

    #[test]
    fn schema_json_outputs_keep_the_json_codec() {
        let (generated, first, _) = generate_and_patch(&procedure_fixture(
            json!({ "encoding": "application/json", "schema": object_definition() }),
        ));
        assert_eq!(first, 0);
        assert!(!generated.contains("fn decode_output"));
    }

    #[test]
    fn colliding_main_union_arms_get_nsid_qualified_variants() {
        let fixture = tempfile::tempdir().expect("fixture tempdir");
        for (relative, id) in [
            ("first.json", "blue.catbird.alpha.policy"),
            ("second.json", "blue.catbird.beta.policy"),
        ] {
            write_lexicon_at(
                fixture.path(),
                relative,
                &json!({ "lexicon": 1, "id": id, "defs": { "main": object_definition() } }),
            );
        }
        write_lexicon_at(
            fixture.path(),
            "holder.json",
            &json!({
                "lexicon": 1,
                "id": "blue.catbird.holder",
                "defs": { "main": {
                    "type": "object",
                    "required": ["policy"],
                    "properties": { "policy": {
                        "type": "union",
                        "refs": ["blue.catbird.alpha.policy", "blue.catbird.beta.policy"]
                    } }
                } }
            }),
        );
        let corpus = LexiconCorpus::load_from_dir(fixture.path()).expect("load fixture corpus");
        let output = tempfile::tempdir().expect("generated output tempdir");
        CodeGenerator::new(&corpus, "crate::generated")
            .write_to_disk(output.path())
            .expect("generate fixture corpus");
        let path = output.path().join("blue_catbird/holder.rs");
        let before = fs::read_to_string(&path).expect("read generated holder");
        let compact: String = before.split_whitespace().collect();
        assert_eq!(compact.matches("Policy(Box<").count(), 2, "{before}");

        let first = disambiguate_union_variants(output.path()).expect("rename variants");
        let second = disambiguate_union_variants(output.path()).expect("rename again");
        assert_eq!((first, second), (2, 0));
        let after: String = fs::read_to_string(&path)
            .expect("read patched holder")
            .split_whitespace()
            .collect();
        assert!(after.contains("#[serde(rename=\"blue.catbird.alpha.policy\")]AlphaPolicy(Box<"));
        assert!(after.contains("#[serde(rename=\"blue.catbird.beta.policy\")]BetaPolicy(Box<"));
    }
}
