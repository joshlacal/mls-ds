import CryptoKit
import Foundation
import Petrel
import PetrelCatbird

private enum ProducerError: Error {
    case invalid(String)
}

private func require(_ condition: Bool, _ message: String) throws {
    if !condition { throw ProducerError.invalid(message) }
}

private func dictionary(_ value: Any, _ label: String) throws -> [String: Any] {
    guard let value = value as? [String: Any] else {
        throw ProducerError.invalid("Expected object: \(label)")
    }
    return value
}

private func loadJSON(_ path: URL) throws -> [String: Any] {
    try dictionary(JSONSerialization.jsonObject(with: Data(contentsOf: path)), path.path)
}

private func unhex(_ value: String) throws -> Data {
    try require(value.count.isMultiple(of: 2), "Odd-length hex")
    var result = Data()
    var index = value.startIndex
    while index != value.endIndex {
        let end = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<end], radix: 16) else {
            throw ProducerError.invalid("Invalid hex")
        }
        result.append(byte)
        index = end
    }
    return result
}

private func sha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func requireKnownUnions(_ value: Any, path: String = "root") throws {
    if value is Data || value is String || value is Date { return }
    let mirror = Mirror(reflecting: value)
    for child in mirror.children {
        let label = child.label ?? "item"
        try require(!(mirror.displayStyle == .enum && label == "unexpected"),
                    "Generated decoder used an unknown-union fallback at \(path)")
        try requireKnownUnions(child.value, path: path + "." + label)
    }
}

private func emittedTags(_ value: Any, path: String = "") -> [String: String] {
    var result: [String: String] = [:]
    if let object = value as? [String: Any] {
        if let tag = object["$type"] as? String { result[path] = tag }
        for (key, child) in object where key != "$type" {
            result.merge(emittedTags(child, path: path + "/" + key)) { _, new in new }
        }
    } else if let array = value as? [Any] {
        for (index, child) in array.enumerated() {
            result.merge(emittedTags(child, path: path + "/" + String(index))) { _, new in new }
        }
    }
    return result
}

/// Materialize the semantic corpus notation according to the real lexicon.
/// This only prepares decoder input: emitted request bytes always come from
/// JSONEncoder encoding actual generated PetrelCatbird values below.
private func decoderInput(_ value: Any, schema: [String: Any], defs: [String: Any]) throws -> Any {
    switch schema["type"] as? String {
    case "ref":
        guard let ref = schema["ref"] as? String,
              let definition = defs[String(ref.split(separator: "#").last ?? "")] as? [String: Any] else {
            throw ProducerError.invalid("Unresolved schema ref")
        }
        return try decoderInput(value, schema: definition, defs: defs)
    case "union":
        let object = try dictionary(value, "union")
        guard let tag = object["$type"] as? String,
              let refs = schema["refs"] as? [String],
              refs.contains(where: { "blue.catbird.chat.defs" + $0 == tag }),
              let definition = defs[String(tag.split(separator: "#").last ?? "")] as? [String: Any] else {
            throw ProducerError.invalid("Unknown or missing concrete union type")
        }
        return try decoderInput(value, schema: definition, defs: defs)
    case "object":
        let object = try dictionary(value, "object")
        let properties = try dictionary(schema["properties"] ?? [:], "properties")
        var result: [String: Any] = [:]
        for (key, child) in object {
            if key == "$type" { result[key] = child; continue }
            guard let childSchema = properties[key] as? [String: Any] else {
                throw ProducerError.invalid("Unknown source field \(key)")
            }
            result[key] = try decoderInput(child, schema: childSchema, defs: defs)
        }
        return result
    case "array":
        guard let items = value as? [Any], let itemSchema = schema["items"] as? [String: Any] else {
            throw ProducerError.invalid("Invalid array input")
        }
        return try items.map { try decoderInput($0, schema: itemSchema, defs: defs) }
    case "bytes":
        let encoded: String
        if let string = value as? String {
            encoded = string
        } else {
            let object = try dictionary(value, "bytes")
            if let hex = object["$bytesHex"] as? String, object.count == 1 {
                encoded = try unhex(hex).base64EncodedString()
            } else if let uuid = object["$uuid"] as? String, object.count == 1 {
                guard UUID(uuidString: uuid) != nil else { throw ProducerError.invalid("Invalid UUID") }
                encoded = try unhex(uuid.replacingOccurrences(of: "-", with: "")).base64EncodedString()
            } else if let bytes = object["$bytes"] as? String, object.count == 1 {
                encoded = bytes
            } else {
                throw ProducerError.invalid("Unrecognized semantic bytes")
            }
        }
        guard let bytes = Data(base64Encoded: encoded), bytes.base64EncodedString() == encoded else {
            throw ProducerError.invalid("Noncanonical source base64")
        }
        return ["$bytes": encoded]
    case "string":
        if let object = value as? [String: Any], let uuid = object["$uuid"] as? String, object.count == 1 {
            return uuid
        }
        try require(value is String, "Expected string source value")
        return value
    case "integer", "boolean":
        return value
    default:
        throw ProducerError.invalid("Unsupported fixture schema type \(schema["type"] ?? "missing")")
    }
}

private let variants: [(name: String, wrapper: String, body: String)] = [
    ("commit", "signedCommitTransition", "commitTransitionBody"),
    ("policy", "signedPolicyTransition", "policyTransitionBody"),
    ("metadata", "signedMetadataTransition", "metadataTransitionBody"),
    ("recovery", "signedLeafRecoveryFulfillment", "leafRecoveryFulfillmentBody"),
    ("leave", "signedLeaveCommitFulfillment", "leaveCommitFulfillmentBody"),
]

/// Concrete generated body decoding recursively instantiates generated nested
/// coordinates, AAD, metadata, manifest, Welcome, and union types. Wrapper and
/// endpoint input are then constructed using the generated initializers.
private func typedInput(body: Any, signature: String, variant: String) throws -> BlueCatbirdChatSubmitTransition.Input {
    let decoder = JSONDecoder()
    let bodyData = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    guard let signatureBytes = Data(base64Encoded: signature), signatureBytes.count == 64 else {
        throw ProducerError.invalid("Expected 64-byte source signature")
    }
    let bytes = Bytes(data: signatureBytes)
    let signed: BlueCatbirdChatDefs.SignedTransition
    switch variant {
    case "commit":
        let value = try decoder.decode(BlueCatbirdChatDefs.CommitTransitionBody.self, from: bodyData)
        signed = .init(BlueCatbirdChatDefs.SignedCommitTransition(
            body: .blueCatbirdChatDefsCommitTransitionBody(value), signature: bytes))
    case "policy":
        let value = try decoder.decode(BlueCatbirdChatDefs.PolicyTransitionBody.self, from: bodyData)
        signed = .init(BlueCatbirdChatDefs.SignedPolicyTransition(
            body: .blueCatbirdChatDefsPolicyTransitionBody(value), signature: bytes))
    case "metadata":
        let value = try decoder.decode(BlueCatbirdChatDefs.MetadataTransitionBody.self, from: bodyData)
        signed = .init(BlueCatbirdChatDefs.SignedMetadataTransition(
            body: .blueCatbirdChatDefsMetadataTransitionBody(value), signature: bytes))
    case "recovery":
        let value = try decoder.decode(BlueCatbirdChatDefs.LeafRecoveryFulfillmentBody.self, from: bodyData)
        signed = .init(BlueCatbirdChatDefs.SignedLeafRecoveryFulfillment(
            body: .blueCatbirdChatDefsLeafRecoveryFulfillmentBody(value), signature: bytes))
    case "leave":
        let value = try decoder.decode(BlueCatbirdChatDefs.LeaveCommitFulfillmentBody.self, from: bodyData)
        signed = .init(BlueCatbirdChatDefs.SignedLeaveCommitFulfillment(
            body: .blueCatbirdChatDefsLeaveCommitFulfillmentBody(value), signature: bytes))
    default:
        throw ProducerError.invalid("Unsupported variant \(variant)")
    }
    return .init(signedRequest: signed)
}

private func encodeCase(name: String, variant: String, body: Any, signature: String,
                        defs: [String: Any], output: URL) throws -> [String: Any] {
    guard let specification = variants.first(where: { $0.name == variant }),
          let schema = defs[specification.body] as? [String: Any] else {
        throw ProducerError.invalid("Missing variant schema")
    }
    try require(try dictionary(body, "body")["$type"] as? String == "blue.catbird.chat.defs#" + specification.body,
                "Source body tag differs from selected variant")
    let prepared = try decoderInput(body, schema: schema, defs: defs)
    let input = try typedInput(body: prepared, signature: signature, variant: variant)
    try requireKnownUnions(input)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    let encoded = try encoder.encode(input)
    let wrapper = try encoder.encode(input.signedRequest)
    let tags = emittedTags(try JSONSerialization.jsonObject(with: encoded))
    if name == "recovery-nonempty" {
        let prefix = "/signedRequest/body/manifest/"
        for (suffix, type) in [
            ("leafChanges/0", "addLeafByRecovery"),
            ("welcomeBundle", "welcomeBundle"),
            ("welcomeBundle/deliveries/0", "welcomeDelivery"),
            ("welcomeBundle/deliveries/0/provenance", "recoveryWelcomeProvenance"),
        ] {
            try require(tags[prefix + suffix] == "blue.catbird.chat.defs#" + type,
                        "Supplemental recovery did not encode the required nested \(type)")
        }
    }
    try require(encoded == Data("{\"signedRequest\":".utf8) + wrapper + Data("}".utf8),
                "Wrapper bytes differ from the exact request slice")
    let decoded = try JSONDecoder().decode(BlueCatbirdChatSubmitTransition.Input.self, from: encoded)
    try require(decoded.signedRequest == input.signedRequest, "Generated typed roundtrip changed a value")
    try require(try encoder.encode(decoded) == encoded, "Generated encoding is not byte-stable")
    let requestName = "swift-\(name).request.json"
    let wrapperName = "swift-\(name).wrapper.json"
    try encoded.write(to: output.appendingPathComponent(requestName))
    try wrapper.write(to: output.appendingPathComponent(wrapperName))
    return [
        "name": name,
        "variant": variant,
        "wrapperType": "blue.catbird.chat.defs#" + specification.wrapper,
        "bodyType": "blue.catbird.chat.defs#" + specification.body,
        "requestFile": requestName,
        "requestSHA256": sha256(encoded),
        "requestBytes": encoded.count,
        "wrapperFile": wrapperName,
        "wrapperSHA256": sha256(wrapper),
        "wrapperBytes": wrapper.count,
        "generatedTypedRoundtrip": true,
        "emittedTypeTags": tags,
    ]
}

private func decodeResponse(kind: String, path: URL) throws {
    let bytes = try Data(contentsOf: path)
    let decoder = JSONDecoder()
    switch kind {
    case "submitTransition":
        let value = try decoder.decode(BlueCatbirdChatSubmitTransition.Output.self, from: bytes)
        try requireKnownUnions(value)
        _ = try JSONEncoder().encode(value)
    case "getEntries":
        let value = try decoder.decode(BlueCatbirdChatGetEntries.Output.self, from: bytes)
        try requireKnownUnions(value)
        _ = try JSONEncoder().encode(value)
    case "getConversationState":
        let value = try decoder.decode(BlueCatbirdChatGetConversationState.Output.self, from: bytes)
        try requireKnownUnions(value)
        _ = try JSONEncoder().encode(value)
    default:
        throw ProducerError.invalid("Unknown response kind \(kind)")
    }
    print("Generated \(kind).Output decoded and re-encoded \(bytes.count) server-response bytes (sha256 \(sha256(bytes)))")
}

private func run() throws {
    let args = Array(CommandLine.arguments.dropFirst())
    if args.count == 3 && args[0] == "decode-response" {
        try decodeResponse(kind: args[1], path: URL(fileURLWithPath: args[2]))
        return
    }
    if args.count == 5 && args[0] == "encode-wrapper" {
        let workspace = URL(fileURLWithPath: args[1])
        let inputPath = URL(fileURLWithPath: args[3])
        let output = URL(fileURLWithPath: args[4])
        let sourceBytes = try Data(contentsOf: inputPath)
        let wrapper = try dictionary(JSONSerialization.jsonObject(with: sourceBytes), "wrapper")
        let schema = try loadJSON(workspace.appendingPathComponent("PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json"))
        let defs = try dictionary(schema["defs"] as Any, "defs")
        guard let body = wrapper["body"], let signature = wrapper["signature"] as? String else {
            throw ProducerError.invalid("Expected canonical wrapper with body and bare signature")
        }
        try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        var record = try encodeCase(name: args[2], variant: args[2], body: body,
                                    signature: signature, defs: defs, output: output)
        record["canonicalInputSHA256"] = sha256(sourceBytes)
        let receipt = try JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try (receipt + Data("\n".utf8)).write(to: output.appendingPathComponent("serialization.json"))
        print("Encoded actual generated Swift \(args[2]) input from supplied canonical signed wrapper")
        return
    }
    guard args.count == 3 && args[0] == "generate" else {
        throw ProducerError.invalid("Usage: generate <workspace> <output-dir> | encode-wrapper <workspace> <variant> <json-file> <output-dir> | decode-response <kind> <json-file>")
    }
    let workspace = URL(fileURLWithPath: args[1])
    let output = URL(fileURLWithPath: args[2])
    let fixtures = workspace.appendingPathComponent("mls-ds/server/tests/fixtures")
    let source = try loadJSON(fixtures.appendingPathComponent("mls_chat_control_fingerprint_source.json"))
    let vectors = try loadJSON(fixtures.appendingPathComponent("mls_chat_contract_vectors.json"))
    let fingerprints = try dictionary(vectors["controlEntryFingerprints"] as Any, "fingerprints")
    let schema = try loadJSON(workspace.appendingPathComponent("PetrelCatbird/lexicons/blue/catbird/chat/blue.catbird.chat.defs.json"))
    let defs = try dictionary(schema["defs"] as Any, "defs")
    guard let sourceCases = source["cases"] as? [[String: Any]],
          let vectorCases = fingerprints["cases"] as? [[String: Any]],
          let publicKeys = fingerprints["historicalPublicKeys"] as? [String: String] else {
        throw ProducerError.invalid("Invalid frozen corpus shape")
    }
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    var records: [[String: Any]] = []
    for variant in variants {
        let tag = "blue.catbird.chat.defs#" + variant.wrapper
        guard let fields = sourceCases.first(where: { $0["signedRequestRef"] as? String == tag }),
              let vector = vectorCases.first(where: { $0["signedRequestRef"] as? String == tag }),
              let body = fields["body"], let signature = vector["signature"] as? String,
              let keyRef = vector["historicalPublicKeyRef"] as? String else {
            throw ProducerError.invalid("Missing frozen variant \(variant.name)")
        }
        var record = try encodeCase(name: variant.name, variant: variant.name, body: body,
                                    signature: signature, defs: defs, output: output)
        record["source"] = "../mls_chat_control_fingerprint_source.json"
        record["expectedSource"] = "../mls_chat_contract_vectors.json#/controlEntryFingerprints/cases"
        record["expected"] = [
            "publicKeyHex": publicKeys[keyRef] as Any,
            "unsignedSigningProjectionCanonicalDagCborHex": vector["unsignedSigningProjectionCanonicalDagCborHex"] as Any,
            "signingTranscriptHex": vector["signingTranscriptHex"] as Any,
            "requestDigest": vector["requestDigest"] as Any,
            "signature": signature,
        ]
        records.append(record)
    }
    let supplemental = fixtures.appendingPathComponent("generated_transitions/inputs/recovery-nonempty.canonical.json")
    try require(FileManager.default.fileExists(atPath: supplemental.path),
                "Required nonempty recovery input is absent: \(supplemental.path)")
    do {
        let wrapper = try loadJSON(supplemental)
        let expected = try loadJSON(supplemental.deletingLastPathComponent().appendingPathComponent("recovery-nonempty.expected.json"))
        guard let body = wrapper["body"], let signature = wrapper["signature"] as? String else {
            throw ProducerError.invalid("Invalid supplemental wrapper")
        }
        var record = try encodeCase(name: "recovery-nonempty", variant: "recovery", body: body,
                                    signature: signature, defs: defs, output: output)
        record["source"] = "inputs/recovery-nonempty.canonical.json"
        record["expectedSource"] = "inputs/recovery-nonempty.expected.json"
        record["expected"] = expected
        records.append(record)
    }
    let index: [String: Any] = [
        "schemaVersion": 1,
        "serializer": "JSONEncoder.encode(BlueCatbirdChatSubmitTransition.Input)",
        "encoderFormatting": ["sortedKeys", "withoutEscapingSlashes"],
        "cases": records,
    ]
    let indexBytes = try JSONSerialization.data(withJSONObject: index, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    try (indexBytes + Data("\n".utf8)).write(to: output.appendingPathComponent("swift-fixtures.json"))
    print("Encoded \(records.count) actual generated Swift transition inputs; every typed roundtrip matched exact bytes")
}

do {
    try run()
} catch {
    FileHandle.standardError.write(Data("GeneratedTransitionProducer: \(error)\n".utf8))
    exit(1)
}
