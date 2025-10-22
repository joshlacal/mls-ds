import Foundation

/// Test data generators for MLS integration tests
public struct TestData {
    
    // MARK: - User/DID Generation
    
    public static func generateDID(_ index: Int = 0) -> String {
        return "did:plc:test\(String(format: "%06d", index))"
    }
    
    public static func generateMultipleDIDs(count: Int) -> [String] {
        return (0..<count).map { generateDID($0) }
    }
    
    // MARK: - Key Package Generation
    
    public static func generateKeyPackage(for did: String, cipherSuite: String = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519") -> String {
        // Simulated base64-encoded key package
        let data = "\(did)_\(cipherSuite)_\(UUID().uuidString)".data(using: .utf8)!
        return data.base64EncodedString()
    }
    
    public static func generateKeyPackages(for dids: [String], cipherSuite: String = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519") -> [String: String] {
        var packages: [String: String] = [:]
        for did in dids {
            packages[did] = generateKeyPackage(for: did, cipherSuite: cipherSuite)
        }
        return packages
    }
    
    // MARK: - Message Generation
    
    public static func generateCiphertext(_ plaintext: String = "Test message") -> String {
        let data = "\(plaintext)_\(UUID().uuidString)".data(using: .utf8)!
        return data.base64EncodedString()
    }
    
    public static func generateMessages(count: Int, convoId: String, senderDID: String) -> [TestMessage] {
        return (0..<count).map { index in
            TestMessage(
                id: UUID().uuidString,
                convoId: convoId,
                senderDid: senderDID,
                ciphertext: generateCiphertext("Message \(index)"),
                epoch: 1,
                sentAt: Date().addingTimeInterval(TimeInterval(index * 60))
            )
        }
    }
    
    // MARK: - Conversation Generation
    
    public static func generateConvoId() -> String {
        return "convo_\(UUID().uuidString)"
    }
    
    public static func generateConversation(members: [String], title: String? = nil) -> TestConversation {
        return TestConversation(
            id: generateConvoId(),
            members: members,
            title: title ?? "Test Conversation",
            epoch: 1,
            createdAt: Date(),
            createdBy: members.first ?? generateDID(0)
        )
    }
    
    // MARK: - Blob Generation
    
    public static func generateBlob(size: Int = 1024) -> Data {
        var data = Data(count: size)
        data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else { return }
            arc4random_buf(baseAddress, size)
        }
        return data
    }
    
    public static func generateCID() -> String {
        return "bafyrei\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(52))"
    }
    
    // MARK: - Test Scenarios
    
    public static func multiDeviceScenario() -> MultiDeviceScenario {
        let user = generateDID(1)
        return MultiDeviceScenario(
            userDID: user,
            devices: [
                DeviceInfo(id: "device1", keyPackage: generateKeyPackage(for: "\(user)_device1")),
                DeviceInfo(id: "device2", keyPackage: generateKeyPackage(for: "\(user)_device2")),
                DeviceInfo(id: "device3", keyPackage: generateKeyPackage(for: "\(user)_device3"))
            ]
        )
    }
    
    public static func groupConversationScenario(memberCount: Int = 5) -> GroupScenario {
        let members = generateMultipleDIDs(count: memberCount)
        return GroupScenario(
            convoId: generateConvoId(),
            members: members,
            admin: members[0],
            keyPackages: generateKeyPackages(for: members)
        )
    }
    
    // MARK: - Error Scenarios
    
    public static func errorScenarios() -> [ErrorScenario] {
        return [
            ErrorScenario(name: "Invalid DID", type: .invalidDID, expectedCode: 400),
            ErrorScenario(name: "Unauthorized Access", type: .unauthorized, expectedCode: 401),
            ErrorScenario(name: "Conversation Not Found", type: .notFound, expectedCode: 404),
            ErrorScenario(name: "Duplicate Member", type: .conflict, expectedCode: 409),
            ErrorScenario(name: "Network Timeout", type: .timeout, expectedCode: 408),
            ErrorScenario(name: "Invalid Key Package", type: .invalidKeyPackage, expectedCode: 400),
            ErrorScenario(name: "Epoch Mismatch", type: .epochMismatch, expectedCode: 409),
            ErrorScenario(name: "Rate Limited", type: .rateLimited, expectedCode: 429)
        ]
    }
}

// MARK: - Supporting Types

public struct TestMessage {
    public let id: String
    public let convoId: String
    public let senderDid: String
    public let ciphertext: String
    public let epoch: Int
    public let sentAt: Date
}

public struct TestConversation {
    public let id: String
    public let members: [String]
    public let title: String
    public let epoch: Int
    public let createdAt: Date
    public let createdBy: String
}

public struct DeviceInfo {
    public let id: String
    public let keyPackage: String
}

public struct MultiDeviceScenario {
    public let userDID: String
    public let devices: [DeviceInfo]
}

public struct GroupScenario {
    public let convoId: String
    public let members: [String]
    public let admin: String
    public let keyPackages: [String: String]
}

public struct ErrorScenario {
    public let name: String
    public let type: ErrorType
    public let expectedCode: Int
    
    public enum ErrorType {
        case invalidDID
        case unauthorized
        case notFound
        case conflict
        case timeout
        case invalidKeyPackage
        case epochMismatch
        case rateLimited
    }
}
