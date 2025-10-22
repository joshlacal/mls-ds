import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Mock MLS server for testing without network dependencies
public class MockMLSServer {
    public static let shared = MockMLSServer()
    
    private var conversations: [String: MockConversation] = [:]
    private var messages: [String: [MockMessage]] = [:]
    private var keyPackages: [String: [MockKeyPackage]] = [:]
    private var members: [String: Set<String>] = [:]
    private var blobs: [String: Data] = [:]
    
    public var shouldSimulateNetworkError = false
    public var shouldSimulateTimeout = false
    public var networkDelay: TimeInterval = 0.1
    public var authToken: String? = "mock_token"
    
    private init() {}
    
    // MARK: - Reset
    
    public func reset() {
        conversations.removeAll()
        messages.removeAll()
        keyPackages.removeAll()
        members.removeAll()
        blobs.removeAll()
        shouldSimulateNetworkError = false
        shouldSimulateTimeout = false
        networkDelay = 0.1
        authToken = "mock_token"
    }
    
    // MARK: - Conversation Operations
    
    public func createConversation(members: [String], title: String?, createdBy: String) async throws -> MockConversation {
        try await simulateNetwork()
        
        let convo = MockConversation(
            id: TestData.generateConvoId(),
            members: members,
            title: title,
            epoch: 1,
            createdAt: Date(),
            createdBy: createdBy,
            unreadCount: 0
        )
        
        conversations[convo.id] = convo
        self.members[convo.id] = Set(members)
        messages[convo.id] = []
        
        return convo
    }
    
    public func getConversation(_ convoId: String) async throws -> MockConversation {
        try await simulateNetwork()
        
        guard let convo = conversations[convoId] else {
            throw MockError.notFound
        }
        return convo
    }
    
    public func listConversations(for did: String) async throws -> [MockConversation] {
        try await simulateNetwork()
        
        return conversations.values.filter { convo in
            members[convo.id]?.contains(did) ?? false
        }
    }
    
    // MARK: - Member Operations
    
    public func addMembers(to convoId: String, dids: [String]) async throws {
        try await simulateNetwork()
        
        guard var convo = conversations[convoId] else {
            throw MockError.notFound
        }
        
        var memberSet = members[convoId] ?? Set()
        for did in dids {
            if memberSet.contains(did) {
                throw MockError.conflict
            }
            memberSet.insert(did)
        }
        
        convo.members = Array(memberSet)
        convo.epoch += 1
        conversations[convoId] = convo
        members[convoId] = memberSet
    }
    
    public func removeMember(from convoId: String, did: String) async throws {
        try await simulateNetwork()
        
        guard var convo = conversations[convoId] else {
            throw MockError.notFound
        }
        
        var memberSet = members[convoId] ?? Set()
        guard memberSet.contains(did) else {
            throw MockError.notFound
        }
        
        memberSet.remove(did)
        convo.members = Array(memberSet)
        convo.epoch += 1
        conversations[convoId] = convo
        members[convoId] = memberSet
    }
    
    public func isMember(convoId: String, did: String) -> Bool {
        return members[convoId]?.contains(did) ?? false
    }
    
    // MARK: - Message Operations
    
    public func sendMessage(to convoId: String, ciphertext: String, epoch: Int, senderDid: String) async throws {
        try await simulateNetwork()
        
        guard let convo = conversations[convoId] else {
            throw MockError.notFound
        }
        
        guard isMember(convoId: convoId, did: senderDid) else {
            throw MockError.unauthorized
        }
        
        if epoch != convo.epoch {
            throw MockError.epochMismatch
        }
        
        let message = MockMessage(
            id: UUID().uuidString,
            convoId: convoId,
            ciphertext: ciphertext,
            epoch: epoch,
            senderDid: senderDid,
            sentAt: Date()
        )
        
        messages[convoId, default: []].append(message)
    }
    
    public func getMessages(for convoId: String, since: String? = nil) async throws -> [MockMessage] {
        try await simulateNetwork()
        
        guard conversations[convoId] != nil else {
            throw MockError.notFound
        }
        
        var msgs = messages[convoId] ?? []
        
        if let sinceId = since, let index = msgs.firstIndex(where: { $0.id == sinceId }) {
            msgs = Array(msgs.suffix(from: index + 1))
        }
        
        return msgs
    }
    
    // MARK: - Key Package Operations
    
    public func publishKeyPackage(did: String, keyPackage: String, cipherSuite: String, expires: Date) async throws {
        try await simulateNetwork()
        
        let pkg = MockKeyPackage(
            did: did,
            keyPackage: keyPackage,
            cipherSuite: cipherSuite,
            expires: expires
        )
        
        keyPackages[did, default: []].append(pkg)
    }
    
    public func getKeyPackages(for dids: [String]) async throws -> [MockKeyPackage] {
        try await simulateNetwork()
        
        var packages: [MockKeyPackage] = []
        for did in dids {
            if let pkgs = keyPackages[did]?.filter({ $0.expires > Date() }), let pkg = pkgs.first {
                packages.append(pkg)
            }
        }
        return packages
    }
    
    // MARK: - Blob Operations
    
    public func uploadBlob(_ data: Data) async throws -> String {
        try await simulateNetwork()
        
        let cid = TestData.generateCID()
        blobs[cid] = data
        return cid
    }
    
    public func getBlob(_ cid: String) async throws -> Data {
        try await simulateNetwork()
        
        guard let data = blobs[cid] else {
            throw MockError.notFound
        }
        return data
    }
    
    // MARK: - Network Simulation
    
    private func simulateNetwork() async throws {
        if shouldSimulateTimeout {
            throw MockError.timeout
        }
        
        if shouldSimulateNetworkError {
            throw MockError.networkError
        }
        
        if networkDelay > 0 {
            try await Task.sleep(nanoseconds: UInt64(networkDelay * 1_000_000_000))
        }
    }
}

// MARK: - Mock Types

public struct MockConversation {
    public let id: String
    public var members: [String]
    public let title: String?
    public var epoch: Int
    public let createdAt: Date
    public let createdBy: String
    public var unreadCount: Int
}

public struct MockMessage {
    public let id: String
    public let convoId: String
    public let ciphertext: String
    public let epoch: Int
    public let senderDid: String
    public let sentAt: Date
}

public struct MockKeyPackage {
    public let did: String
    public let keyPackage: String
    public let cipherSuite: String
    public let expires: Date
}

public enum MockError: Error {
    case notFound
    case unauthorized
    case conflict
    case epochMismatch
    case networkError
    case timeout
    case invalidRequest
}
