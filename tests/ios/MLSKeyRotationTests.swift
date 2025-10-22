import XCTest
@testable import CatbirdChat

/// End-to-end tests for MLS key rotation and epoch management
final class MLSKeyRotationTests: XCTestCase {
    
    var mockServer: MockMLSServer!
    var client: CatbirdClient!
    
    override func setUp() {
        super.setUp()
        mockServer = MockMLSServer.shared
        mockServer.reset()
        client = CatbirdClient(baseURL: "http://localhost:8080")
        client.setAuthToken(mockServer.authToken ?? "")
    }
    
    override func tearDown() {
        mockServer.reset()
        super.tearDown()
    }
    
    // MARK: - Key Package Tests
    
    func testPublishKeyPackage() async throws {
        let did = TestData.generateDID(0)
        let keyPackage = TestData.generateKeyPackage(for: did)
        let cipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let expires = Date().addingTimeInterval(86400 * 30) // 30 days
        
        try await mockServer.publishKeyPackage(
            did: did,
            keyPackage: keyPackage,
            cipherSuite: cipherSuite,
            expires: expires
        )
        
        let packages = try await mockServer.getKeyPackages(for: [did])
        XCTAssertEqual(packages.count, 1)
        XCTAssertEqual(packages[0].did, did)
        XCTAssertEqual(packages[0].keyPackage, keyPackage)
    }
    
    func testPublishMultipleKeyPackages() async throws {
        let dids = TestData.generateMultipleDIDs(count: 5)
        let cipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let expires = Date().addingTimeInterval(86400 * 30)
        
        for did in dids {
            let keyPackage = TestData.generateKeyPackage(for: did)
            try await mockServer.publishKeyPackage(
                did: did,
                keyPackage: keyPackage,
                cipherSuite: cipherSuite,
                expires: expires
            )
        }
        
        let packages = try await mockServer.getKeyPackages(for: dids)
        XCTAssertEqual(packages.count, dids.count)
    }
    
    func testGetKeyPackagesExpired() async throws {
        let did = TestData.generateDID(0)
        let keyPackage = TestData.generateKeyPackage(for: did)
        let cipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let expires = Date().addingTimeInterval(-3600) // Expired 1 hour ago
        
        try await mockServer.publishKeyPackage(
            did: did,
            keyPackage: keyPackage,
            cipherSuite: cipherSuite,
            expires: expires
        )
        
        let packages = try await mockServer.getKeyPackages(for: [did])
        XCTAssertEqual(packages.count, 0)
    }
    
    func testGetKeyPackagesNotFound() async throws {
        let did = TestData.generateDID(999)
        let packages = try await mockServer.getKeyPackages(for: [did])
        XCTAssertEqual(packages.count, 0)
    }
    
    // MARK: - Epoch Management Tests
    
    func testInitialEpoch() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test",
            createdBy: members[0]
        )
        
        XCTAssertEqual(convo.epoch, 1)
    }
    
    func testEpochIncrementOnAddMember() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: [members[0]],
            title: "Test",
            createdBy: members[0]
        )
        
        let initialEpoch = convo.epoch
        try await mockServer.addMembers(to: convo.id, dids: [members[1]])
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.epoch, initialEpoch + 1)
    }
    
    func testEpochIncrementOnRemoveMember() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test",
            createdBy: members[0]
        )
        
        let initialEpoch = convo.epoch
        try await mockServer.removeMember(from: convo.id, did: members[1])
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.epoch, initialEpoch + 1)
    }
    
    func testEpochIncrementMultiple() async throws {
        let members = TestData.generateMultipleDIDs(count: 5)
        let convo = try await mockServer.createConversation(
            members: [members[0]],
            title: "Test",
            createdBy: members[0]
        )
        
        let initialEpoch = convo.epoch
        
        // Add members one by one
        for i in 1..<4 {
            try await mockServer.addMembers(to: convo.id, dids: [members[i]])
        }
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.epoch, initialEpoch + 3)
    }
    
    func testMessageRejectedWrongEpoch() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test",
            createdBy: members[0]
        )
        
        // Try to send with wrong epoch
        do {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Test"),
                epoch: convo.epoch + 5,
                senderDid: members[0]
            )
            XCTFail("Should have thrown epoch mismatch error")
        } catch MockError.epochMismatch {
            // Expected
        }
    }
    
    func testMessageAcceptedCorrectEpoch() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test",
            createdBy: members[0]
        )
        
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("Test"),
            epoch: convo.epoch,
            senderDid: members[0]
        )
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 1)
    }
    
    // MARK: - Key Rotation Scenarios
    
    func testKeyRotationAfterMemberChange() async throws {
        let members = TestData.generateMultipleDIDs(count: 3)
        let convo = try await mockServer.createConversation(
            members: [members[0], members[1]],
            title: "Test",
            createdBy: members[0]
        )
        
        let epoch1 = convo.epoch
        
        // Send message in epoch 1
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("Epoch 1"),
            epoch: epoch1,
            senderDid: members[0]
        )
        
        // Add new member (triggers key rotation)
        try await mockServer.addMembers(to: convo.id, dids: [members[2]])
        let updated = try await mockServer.getConversation(convo.id)
        let epoch2 = updated.epoch
        
        XCTAssertEqual(epoch2, epoch1 + 1)
        
        // Send message in new epoch
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("Epoch 2"),
            epoch: epoch2,
            senderDid: members[0]
        )
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 2)
        XCTAssertEqual(messages[0].epoch, epoch1)
        XCTAssertEqual(messages[1].epoch, epoch2)
    }
    
    func testMultipleKeyRotations() async throws {
        let members = TestData.generateMultipleDIDs(count: 6)
        let convo = try await mockServer.createConversation(
            members: [members[0]],
            title: "Test",
            createdBy: members[0]
        )
        
        var currentEpoch = convo.epoch
        
        // Perform multiple rotations
        for i in 1..<5 {
            try await mockServer.addMembers(to: convo.id, dids: [members[i]])
            let updated = try await mockServer.getConversation(convo.id)
            currentEpoch += 1
            XCTAssertEqual(updated.epoch, currentEpoch)
        }
        
        XCTAssertEqual(currentEpoch, 5)
    }
    
    func testKeyPackageRotation() async throws {
        let did = TestData.generateDID(0)
        let cipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let expires = Date().addingTimeInterval(86400 * 30)
        
        // Publish first key package
        let pkg1 = TestData.generateKeyPackage(for: did)
        try await mockServer.publishKeyPackage(
            did: did,
            keyPackage: pkg1,
            cipherSuite: cipherSuite,
            expires: expires
        )
        
        // Publish second key package (rotation)
        let pkg2 = TestData.generateKeyPackage(for: did)
        try await mockServer.publishKeyPackage(
            did: did,
            keyPackage: pkg2,
            cipherSuite: cipherSuite,
            expires: expires
        )
        
        // Should have multiple packages available
        let packages = try await mockServer.getKeyPackages(for: [did])
        XCTAssertGreaterThan(packages.count, 0)
    }
}
