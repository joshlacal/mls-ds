import XCTest
@testable import CatbirdChat

/// End-to-end tests for multi-device sync scenarios
final class MLSMultiDeviceTests: XCTestCase {
    
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
    
    // MARK: - Multi-Device Setup Tests
    
    func testSingleUserMultipleDevices() async throws {
        let scenario = TestData.multiDeviceScenario()
        let cipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
        let expires = Date().addingTimeInterval(86400 * 30)
        
        // Register key packages for each device
        for device in scenario.devices {
            try await mockServer.publishKeyPackage(
                did: "\(scenario.userDID)_\(device.id)",
                keyPackage: device.keyPackage,
                cipherSuite: cipherSuite,
                expires: expires
            )
        }
        
        // Verify all devices registered
        let deviceDIDs = scenario.devices.map { "\(scenario.userDID)_\($0.id)" }
        let packages = try await mockServer.getKeyPackages(for: deviceDIDs)
        XCTAssertEqual(packages.count, scenario.devices.count)
    }
    
    func testDeviceAddedToExistingConversation() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        // Create conversation with device1
        let convo = try await mockServer.createConversation(
            members: [device1],
            title: "Multi-Device",
            createdBy: device1
        )
        
        // Add device2
        try await mockServer.addMembers(to: convo.id, dids: [device2])
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertTrue(mockServer.isMember(convoId: convo.id, did: device2))
        XCTAssertEqual(updated.members.count, 2)
    }
    
    // MARK: - Message Sync Tests
    
    func testMessageSyncBetweenDevices() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "Sync Test",
            createdBy: device1
        )
        
        // Send from device1
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("From device 1"),
            epoch: convo.epoch,
            senderDid: device1
        )
        
        // Receive on device2
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].senderDid, device1)
    }
    
    func testBidirectionalSync() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "Bidirectional",
            createdBy: device1
        )
        
        // Send from device1
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("From device 1"),
            epoch: convo.epoch,
            senderDid: device1
        )
        
        // Send from device2
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("From device 2"),
            epoch: convo.epoch,
            senderDid: device2
        )
        
        // Both devices see all messages
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 2)
        
        let senders = Set(messages.map { $0.senderDid })
        XCTAssertEqual(senders, Set([device1, device2]))
    }
    
    func testMessageOrderingAcrossDevices() async throws {
        let user = TestData.generateDID(0)
        let devices = (1...3).map { "\(user)_device\($0)" }
        
        let convo = try await mockServer.createConversation(
            members: devices,
            title: "Ordering Test",
            createdBy: devices[0]
        )
        
        // Send messages from different devices
        for (index, device) in devices.enumerated() {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Message \(index)"),
                epoch: convo.epoch,
                senderDid: device
            )
            try await Task.sleep(nanoseconds: 100_000_000) // 0.1s
        }
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 3)
        
        // Verify chronological ordering
        for i in 0..<messages.count - 1 {
            XCTAssertLessThanOrEqual(messages[i].sentAt, messages[i + 1].sentAt)
        }
    }
    
    // MARK: - Device Removal Tests
    
    func testRemoveDevice() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "Device Removal",
            createdBy: device1
        )
        
        // Remove device2
        try await mockServer.removeMember(from: convo.id, did: device2)
        
        // Verify device2 can't send messages
        do {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Should fail"),
                epoch: convo.epoch + 1,
                senderDid: device2
            )
            XCTFail("Should have thrown unauthorized error")
        } catch MockError.unauthorized {
            // Expected
        }
    }
    
    func testDeviceRejoinAfterRemoval() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "Rejoin Test",
            createdBy: device1
        )
        
        // Remove device2
        try await mockServer.removeMember(from: convo.id, did: device2)
        let epochAfterRemoval = try await mockServer.getConversation(convo.id).epoch
        
        // Re-add device2
        try await mockServer.addMembers(to: convo.id, dids: [device2])
        let epochAfterReAdd = try await mockServer.getConversation(convo.id).epoch
        
        // Epoch should have incremented twice
        XCTAssertEqual(epochAfterReAdd, epochAfterRemoval + 1)
        
        // Device2 should be able to send messages
        try await mockServer.sendMessage(
            to: convo.id,
            ciphertext: TestData.generateCiphertext("Rejoined"),
            epoch: epochAfterReAdd,
            senderDid: device2
        )
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.last?.senderDid, device2)
    }
    
    // MARK: - Concurrent Device Operations
    
    func testConcurrentDeviceMessages() async throws {
        let user = TestData.generateDID(0)
        let devices = (1...5).map { "\(user)_device\($0)" }
        
        let convo = try await mockServer.createConversation(
            members: devices,
            title: "Concurrent Test",
            createdBy: devices[0]
        )
        
        // Send messages concurrently from all devices
        await withTaskGroup(of: Void.self) { group in
            for device in devices {
                group.addTask {
                    do {
                        try await self.mockServer.sendMessage(
                            to: convo.id,
                            ciphertext: TestData.generateCiphertext("From \(device)"),
                            epoch: convo.epoch,
                            senderDid: device
                        )
                    } catch {
                        XCTFail("Failed to send: \(error)")
                    }
                }
            }
        }
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, devices.count)
    }
    
    // MARK: - State Synchronization Tests
    
    func testConversationStateSyncAcrossDevices() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        
        // Create conversation on device1
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "State Sync",
            createdBy: device1
        )
        
        // List conversations from both devices
        let device1Convos = try await mockServer.listConversations(for: device1)
        let device2Convos = try await mockServer.listConversations(for: device2)
        
        XCTAssertEqual(device1Convos.count, 1)
        XCTAssertEqual(device2Convos.count, 1)
        XCTAssertEqual(device1Convos[0].id, device2Convos[0].id)
    }
    
    func testMemberListSyncAcrossDevices() async throws {
        let user1 = TestData.generateDID(0)
        let user2 = TestData.generateDID(1)
        let user1device1 = "\(user1)_device1"
        let user1device2 = "\(user1)_device2"
        
        let convo = try await mockServer.createConversation(
            members: [user1device1, user1device2],
            title: "Member Sync",
            createdBy: user1device1
        )
        
        // Add new member from device1
        try await mockServer.addMembers(to: convo.id, dids: [user2])
        
        // Verify device2 sees the new member
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertTrue(mockServer.isMember(convoId: convo.id, did: user2))
        XCTAssertEqual(updated.members.count, 3)
    }
    
    func testEpochSyncAcrossDevices() async throws {
        let user = TestData.generateDID(0)
        let device1 = "\(user)_device1"
        let device2 = "\(user)_device2"
        let newMember = TestData.generateDID(1)
        
        let convo = try await mockServer.createConversation(
            members: [device1, device2],
            title: "Epoch Sync",
            createdBy: device1
        )
        
        let initialEpoch = convo.epoch
        
        // Add member from device1
        try await mockServer.addMembers(to: convo.id, dids: [newMember])
        
        // Both devices should see updated epoch
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.epoch, initialEpoch + 1)
    }
}
