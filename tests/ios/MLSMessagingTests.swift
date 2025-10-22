import XCTest
@testable import CatbirdChat

/// End-to-end tests for MLS messaging operations
final class MLSMessagingTests: XCTestCase {
    
    var mockServer: MockMLSServer!
    var client: CatbirdClient!
    var testConvo: MockConversation!
    var testMembers: [String]!
    
    override func setUp() async throws {
        try await super.setUp()
        mockServer = MockMLSServer.shared
        mockServer.reset()
        client = CatbirdClient(baseURL: "http://localhost:8080")
        client.setAuthToken(mockServer.authToken ?? "")
        
        // Create test conversation
        testMembers = TestData.generateMultipleDIDs(count: 3)
        testConvo = try await mockServer.createConversation(
            members: testMembers,
            title: "Test Convo",
            createdBy: testMembers[0]
        )
    }
    
    override func tearDown() {
        mockServer.reset()
        super.tearDown()
    }
    
    // MARK: - Send Message Tests
    
    func testSendSingleMessage() async throws {
        let sender = testMembers[0]
        let ciphertext = TestData.generateCiphertext("Hello, World!")
        
        try await mockServer.sendMessage(
            to: testConvo.id,
            ciphertext: ciphertext,
            epoch: testConvo.epoch,
            senderDid: sender
        )
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, 1)
        XCTAssertEqual(messages[0].ciphertext, ciphertext)
        XCTAssertEqual(messages[0].senderDid, sender)
    }
    
    func testSendMultipleMessages() async throws {
        let sender = testMembers[0]
        let messageCount = 10
        
        for i in 0..<messageCount {
            let ciphertext = TestData.generateCiphertext("Message \(i)")
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: ciphertext,
                epoch: testConvo.epoch,
                senderDid: sender
            )
        }
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, messageCount)
    }
    
    func testSendMessageFromMultipleSenders() async throws {
        for sender in testMembers {
            let ciphertext = TestData.generateCiphertext("From \(sender)")
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: ciphertext,
                epoch: testConvo.epoch,
                senderDid: sender
            )
        }
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, testMembers.count)
        
        let senders = Set(messages.map { $0.senderDid })
        XCTAssertEqual(senders, Set(testMembers))
    }
    
    func testSendMessageUnauthorized() async throws {
        let nonMember = TestData.generateDID(999)
        let ciphertext = TestData.generateCiphertext("Unauthorized")
        
        do {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: ciphertext,
                epoch: testConvo.epoch,
                senderDid: nonMember
            )
            XCTFail("Should have thrown unauthorized error")
        } catch MockError.unauthorized {
            // Expected
        }
    }
    
    func testSendMessageWrongEpoch() async throws {
        let sender = testMembers[0]
        let ciphertext = TestData.generateCiphertext("Wrong epoch")
        
        do {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: ciphertext,
                epoch: testConvo.epoch + 1,
                senderDid: sender
            )
            XCTFail("Should have thrown epoch mismatch error")
        } catch MockError.epochMismatch {
            // Expected
        }
    }
    
    func testSendMessageToNonexistentConvo() async throws {
        let sender = testMembers[0]
        let ciphertext = TestData.generateCiphertext("Test")
        
        do {
            try await mockServer.sendMessage(
                to: "nonexistent",
                ciphertext: ciphertext,
                epoch: 1,
                senderDid: sender
            )
            XCTFail("Should have thrown not found error")
        } catch MockError.notFound {
            // Expected
        }
    }
    
    // MARK: - Receive Message Tests
    
    func testGetMessagesEmpty() async throws {
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, 0)
    }
    
    func testGetAllMessages() async throws {
        let sender = testMembers[0]
        let messageCount = 5
        
        for i in 0..<messageCount {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: testConvo.epoch,
                senderDid: sender
            )
        }
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, messageCount)
    }
    
    func testGetMessagesSince() async throws {
        let sender = testMembers[0]
        var messageIds: [String] = []
        
        for i in 0..<5 {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: testConvo.epoch,
                senderDid: sender
            )
            
            let messages = try await mockServer.getMessages(for: testConvo.id)
            messageIds.append(messages.last!.id)
        }
        
        let recentMessages = try await mockServer.getMessages(
            for: testConvo.id,
            since: messageIds[2]
        )
        
        XCTAssertEqual(recentMessages.count, 2)
    }
    
    func testGetMessagesOrdering() async throws {
        let sender = testMembers[0]
        var sentTimes: [Date] = []
        
        for i in 0..<5 {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: testConvo.epoch,
                senderDid: sender
            )
            sentTimes.append(Date())
            try await Task.sleep(nanoseconds: 100_000_000) // 0.1s
        }
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        
        for i in 0..<messages.count - 1 {
            XCTAssertLessThanOrEqual(messages[i].sentAt, messages[i + 1].sentAt)
        }
    }
    
    // MARK: - Message History Tests
    
    func testMessageHistory() async throws {
        let sender = testMembers[0]
        
        // Send initial batch
        for i in 0..<10 {
            try await mockServer.sendMessage(
                to: testConvo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: testConvo.epoch,
                senderDid: sender
            )
        }
        
        let allMessages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(allMessages.count, 10)
        
        // Verify we can retrieve all messages
        let history = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(history.count, allMessages.count)
    }
    
    // MARK: - Concurrent Messaging Tests
    
    func testConcurrentMessageSending() async throws {
        let sender = testMembers[0]
        let messageCount = 20
        
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<messageCount {
                group.addTask {
                    do {
                        try await self.mockServer.sendMessage(
                            to: self.testConvo.id,
                            ciphertext: TestData.generateCiphertext("Concurrent \(i)"),
                            epoch: self.testConvo.epoch,
                            senderDid: sender
                        )
                    } catch {
                        XCTFail("Failed to send message: \(error)")
                    }
                }
            }
        }
        
        let messages = try await mockServer.getMessages(for: testConvo.id)
        XCTAssertEqual(messages.count, messageCount)
    }
}
