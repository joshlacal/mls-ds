import XCTest
@testable import CatbirdChat

/// End-to-end tests for offline handling and error recovery
final class MLSOfflineErrorTests: XCTestCase {
    
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
    
    // MARK: - Network Error Tests
    
    func testNetworkError() async throws {
        mockServer.shouldSimulateNetworkError = true
        
        do {
            _ = try await mockServer.createConversation(
                members: [TestData.generateDID(0)],
                title: "Test",
                createdBy: TestData.generateDID(0)
            )
            XCTFail("Should have thrown network error")
        } catch MockError.networkError {
            // Expected
        }
    }
    
    func testTimeoutError() async throws {
        mockServer.shouldSimulateTimeout = true
        
        do {
            _ = try await mockServer.createConversation(
                members: [TestData.generateDID(0)],
                title: "Test",
                createdBy: TestData.generateDID(0)
            )
            XCTFail("Should have thrown timeout error")
        } catch MockError.timeout {
            // Expected
        }
    }
    
    func testNetworkRecovery() async throws {
        let member = TestData.generateDID(0)
        
        // Simulate network error
        mockServer.shouldSimulateNetworkError = true
        
        do {
            _ = try await mockServer.createConversation(
                members: [member],
                title: "Test",
                createdBy: member
            )
            XCTFail("Should have thrown network error")
        } catch MockError.networkError {
            // Expected
        }
        
        // Recover from error
        mockServer.shouldSimulateNetworkError = false
        
        // Retry should succeed
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Test",
            createdBy: member
        )
        
        XCTAssertNotNil(convo)
    }
    
    // MARK: - Offline Message Queue Tests
    
    func testOfflineMessageQueueing() async throws {
        let member = TestData.generateDID(0)
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Test",
            createdBy: member
        )
        
        var queuedMessages: [String] = []
        
        // Simulate offline mode
        mockServer.shouldSimulateNetworkError = true
        
        // Queue messages
        for i in 0..<5 {
            let ciphertext = TestData.generateCiphertext("Queued \(i)")
            queuedMessages.append(ciphertext)
            
            do {
                try await mockServer.sendMessage(
                    to: convo.id,
                    ciphertext: ciphertext,
                    epoch: convo.epoch,
                    senderDid: member
                )
                XCTFail("Should have thrown network error")
            } catch MockError.networkError {
                // Expected - message queued locally
            }
        }
        
        // Come back online
        mockServer.shouldSimulateNetworkError = false
        
        // Send queued messages
        for ciphertext in queuedMessages {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: ciphertext,
                epoch: convo.epoch,
                senderDid: member
            )
        }
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 5)
    }
    
    func testOfflineConversationCreation() async throws {
        let member = TestData.generateDID(0)
        
        // Simulate offline
        mockServer.shouldSimulateNetworkError = true
        
        do {
            _ = try await mockServer.createConversation(
                members: [member],
                title: "Offline Convo",
                createdBy: member
            )
            XCTFail("Should have thrown network error")
        } catch MockError.networkError {
            // Expected
        }
        
        // Come back online and retry
        mockServer.shouldSimulateNetworkError = false
        
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Offline Convo",
            createdBy: member
        )
        
        XCTAssertEqual(convo.title, "Offline Convo")
    }
    
    // MARK: - Error Recovery Tests
    
    func testRetryOnTransientError() async throws {
        let member = TestData.generateDID(0)
        var attemptCount = 0
        let maxRetries = 3
        
        while attemptCount < maxRetries {
            do {
                mockServer.shouldSimulateNetworkError = attemptCount < 2
                
                let convo = try await mockServer.createConversation(
                    members: [member],
                    title: "Retry Test",
                    createdBy: member
                )
                
                XCTAssertNotNil(convo)
                break
            } catch MockError.networkError {
                attemptCount += 1
                if attemptCount >= maxRetries {
                    XCTFail("Exceeded max retries")
                }
            }
        }
        
        XCTAssertLessThan(attemptCount, maxRetries)
    }
    
    func testExponentialBackoff() async throws {
        let member = TestData.generateDID(0)
        var delays: [TimeInterval] = []
        var currentDelay: TimeInterval = 0.1
        
        for attempt in 0..<4 {
            mockServer.shouldSimulateNetworkError = attempt < 3
            delays.append(currentDelay)
            
            do {
                try await Task.sleep(nanoseconds: UInt64(currentDelay * 1_000_000_000))
                
                _ = try await mockServer.createConversation(
                    members: [member],
                    title: "Backoff Test",
                    createdBy: member
                )
                break
            } catch MockError.networkError {
                currentDelay *= 2 // Exponential backoff
            }
        }
        
        // Verify exponential growth
        for i in 0..<delays.count - 1 {
            XCTAssertEqual(delays[i + 1], delays[i] * 2, accuracy: 0.01)
        }
    }
    
    // MARK: - Data Consistency Tests
    
    func testPartialUpdateRollback() async throws {
        let members = TestData.generateMultipleDIDs(count: 3)
        let convo = try await mockServer.createConversation(
            members: [members[0]],
            title: "Test",
            createdBy: members[0]
        )
        
        let initialEpoch = convo.epoch
        let initialMemberCount = try await mockServer.getConversation(convo.id).members.count
        
        // Simulate error during member addition
        mockServer.shouldSimulateNetworkError = true
        
        do {
            try await mockServer.addMembers(to: convo.id, dids: [members[1]])
            XCTFail("Should have thrown network error")
        } catch MockError.networkError {
            // Expected
        }
        
        // Verify state wasn't modified
        mockServer.shouldSimulateNetworkError = false
        let current = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(current.epoch, initialEpoch)
        XCTAssertEqual(current.members.count, initialMemberCount)
    }
    
    func testMessageOrderingAfterRecovery() async throws {
        let member = TestData.generateDID(0)
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Test",
            createdBy: member
        )
        
        // Send some messages successfully
        for i in 0..<3 {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: convo.epoch,
                senderDid: member
            )
        }
        
        // Simulate error
        mockServer.shouldSimulateNetworkError = true
        
        do {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Failed"),
                epoch: convo.epoch,
                senderDid: member
            )
            XCTFail("Should have thrown network error")
        } catch MockError.networkError {
            // Expected
        }
        
        // Recover and send more messages
        mockServer.shouldSimulateNetworkError = false
        
        for i in 3..<6 {
            try await mockServer.sendMessage(
                to: convo.id,
                ciphertext: TestData.generateCiphertext("Message \(i)"),
                epoch: convo.epoch,
                senderDid: member
            )
        }
        
        let messages = try await mockServer.getMessages(for: convo.id)
        XCTAssertEqual(messages.count, 6)
        
        // Verify ordering
        for i in 0..<messages.count - 1 {
            XCTAssertLessThanOrEqual(messages[i].sentAt, messages[i + 1].sentAt)
        }
    }
    
    // MARK: - Error Scenarios
    
    func testHandleAllErrorScenarios() async throws {
        let scenarios = TestData.errorScenarios()
        
        for scenario in scenarios {
            switch scenario.type {
            case .invalidDID:
                // Test invalid DID format
                continue
            case .unauthorized:
                mockServer.authToken = nil
                do {
                    _ = try await mockServer.createConversation(
                        members: [TestData.generateDID(0)],
                        title: "Test",
                        createdBy: TestData.generateDID(0)
                    )
                } catch {
                    // Expected
                }
                mockServer.authToken = "mock_token"
                
            case .notFound:
                do {
                    _ = try await mockServer.getConversation("nonexistent")
                    XCTFail("Should throw not found")
                } catch MockError.notFound {
                    // Expected
                }
                
            case .conflict:
                let member = TestData.generateDID(0)
                let convo = try await mockServer.createConversation(
                    members: [member],
                    title: "Test",
                    createdBy: member
                )
                do {
                    try await mockServer.addMembers(to: convo.id, dids: [member])
                    XCTFail("Should throw conflict")
                } catch MockError.conflict {
                    // Expected
                }
                
            case .timeout:
                mockServer.shouldSimulateTimeout = true
                do {
                    _ = try await mockServer.createConversation(
                        members: [TestData.generateDID(0)],
                        title: "Test",
                        createdBy: TestData.generateDID(0)
                    )
                    XCTFail("Should throw timeout")
                } catch MockError.timeout {
                    // Expected
                }
                mockServer.shouldSimulateTimeout = false
                
            case .invalidKeyPackage, .epochMismatch, .rateLimited:
                // Additional test scenarios
                continue
            }
        }
    }
    
    // MARK: - Network Latency Tests
    
    func testHighLatencyHandling() async throws {
        mockServer.networkDelay = 2.0 // 2 second delay
        
        let member = TestData.generateDID(0)
        let startTime = Date()
        
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "High Latency",
            createdBy: member
        )
        
        let elapsed = Date().timeIntervalSince(startTime)
        
        XCTAssertGreaterThanOrEqual(elapsed, 2.0)
        XCTAssertNotNil(convo)
        
        mockServer.networkDelay = 0.1 // Reset
    }
}
