//
//  MLSPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Performance tests for MLS encryption/decryption operations
//

import XCTest
@testable import CatbirdChat

class MLSPerformanceTests: XCTestCase {
    
    var mlsManager: MLSManager!
    var testGroupId: String!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        mlsManager = MLSManager.shared
        testGroupId = "test_group_\(UUID().uuidString)"
    }
    
    override func tearDownWithError() throws {
        mlsManager = nil
        testGroupId = nil
        try super.tearDownWithError()
    }
    
    // MARK: - Encryption/Decryption Performance
    
    func testEncryptionSpeed() throws {
        let testMessage = "Test message for encryption performance benchmarking"
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for _ in 0..<100 {
                _ = try? mlsManager.encryptMessage(testMessage, groupId: testGroupId)
            }
        }
    }
    
    func testDecryptionSpeed() throws {
        let testMessage = "Test message for decryption performance benchmarking"
        guard let encryptedMessage = try? mlsManager.encryptMessage(testMessage, groupId: testGroupId) else {
            XCTFail("Failed to encrypt test message")
            return
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for _ in 0..<100 {
                _ = try? mlsManager.decryptMessage(encryptedMessage, groupId: testGroupId)
            }
        }
    }
    
    func testLargeMessageEncryption() throws {
        // Test with 10KB message
        let largeMessage = String(repeating: "A", count: 10_240)
        
        measure(metrics: [XCTClockMetric(), XCTCPUMetric(), XCTMemoryMetric()]) {
            _ = try? mlsManager.encryptMessage(largeMessage, groupId: testGroupId)
        }
    }
    
    func testLargeMessageDecryption() throws {
        let largeMessage = String(repeating: "A", count: 10_240)
        guard let encryptedMessage = try? mlsManager.encryptMessage(largeMessage, groupId: testGroupId) else {
            XCTFail("Failed to encrypt large message")
            return
        }
        
        measure(metrics: [XCTClockMetric(), XCTCPUMetric(), XCTMemoryMetric()]) {
            _ = try? mlsManager.decryptMessage(encryptedMessage, groupId: testGroupId)
        }
    }
    
    func testBulkMessageProcessing() throws {
        let messages = (0..<50).map { "Message \($0)" }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for message in messages {
                if let encrypted = try? mlsManager.encryptMessage(message, groupId: testGroupId) {
                    _ = try? mlsManager.decryptMessage(encrypted, groupId: testGroupId)
                }
            }
        }
    }
    
    // MARK: - Key Generation Performance
    
    func testKeyPairGeneration() throws {
        measure(metrics: [XCTClockMetric(), XCTCPUMetric()]) {
            for _ in 0..<10 {
                _ = try? mlsManager.generateKeyPair()
            }
        }
    }
    
    func testKeyPackageCreation() throws {
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for _ in 0..<20 {
                _ = try? mlsManager.createKeyPackage()
            }
        }
    }
    
    // MARK: - Group Operations Performance
    
    func testGroupCreationSpeed() throws {
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for i in 0..<10 {
                let groupId = "test_group_\(i)"
                _ = try? mlsManager.createGroup(groupId: groupId)
            }
        }
    }
    
    func testAddMemberPerformance() throws {
        let groupId = "test_add_member_\(UUID().uuidString)"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for i in 0..<20 {
                let memberId = "member_\(i)"
                _ = try? mlsManager.addMember(memberId, to: groupId)
            }
        }
    }
    
    func testRemoveMemberPerformance() throws {
        let groupId = "test_remove_member_\(UUID().uuidString)"
        try mlsManager.createGroup(groupId: groupId)
        
        // Add members first
        let memberIds = (0..<20).map { "member_\($0)" }
        for memberId in memberIds {
            try? mlsManager.addMember(memberId, to: groupId)
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for memberId in memberIds.prefix(10) {
                _ = try? mlsManager.removeMember(memberId, from: groupId)
            }
        }
    }
    
    // MARK: - Concurrent Operations
    
    func testConcurrentEncryption() throws {
        let expectation = self.expectation(description: "Concurrent encryption")
        expectation.expectedFulfillmentCount = 10
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            DispatchQueue.concurrentPerform(iterations: 10) { i in
                let message = "Concurrent message \(i)"
                _ = try? mlsManager.encryptMessage(message, groupId: testGroupId)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testConcurrentGroupOperations() throws {
        let expectation = self.expectation(description: "Concurrent group operations")
        expectation.expectedFulfillmentCount = 5
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            DispatchQueue.concurrentPerform(iterations: 5) { i in
                let groupId = "concurrent_group_\(i)"
                _ = try? mlsManager.createGroup(groupId: groupId)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
}
