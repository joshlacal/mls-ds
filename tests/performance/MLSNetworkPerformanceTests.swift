//
//  MLSNetworkPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Network efficiency and bandwidth tests
//

import XCTest
@testable import CatbirdChat

class MLSNetworkPerformanceTests: XCTestCase {
    
    var mlsManager: MLSManager!
    var networkMonitor: NetworkMonitor!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        mlsManager = MLSManager.shared
        networkMonitor = NetworkMonitor.shared
    }
    
    override func tearDownWithError() throws {
        mlsManager = nil
        networkMonitor = nil
        try super.tearDownWithError()
    }
    
    // MARK: - Message Payload Size Tests
    
    func testEncryptedMessageOverhead() throws {
        let groupId = "overhead_test_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let messages = [
            ("Small", String(repeating: "A", count: 100)),
            ("Medium", String(repeating: "A", count: 1000)),
            ("Large", String(repeating: "A", count: 10000))
        ]
        
        for (label, message) in messages {
            let originalSize = message.data(using: .utf8)?.count ?? 0
            
            if let encrypted = try? mlsManager.encryptMessage(message, groupId: groupId) {
                let encryptedSize = encrypted.data(using: .utf8)?.count ?? 0
                let overhead = Double(encryptedSize - originalSize) / Double(originalSize) * 100
                
                print("\(label) message overhead: \(String(format: "%.2f", overhead))%")
                XCTAssertLessThan(overhead, 50.0, "\(label) message overhead too high")
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testWelcomeMessageSize() throws {
        let groupId = "welcome_size_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTStorageMetric()]) {
            for i in 0..<10 {
                let memberId = "member_\(i)"
                if let welcomeMessage = try? mlsManager.addMember(memberId, to: groupId) {
                    let size = welcomeMessage.data(using: .utf8)?.count ?? 0
                    print("Welcome message size: \(size) bytes")
                }
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testCommitMessageSize() throws {
        let groupId = "commit_size_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Add members
        for i in 0..<10 {
            try mlsManager.addMember("member_\(i)", to: groupId)
        }
        
        measure(metrics: [XCTStorageMetric()]) {
            for i in 10..<20 {
                if let commit = try? mlsManager.createAddCommit("member_\(i)", groupId: groupId) {
                    let size = commit.data(using: .utf8)?.count ?? 0
                    print("Commit message size: \(size) bytes")
                }
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Bandwidth Usage Tests
    
    func testBandwidthForMessageBurst() throws {
        let groupId = "bandwidth_test_group"
        try mlsManager.createGroup(groupId: groupId)
        
        networkMonitor.startMonitoring()
        let startBytes = networkMonitor.totalBytesSent
        
        measure(metrics: [XCTStorageMetric()]) {
            for i in 0..<50 {
                let message = "Test message \(i)"
                _ = try? mlsManager.encryptMessage(message, groupId: groupId)
            }
        }
        
        let endBytes = networkMonitor.totalBytesSent
        let bandwidthUsed = endBytes - startBytes
        print("Bandwidth used for 50 messages: \(bandwidthUsed) bytes")
        
        networkMonitor.stopMonitoring()
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testBandwidthForGroupUpdate() throws {
        let groupId = "bandwidth_update_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Add initial members
        for i in 0..<20 {
            try mlsManager.addMember("member_\(i)", to: groupId)
        }
        
        networkMonitor.startMonitoring()
        let startBytes = networkMonitor.totalBytesSent
        
        measure(metrics: [XCTStorageMetric()]) {
            for i in 20..<30 {
                _ = try? mlsManager.addMember("member_\(i)", to: groupId)
            }
        }
        
        let endBytes = networkMonitor.totalBytesSent
        let bandwidthUsed = endBytes - startBytes
        print("Bandwidth used for 10 member additions: \(bandwidthUsed) bytes")
        
        networkMonitor.stopMonitoring()
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Network Latency Tests
    
    func testMessageRoundTripTime() throws {
        let groupId = "latency_test_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTClockMetric()]) {
            let message = "Latency test message"
            
            let startTime = Date()
            if let encrypted = try? mlsManager.encryptMessage(message, groupId: groupId) {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
            let endTime = Date()
            
            let latency = endTime.timeIntervalSince(startTime) * 1000
            print("Message round-trip time: \(String(format: "%.2f", latency))ms")
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testKeyPackageUploadLatency() throws {
        measure(metrics: [XCTClockMetric()]) {
            let startTime = Date()
            
            if let keyPackage = try? mlsManager.createKeyPackage() {
                _ = try? mlsManager.uploadKeyPackage(keyPackage)
            }
            
            let endTime = Date()
            let latency = endTime.timeIntervalSince(startTime) * 1000
            print("Key package upload latency: \(String(format: "%.2f", latency))ms")
        }
    }
    
    // MARK: - Network Efficiency Tests
    
    func testBatchMessageEfficiency() throws {
        let groupId = "batch_efficiency_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let messages = (0..<10).map { "Batch message \($0)" }
        
        // Test individual sends
        networkMonitor.startMonitoring()
        let individualStart = networkMonitor.totalBytesSent
        
        for message in messages {
            _ = try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        
        let individualEnd = networkMonitor.totalBytesSent
        let individualBytes = individualEnd - individualStart
        
        // Test batch send
        let batchStart = networkMonitor.totalBytesSent
        _ = try? mlsManager.encryptMessageBatch(messages, groupId: groupId)
        let batchEnd = networkMonitor.totalBytesSent
        let batchBytes = batchEnd - batchStart
        
        let efficiency = Double(batchBytes) / Double(individualBytes) * 100
        print("Batch efficiency: \(String(format: "%.2f", efficiency))% of individual sends")
        XCTAssertLessThan(batchBytes, individualBytes, "Batch should be more efficient")
        
        networkMonitor.stopMonitoring()
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testKeyPackageBundlingEfficiency() throws {
        measure(metrics: [XCTStorageMetric()]) {
            let keyPackages = try? (0..<10).compactMap { _ in
                try? mlsManager.createKeyPackage()
            }
            
            if let packages = keyPackages {
                _ = try? mlsManager.uploadKeyPackageBatch(packages)
            }
        }
    }
    
    // MARK: - Compression Tests
    
    func testMessageCompressionRatio() throws {
        let groupId = "compression_test_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let repeatableMessage = String(repeating: "This is a test message that should compress well. ", count: 20)
        
        guard let encrypted = try? mlsManager.encryptMessage(repeatableMessage, groupId: groupId) else {
            XCTFail("Failed to encrypt message")
            return
        }
        
        let originalSize = repeatableMessage.data(using: .utf8)?.count ?? 0
        let encryptedSize = encrypted.data(using: .utf8)?.count ?? 0
        
        if let compressed = encrypted.data(using: .utf8)?.compressed() {
            let compressedSize = compressed.count
            let ratio = Double(compressedSize) / Double(encryptedSize) * 100
            print("Compression ratio: \(String(format: "%.2f", ratio))%")
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Connection Pool Tests
    
    func testConnectionPoolEfficiency() throws {
        measure(metrics: [XCTClockMetric()]) {
            let expectation = self.expectation(description: "Concurrent requests")
            expectation.expectedFulfillmentCount = 10
            
            DispatchQueue.concurrentPerform(iterations: 10) { i in
                let groupId = "pool_test_\(i)"
                _ = try? mlsManager.createGroup(groupId: groupId)
                _ = try? mlsManager.deleteGroup(groupId)
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    // MARK: - Network Retry Tests
    
    func testRetryPerformance() throws {
        measure(metrics: [XCTClockMetric()]) {
            let groupId = "retry_test_group"
            
            // Simulate network conditions
            networkMonitor.simulateUnstableNetwork()
            
            _ = try? mlsManager.createGroup(groupId: groupId, withRetry: true)
            
            networkMonitor.restoreNormalNetwork()
            try? mlsManager.deleteGroup(groupId)
        }
    }
}
