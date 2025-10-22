//
//  MLSMemoryPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Memory usage and leak detection tests
//

import XCTest
@testable import CatbirdChat

class MLSMemoryPerformanceTests: XCTestCase {
    
    var mlsManager: MLSManager!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        mlsManager = MLSManager.shared
    }
    
    override func tearDownWithError() throws {
        mlsManager = nil
        try super.tearDownWithError()
    }
    
    // MARK: - Memory Footprint Tests
    
    func testBaselineMemoryUsage() throws {
        measure(metrics: [XCTMemoryMetric()]) {
            let manager = MLSManager()
            _ = manager.initialize()
        }
    }
    
    func testMemoryUsageWith10Groups() throws {
        measure(metrics: [XCTMemoryMetric(), XCTStorageMetric()]) {
            for i in 0..<10 {
                let groupId = "mem_group_\(i)"
                try? mlsManager.createGroup(groupId: groupId)
            }
            
            // Cleanup
            for i in 0..<10 {
                let groupId = "mem_group_\(i)"
                try? mlsManager.deleteGroup(groupId)
            }
        }
    }
    
    func testMemoryUsageWith100Groups() throws {
        measure(metrics: [XCTMemoryMetric(), XCTStorageMetric()]) {
            for i in 0..<100 {
                let groupId = "mem_group_100_\(i)"
                try? mlsManager.createGroup(groupId: groupId)
            }
            
            // Cleanup
            for i in 0..<100 {
                let groupId = "mem_group_100_\(i)"
                try? mlsManager.deleteGroup(groupId)
            }
        }
    }
    
    func testMemoryUsagePerMember() throws {
        let groupId = "mem_per_member_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTMemoryMetric()]) {
            for i in 0..<100 {
                let memberId = "member_\(i)"
                _ = try? mlsManager.addMember(memberId, to: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Memory Leak Detection
    
    func testNoMemoryLeakInEncryption() throws {
        let groupId = "leak_test_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTMemoryMetric()]) {
            for i in 0..<1000 {
                let message = "Test message \(i)"
                _ = try? mlsManager.encryptMessage(message, groupId: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testNoMemoryLeakInDecryption() throws {
        let groupId = "leak_decrypt_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let testMessage = "Test message for leak detection"
        guard let encrypted = try? mlsManager.encryptMessage(testMessage, groupId: groupId) else {
            XCTFail("Failed to encrypt message")
            return
        }
        
        measure(metrics: [XCTMemoryMetric()]) {
            for _ in 0..<1000 {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testNoMemoryLeakInGroupOperations() throws {
        measure(metrics: [XCTMemoryMetric()]) {
            for i in 0..<100 {
                let groupId = "leak_group_\(i)"
                try? mlsManager.createGroup(groupId: groupId)
                
                for j in 0..<10 {
                    let memberId = "member_\(j)"
                    _ = try? mlsManager.addMember(memberId, to: groupId)
                }
                
                try? mlsManager.deleteGroup(groupId)
            }
        }
    }
    
    // MARK: - Cache Memory Usage
    
    func testMessageCacheMemoryUsage() throws {
        let groupId = "cache_mem_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTMemoryMetric()]) {
            for i in 0..<500 {
                let message = "Cached message \(i)"
                if let encrypted = try? mlsManager.encryptMessage(message, groupId: groupId) {
                    _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
                }
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testKeyPackageCacheMemoryUsage() throws {
        measure(metrics: [XCTMemoryMetric()]) {
            for _ in 0..<100 {
                _ = try? mlsManager.createKeyPackage()
            }
            
            _ = mlsManager.loadAllKeyPackages()
        }
    }
    
    // MARK: - Peak Memory Usage
    
    func testPeakMemoryDuringBulkEncryption() throws {
        let groupId = "peak_mem_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let largeMessage = String(repeating: "A", count: 50_000)
        
        measure(metrics: [XCTMemoryMetric(), XCTCPUMetric()]) {
            for _ in 0..<20 {
                _ = try? mlsManager.encryptMessage(largeMessage, groupId: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testPeakMemoryDuringGroupUpdate() throws {
        let groupId = "peak_update_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Add 50 members
        for i in 0..<50 {
            try mlsManager.addMember("member_\(i)", to: groupId)
        }
        
        measure(metrics: [XCTMemoryMetric(), XCTCPUMetric()]) {
            // Add 50 more members
            for i in 50..<100 {
                _ = try? mlsManager.addMember("member_\(i)", to: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Memory Recovery
    
    func testMemoryRecoveryAfterGroupDeletion() throws {
        let groupIds = (0..<20).map { "recovery_group_\($0)" }
        
        // Create groups
        for groupId in groupIds {
            try mlsManager.createGroup(groupId: groupId)
            for i in 0..<10 {
                try mlsManager.addMember("member_\(i)", to: groupId)
            }
        }
        
        measure(metrics: [XCTMemoryMetric()]) {
            // Delete all groups
            for groupId in groupIds {
                try? mlsManager.deleteGroup(groupId)
            }
            
            // Force memory cleanup
            autoreleasepool {
                _ = mlsManager.cleanupMemory()
            }
        }
    }
    
    func testMemoryRecoveryAfterCacheClear() throws {
        let groupId = "cache_clear_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Populate caches
        for i in 0..<100 {
            let message = "Message \(i)"
            _ = try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        
        measure(metrics: [XCTMemoryMetric()]) {
            mlsManager.clearCaches()
            
            autoreleasepool {
                _ = mlsManager.cleanupMemory()
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
}
