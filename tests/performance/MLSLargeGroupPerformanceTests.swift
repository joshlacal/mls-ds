//
//  MLSLargeGroupPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Performance tests for large group operations (100+ members)
//

import XCTest
@testable import CatbirdChat

class MLSLargeGroupPerformanceTests: XCTestCase {
    
    var mlsManager: MLSManager!
    var largeGroupId: String!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        mlsManager = MLSManager.shared
        largeGroupId = "large_group_\(UUID().uuidString)"
    }
    
    override func tearDownWithError() throws {
        // Clean up large group
        try? mlsManager.deleteGroup(largeGroupId)
        mlsManager = nil
        largeGroupId = nil
        try super.tearDownWithError()
    }
    
    // MARK: - 100 Member Group Tests
    
    func testCreate100MemberGroup() throws {
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric(),
            XCTStorageMetric()
        ]) {
            let groupId = "group_100_\(UUID().uuidString)"
            try? mlsManager.createGroup(groupId: groupId)
            
            for i in 0..<100 {
                let memberId = "member_\(i)"
                _ = try? mlsManager.addMember(memberId, to: groupId)
            }
            
            try? mlsManager.deleteGroup(groupId)
        }
    }
    
    func testMessageEncryptionIn100MemberGroup() throws {
        // Setup: Create group with 100 members
        try mlsManager.createGroup(groupId: largeGroupId)
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        let testMessage = "Test message in large group"
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric(), XCTCPUMetric()]) {
            for _ in 0..<20 {
                _ = try? mlsManager.encryptMessage(testMessage, groupId: largeGroupId)
            }
        }
    }
    
    func testMessageDecryptionIn100MemberGroup() throws {
        // Setup: Create group with 100 members
        try mlsManager.createGroup(groupId: largeGroupId)
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        let testMessage = "Test message in large group"
        guard let encrypted = try? mlsManager.encryptMessage(testMessage, groupId: largeGroupId) else {
            XCTFail("Failed to encrypt message")
            return
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            for _ in 0..<20 {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: largeGroupId)
            }
        }
    }
    
    func testAddMemberTo100MemberGroup() throws {
        // Setup: Create group with 100 members
        try mlsManager.createGroup(groupId: largeGroupId)
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric(), XCTCPUMetric()]) {
            for i in 100..<110 {
                let memberId = "new_member_\(i)"
                _ = try? mlsManager.addMember(memberId, to: largeGroupId)
            }
        }
    }
    
    func testRemoveMemberFrom100MemberGroup() throws {
        // Setup: Create group with 110 members
        try mlsManager.createGroup(groupId: largeGroupId)
        for i in 0..<110 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric(), XCTCPUMetric()]) {
            for i in 100..<110 {
                let memberId = "member_\(i)"
                _ = try? mlsManager.removeMember(memberId, from: largeGroupId)
            }
        }
    }
    
    // MARK: - 250 Member Group Tests
    
    func testCreate250MemberGroup() throws {
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric(),
            XCTStorageMetric()
        ]) {
            let groupId = "group_250_\(UUID().uuidString)"
            try? mlsManager.createGroup(groupId: groupId)
            
            for i in 0..<250 {
                let memberId = "member_\(i)"
                _ = try? mlsManager.addMember(memberId, to: groupId)
            }
            
            try? mlsManager.deleteGroup(groupId)
        }
    }
    
    func testMessageProcessingIn250MemberGroup() throws {
        let groupId = "group_250_test_\(UUID().uuidString)"
        try mlsManager.createGroup(groupId: groupId)
        
        // Add 250 members
        for i in 0..<250 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: groupId)
        }
        
        let testMessage = "Test message in very large group"
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric(), XCTCPUMetric()]) {
            if let encrypted = try? mlsManager.encryptMessage(testMessage, groupId: groupId) {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Group State Management
    
    func testGroupStateSize() throws {
        try mlsManager.createGroup(groupId: largeGroupId)
        
        // Add 100 members
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        measure(metrics: [XCTStorageMetric(), XCTMemoryMetric()]) {
            _ = try? mlsManager.exportGroupState(largeGroupId)
        }
    }
    
    func testGroupStateImport() throws {
        try mlsManager.createGroup(groupId: largeGroupId)
        
        // Add 100 members
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        guard let exportedState = try? mlsManager.exportGroupState(largeGroupId) else {
            XCTFail("Failed to export group state")
            return
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            let newGroupId = "imported_group_\(UUID().uuidString)"
            _ = try? mlsManager.importGroupState(exportedState, groupId: newGroupId)
            try? mlsManager.deleteGroup(newGroupId)
        }
    }
    
    // MARK: - Scalability Tests
    
    func testMessageThroughputInLargeGroup() throws {
        try mlsManager.createGroup(groupId: largeGroupId)
        
        // Add 100 members
        for i in 0..<100 {
            let memberId = "member_\(i)"
            try mlsManager.addMember(memberId, to: largeGroupId)
        }
        
        let messages = (0..<100).map { "Message \($0)" }
        
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric()
        ]) {
            for message in messages {
                if let encrypted = try? mlsManager.encryptMessage(message, groupId: largeGroupId) {
                    _ = try? mlsManager.decryptMessage(encrypted, groupId: largeGroupId)
                }
            }
        }
    }
}
