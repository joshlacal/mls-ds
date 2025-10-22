//
//  MLSAppLaunchPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Performance tests for app launch time impact
//

import XCTest
@testable import CatbirdChat

class MLSAppLaunchPerformanceTests: XCTestCase {
    
    // MARK: - Cold Launch Performance
    
    func testMLSInitializationTime() throws {
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            let manager = MLSManager()
            _ = manager.initialize()
        }
    }
    
    func testColdLaunchWithNoGroups() throws {
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric()
        ]) {
            let manager = MLSManager()
            _ = manager.initialize()
            _ = manager.loadConfiguration()
        }
    }
    
    func testColdLaunchWith10Groups() throws {
        // Setup: Create 10 groups
        let manager = MLSManager.shared
        for i in 0..<10 {
            let groupId = "launch_group_\(i)"
            try? manager.createGroup(groupId: groupId)
        }
        
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric()
        ]) {
            let newManager = MLSManager()
            _ = newManager.initialize()
            _ = newManager.loadAllGroups()
        }
        
        // Cleanup
        for i in 0..<10 {
            let groupId = "launch_group_\(i)"
            try? manager.deleteGroup(groupId)
        }
    }
    
    func testColdLaunchWith50Groups() throws {
        // Setup: Create 50 groups with varying sizes
        let manager = MLSManager.shared
        for i in 0..<50 {
            let groupId = "launch_group_50_\(i)"
            try? manager.createGroup(groupId: groupId)
            
            // Add varying number of members (0-10)
            let memberCount = i % 10
            for j in 0..<memberCount {
                try? manager.addMember("member_\(j)", to: groupId)
            }
        }
        
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric(),
            XCTStorageMetric()
        ]) {
            let newManager = MLSManager()
            _ = newManager.initialize()
            _ = newManager.loadAllGroups()
        }
        
        // Cleanup
        for i in 0..<50 {
            let groupId = "launch_group_50_\(i)"
            try? manager.deleteGroup(groupId)
        }
    }
    
    // MARK: - Warm Launch Performance
    
    func testWarmLaunchPerformance() throws {
        let manager = MLSManager.shared
        _ = manager.initialize()
        _ = manager.loadAllGroups()
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            _ = manager.refreshGroupStates()
        }
    }
    
    // MARK: - Database Loading Performance
    
    func testDatabaseConnectionTime() throws {
        measure(metrics: [XCTClockMetric()]) {
            let db = MLSDatabase()
            _ = db.connect()
            db.disconnect()
        }
    }
    
    func testLoadGroupsFromDatabase() throws {
        let manager = MLSManager.shared
        
        // Setup: Create 20 groups
        for i in 0..<20 {
            let groupId = "db_group_\(i)"
            try? manager.createGroup(groupId: groupId)
        }
        
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTStorageMetric()
        ]) {
            _ = manager.loadAllGroups()
        }
        
        // Cleanup
        for i in 0..<20 {
            let groupId = "db_group_\(i)"
            try? manager.deleteGroup(groupId)
        }
    }
    
    func testLoadKeyPackagesOnLaunch() throws {
        let manager = MLSManager.shared
        
        // Setup: Create 50 key packages
        for _ in 0..<50 {
            _ = try? manager.createKeyPackage()
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            _ = manager.loadAllKeyPackages()
        }
    }
    
    // MARK: - Cache Warming
    
    func testCacheWarmingPerformance() throws {
        let manager = MLSManager.shared
        
        // Setup: Create groups with various states
        for i in 0..<10 {
            let groupId = "cache_group_\(i)"
            try? manager.createGroup(groupId: groupId)
            
            // Encrypt some messages to populate caches
            for j in 0..<5 {
                _ = try? manager.encryptMessage("Message \(j)", groupId: groupId)
            }
        }
        
        measure(metrics: [XCTClockMetric(), XCTMemoryMetric()]) {
            _ = manager.warmupCaches()
        }
        
        // Cleanup
        for i in 0..<10 {
            let groupId = "cache_group_\(i)"
            try? manager.deleteGroup(groupId)
        }
    }
    
    // MARK: - Background Initialization
    
    func testBackgroundInitialization() throws {
        measure(metrics: [XCTClockMetric()]) {
            let expectation = self.expectation(description: "Background init")
            
            DispatchQueue.global(qos: .background).async {
                let manager = MLSManager()
                _ = manager.initialize()
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 5.0)
        }
    }
    
    // MARK: - First Message Send Performance
    
    func testFirstMessageSendAfterLaunch() throws {
        let manager = MLSManager.shared
        _ = manager.initialize()
        
        let groupId = "first_message_group"
        try manager.createGroup(groupId: groupId)
        
        measure(metrics: [
            XCTClockMetric(),
            XCTMemoryMetric(),
            XCTCPUMetric()
        ]) {
            _ = try? manager.encryptMessage("First message after launch", groupId: groupId)
        }
        
        try? manager.deleteGroup(groupId)
    }
}
