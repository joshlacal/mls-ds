//
//  MLSDatabasePerformanceTests.swift
//  MLS Performance Test Suite
//
//  Database query and storage performance tests
//

import XCTest
@testable import CatbirdChat

class MLSDatabasePerformanceTests: XCTestCase {
    
    var database: MLSDatabase!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        database = MLSDatabase.shared
        try database.connect()
    }
    
    override func tearDownWithError() throws {
        try database.cleanupTestData()
        database.disconnect()
        database = nil
        try super.tearDownWithError()
    }
    
    // MARK: - Basic Query Performance
    
    func testInsertGroupPerformance() throws {
        measure(metrics: [XCTClockMetric(), XCTStorageMetric()]) {
            for i in 0..<100 {
                let groupId = "db_insert_group_\(i)"
                _ = try? database.insertGroup(groupId: groupId, name: "Test Group \(i)")
            }
        }
    }
    
    func testSelectGroupPerformance() throws {
        // Setup: Insert test groups
        for i in 0..<100 {
            let groupId = "db_select_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Test Group \(i)")
        }
        
        measure(metrics: [XCTClockMetric()]) {
            for i in 0..<100 {
                let groupId = "db_select_group_\(i)"
                _ = try? database.getGroup(groupId: groupId)
            }
        }
    }
    
    func testUpdateGroupPerformance() throws {
        // Setup: Insert test groups
        for i in 0..<100 {
            let groupId = "db_update_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Test Group \(i)")
        }
        
        measure(metrics: [XCTClockMetric()]) {
            for i in 0..<100 {
                let groupId = "db_update_group_\(i)"
                _ = try? database.updateGroup(groupId: groupId, name: "Updated Group \(i)")
            }
        }
    }
    
    func testDeleteGroupPerformance() throws {
        // Setup: Insert test groups
        for i in 0..<100 {
            let groupId = "db_delete_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Test Group \(i)")
        }
        
        measure(metrics: [XCTClockMetric()]) {
            for i in 0..<100 {
                let groupId = "db_delete_group_\(i)"
                _ = try? database.deleteGroup(groupId: groupId)
            }
        }
    }
    
    // MARK: - Bulk Operations
    
    func testBulkInsertPerformance() throws {
        let groups = (0..<1000).map { i in
            GroupData(id: "bulk_group_\(i)", name: "Bulk Group \(i)")
        }
        
        measure(metrics: [XCTClockMetric(), XCTStorageMetric()]) {
            _ = try? database.bulkInsertGroups(groups)
        }
    }
    
    func testBulkSelectPerformance() throws {
        // Setup: Insert test groups
        let groups = (0..<1000).map { i in
            GroupData(id: "bulk_select_group_\(i)", name: "Bulk Group \(i)")
        }
        try database.bulkInsertGroups(groups)
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.getAllGroups()
        }
    }
    
    func testBulkUpdatePerformance() throws {
        // Setup: Insert test groups
        let groups = (0..<1000).map { i in
            GroupData(id: "bulk_update_group_\(i)", name: "Bulk Group \(i)")
        }
        try database.bulkInsertGroups(groups)
        
        let updates = groups.map { group in
            GroupData(id: group.id, name: "Updated \(group.name)")
        }
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.bulkUpdateGroups(updates)
        }
    }
    
    func testBulkDeletePerformance() throws {
        // Setup: Insert test groups
        let groups = (0..<1000).map { i in
            GroupData(id: "bulk_delete_group_\(i)", name: "Bulk Group \(i)")
        }
        try database.bulkInsertGroups(groups)
        
        let groupIds = groups.map { $0.id }
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.bulkDeleteGroups(groupIds)
        }
    }
    
    // MARK: - Index Performance
    
    func testIndexedQueryPerformance() throws {
        // Setup: Insert 10000 groups
        let groups = (0..<10000).map { i in
            GroupData(id: "indexed_group_\(i)", name: "Group \(i)", timestamp: Date())
        }
        try database.bulkInsertGroups(groups)
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.getGroupsByTimestampRange(
                from: Date().addingTimeInterval(-3600),
                to: Date()
            )
        }
    }
    
    func testUnindexedQueryPerformance() throws {
        // Setup: Insert 1000 groups
        let groups = (0..<1000).map { i in
            GroupData(id: "unindexed_group_\(i)", name: "Group \(i)", metadata: "meta_\(i)")
        }
        try database.bulkInsertGroups(groups)
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.searchGroupsByMetadata("meta_500")
        }
    }
    
    // MARK: - Join Query Performance
    
    func testJoinQueryPerformance() throws {
        // Setup: Create groups with members
        for i in 0..<100 {
            let groupId = "join_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Group \(i)")
            
            for j in 0..<10 {
                let memberId = "member_\(j)"
                try database.insertMember(memberId: memberId, groupId: groupId)
            }
        }
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.getGroupsWithMembers()
        }
    }
    
    func testComplexJoinQueryPerformance() throws {
        // Setup: Create complex data structure
        for i in 0..<50 {
            let groupId = "complex_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Group \(i)")
            
            for j in 0..<20 {
                let memberId = "member_\(j)"
                try database.insertMember(memberId: memberId, groupId: groupId)
                
                for k in 0..<5 {
                    try database.insertMessage(
                        groupId: groupId,
                        senderId: memberId,
                        content: "Message \(k)"
                    )
                }
            }
        }
        
        measure(metrics: [XCTClockMetric()]) {
            _ = try? database.getGroupsWithMembersAndMessages()
        }
    }
    
    // MARK: - Transaction Performance
    
    func testTransactionPerformance() throws {
        measure(metrics: [XCTClockMetric()]) {
            try? database.beginTransaction()
            
            for i in 0..<100 {
                let groupId = "transaction_group_\(i)"
                _ = try? database.insertGroup(groupId: groupId, name: "Group \(i)")
            }
            
            try? database.commitTransaction()
        }
    }
    
    func testNestedTransactionPerformance() throws {
        measure(metrics: [XCTClockMetric()]) {
            try? database.beginTransaction()
            
            for i in 0..<10 {
                let groupId = "nested_group_\(i)"
                try? database.insertGroup(groupId: groupId, name: "Group \(i)")
                
                try? database.beginTransaction()
                for j in 0..<10 {
                    let memberId = "member_\(j)"
                    try? database.insertMember(memberId: memberId, groupId: groupId)
                }
                try? database.commitTransaction()
            }
            
            try? database.commitTransaction()
        }
    }
    
    // MARK: - Cache Performance
    
    func testDatabaseCacheHitRate() throws {
        // Setup: Insert test groups
        for i in 0..<100 {
            let groupId = "cache_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Group \(i)")
        }
        
        // Warm up cache
        for i in 0..<100 {
            let groupId = "cache_group_\(i)"
            _ = try? database.getGroup(groupId: groupId)
        }
        
        measure(metrics: [XCTClockMetric()]) {
            for i in 0..<100 {
                let groupId = "cache_group_\(i)"
                _ = try? database.getGroup(groupId: groupId)
            }
        }
    }
    
    // MARK: - Concurrent Access Performance
    
    func testConcurrentReadPerformance() throws {
        // Setup: Insert test groups
        for i in 0..<100 {
            let groupId = "concurrent_read_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Group \(i)")
        }
        
        measure(metrics: [XCTClockMetric()]) {
            let expectation = self.expectation(description: "Concurrent reads")
            expectation.expectedFulfillmentCount = 10
            
            DispatchQueue.concurrentPerform(iterations: 10) { i in
                for j in 0..<10 {
                    let groupId = "concurrent_read_group_\(j * 10 + i)"
                    _ = try? database.getGroup(groupId: groupId)
                }
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    func testConcurrentWritePerformance() throws {
        measure(metrics: [XCTClockMetric()]) {
            let expectation = self.expectation(description: "Concurrent writes")
            expectation.expectedFulfillmentCount = 10
            
            DispatchQueue.concurrentPerform(iterations: 10) { i in
                for j in 0..<10 {
                    let groupId = "concurrent_write_group_\(i * 10 + j)"
                    _ = try? database.insertGroup(groupId: groupId, name: "Group \(j)")
                }
                expectation.fulfill()
            }
            
            wait(for: [expectation], timeout: 10.0)
        }
    }
    
    // MARK: - Storage Size Tests
    
    func testDatabaseSizeGrowth() throws {
        let initialSize = try database.getDatabaseSize()
        
        measure(metrics: [XCTStorageMetric()]) {
            for i in 0..<1000 {
                let groupId = "size_growth_group_\(i)"
                try? database.insertGroup(groupId: groupId, name: "Group \(i)")
            }
            
            let finalSize = try? database.getDatabaseSize()
            if let final = finalSize {
                let growth = final - initialSize
                print("Database size growth for 1000 groups: \(growth) bytes")
            }
        }
    }
    
    func testVacuumPerformance() throws {
        // Setup: Create and delete many records
        for i in 0..<1000 {
            let groupId = "vacuum_group_\(i)"
            try database.insertGroup(groupId: groupId, name: "Group \(i)")
        }
        
        for i in 0..<1000 {
            let groupId = "vacuum_group_\(i)"
            try database.deleteGroup(groupId: groupId)
        }
        
        measure(metrics: [XCTClockMetric(), XCTStorageMetric()]) {
            try? database.vacuum()
        }
    }
}
