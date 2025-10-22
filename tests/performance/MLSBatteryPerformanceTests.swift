//
//  MLSBatteryPerformanceTests.swift
//  MLS Performance Test Suite
//
//  Battery drain and energy usage tests
//

import XCTest
@testable import CatbirdChat

class MLSBatteryPerformanceTests: XCTestCase {
    
    var mlsManager: MLSManager!
    var energyMonitor: EnergyMonitor!
    
    override func setUpWithError() throws {
        try super.setUpWithError()
        mlsManager = MLSManager.shared
        energyMonitor = EnergyMonitor.shared
    }
    
    override func tearDownWithError() throws {
        mlsManager = nil
        energyMonitor = nil
        try super.tearDownWithError()
    }
    
    // MARK: - Idle Energy Usage
    
    func testIdleEnergyConsumption() throws {
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            // App is idle with MLS initialized
            _ = mlsManager.initialize()
            
            // Wait for 60 seconds to measure idle consumption
            Thread.sleep(forTimeInterval: 60.0)
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Idle energy consumption: \(energyUsed)mAh")
    }
    
    // MARK: - Active Operation Energy Usage
    
    func testEncryptionEnergyUsage() throws {
        let groupId = "energy_encrypt_group"
        try mlsManager.createGroup(groupId: groupId)
        
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            for i in 0..<100 {
                let message = "Energy test message \(i)"
                _ = try? mlsManager.encryptMessage(message, groupId: groupId)
            }
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Energy used for 100 encryptions: \(energyUsed)mAh")
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testDecryptionEnergyUsage() throws {
        let groupId = "energy_decrypt_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Pre-encrypt messages
        let encryptedMessages = try (0..<100).compactMap { i -> String? in
            let message = "Energy test message \(i)"
            return try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            for encrypted in encryptedMessages {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Energy used for 100 decryptions: \(energyUsed)mAh")
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testGroupOperationEnergyUsage() throws {
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            for i in 0..<10 {
                let groupId = "energy_group_\(i)"
                try? mlsManager.createGroup(groupId: groupId)
                
                for j in 0..<20 {
                    let memberId = "member_\(j)"
                    _ = try? mlsManager.addMember(memberId, to: groupId)
                }
                
                try? mlsManager.deleteGroup(groupId)
            }
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Energy used for group operations: \(energyUsed)mAh")
    }
    
    // MARK: - Background Activity Energy
    
    func testBackgroundSyncEnergyUsage() throws {
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            // Simulate background sync activity
            mlsManager.enableBackgroundSync()
            
            // Wait for background tasks to complete
            Thread.sleep(forTimeInterval: 30.0)
            
            mlsManager.disableBackgroundSync()
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Background sync energy usage: \(energyUsed)mAh")
    }
    
    func testKeyRefreshEnergyUsage() throws {
        let groupId = "energy_refresh_group"
        try mlsManager.createGroup(groupId: groupId)
        
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            for _ in 0..<10 {
                _ = try? mlsManager.refreshGroupKeys(groupId: groupId)
                Thread.sleep(forTimeInterval: 1.0)
            }
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Key refresh energy usage: \(energyUsed)mAh")
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - CPU Usage Tests
    
    func testCPUUsageDuringEncryption() throws {
        let groupId = "cpu_encrypt_group"
        try mlsManager.createGroup(groupId: groupId)
        
        measure(metrics: [XCTCPUMetric()]) {
            for i in 0..<50 {
                let message = "CPU test message \(i)"
                _ = try? mlsManager.encryptMessage(message, groupId: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testCPUUsageDuringLargeGroupUpdate() throws {
        let groupId = "cpu_large_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Create large group
        for i in 0..<100 {
            try mlsManager.addMember("member_\(i)", to: groupId)
        }
        
        measure(metrics: [XCTCPUMetric()]) {
            for i in 100..<120 {
                _ = try? mlsManager.addMember("member_\(i)", to: groupId)
            }
        }
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Network-related Energy
    
    func testNetworkOperationEnergyUsage() throws {
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            for i in 0..<20 {
                let groupId = "network_energy_group_\(i)"
                try? mlsManager.createGroup(groupId: groupId)
                _ = try? mlsManager.syncGroupWithServer(groupId: groupId)
                try? mlsManager.deleteGroup(groupId)
            }
        }
        
        let energyUsed = energyMonitor.stopMonitoring()
        print("Network operations energy usage: \(energyUsed)mAh")
    }
    
    // MARK: - Optimization Tests
    
    func testBatchOperationEnergyEfficiency() throws {
        let groupId = "batch_energy_group"
        try mlsManager.createGroup(groupId: groupId)
        
        let messages = (0..<50).map { "Batch message \($0)" }
        
        // Test individual operations
        energyMonitor.startMonitoring()
        for message in messages {
            _ = try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        let individualEnergy = energyMonitor.stopMonitoring()
        
        // Test batch operations
        energyMonitor.startMonitoring()
        _ = try? mlsManager.encryptMessageBatch(messages, groupId: groupId)
        let batchEnergy = energyMonitor.stopMonitoring()
        
        print("Individual operations: \(individualEnergy)mAh")
        print("Batch operations: \(batchEnergy)mAh")
        print("Energy savings: \(String(format: "%.2f", (1 - batchEnergy/individualEnergy) * 100))%")
        
        XCTAssertLessThan(batchEnergy, individualEnergy, "Batch operations should use less energy")
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    func testCachingEnergyImpact() throws {
        let groupId = "cache_energy_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Test without cache
        mlsManager.clearCaches()
        energyMonitor.startMonitoring()
        
        for i in 0..<50 {
            let message = "Message \(i)"
            if let encrypted = try? mlsManager.encryptMessage(message, groupId: groupId) {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
        }
        
        let noCacheEnergy = energyMonitor.stopMonitoring()
        
        // Test with cache
        mlsManager.enableCaching()
        energyMonitor.startMonitoring()
        
        for i in 0..<50 {
            let message = "Message \(i)"
            if let encrypted = try? mlsManager.encryptMessage(message, groupId: groupId) {
                _ = try? mlsManager.decryptMessage(encrypted, groupId: groupId)
            }
        }
        
        let cacheEnergy = energyMonitor.stopMonitoring()
        
        print("Without cache: \(noCacheEnergy)mAh")
        print("With cache: \(cacheEnergy)mAh")
        print("Energy savings: \(String(format: "%.2f", (1 - cacheEnergy/noCacheEnergy) * 100))%")
        
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Power State Tests
    
    func testLowPowerModeImpact() throws {
        let groupId = "low_power_group"
        try mlsManager.createGroup(groupId: groupId)
        
        // Test normal mode
        energyMonitor.startMonitoring()
        
        for i in 0..<30 {
            let message = "Normal mode message \(i)"
            _ = try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        
        let normalEnergy = energyMonitor.stopMonitoring()
        
        // Test low power mode
        mlsManager.enableLowPowerMode()
        energyMonitor.startMonitoring()
        
        for i in 0..<30 {
            let message = "Low power message \(i)"
            _ = try? mlsManager.encryptMessage(message, groupId: groupId)
        }
        
        let lowPowerEnergy = energyMonitor.stopMonitoring()
        
        print("Normal mode: \(normalEnergy)mAh")
        print("Low power mode: \(lowPowerEnergy)mAh")
        
        mlsManager.disableLowPowerMode()
        try? mlsManager.deleteGroup(groupId)
    }
    
    // MARK: - Long-running Tests
    
    func testExtendedUsageEnergyDrain() throws {
        // This test simulates 1 hour of typical MLS usage
        let groupId = "extended_usage_group"
        try mlsManager.createGroup(groupId: groupId)
        
        energyMonitor.startMonitoring()
        
        measure(metrics: [XCTCPUMetric()]) {
            // Simulate 1 hour of activity (compressed to 60 seconds for testing)
            for _ in 0..<60 {
                // Send messages
                for i in 0..<5 {
                    let message = "Extended test message \(i)"
                    _ = try? mlsManager.encryptMessage(message, groupId: groupId)
                }
                
                Thread.sleep(forTimeInterval: 1.0)
            }
        }
        
        let totalEnergy = energyMonitor.stopMonitoring()
        let hourlyProjection = totalEnergy * 60
        print("Projected hourly energy drain: \(hourlyProjection)mAh")
        
        try? mlsManager.deleteGroup(groupId)
    }
}
