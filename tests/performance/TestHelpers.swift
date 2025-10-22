//
//  TestHelpers.swift
//  MLS Performance Test Suite
//
//  Helper utilities for performance tests
//

import Foundation

// MARK: - Mock Classes for Testing

class MLSManager {
    static let shared = MLSManager()
    
    func initialize() -> Bool {
        return true
    }
    
    func loadConfiguration() -> Bool {
        return true
    }
    
    func loadAllGroups() -> [String] {
        return []
    }
    
    func loadAllKeyPackages() -> [String] {
        return []
    }
    
    func warmupCaches() -> Bool {
        return true
    }
    
    func refreshGroupStates() -> Bool {
        return true
    }
    
    func generateKeyPair() throws -> (String, String) {
        return ("public_key", "private_key")
    }
    
    func createKeyPackage() throws -> String {
        return "key_package_\(UUID().uuidString)"
    }
    
    func createGroup(groupId: String) throws {
        // Simulate group creation
        Thread.sleep(forTimeInterval: 0.01)
    }
    
    func deleteGroup(_ groupId: String) throws {
        // Simulate group deletion
        Thread.sleep(forTimeInterval: 0.005)
    }
    
    func addMember(_ memberId: String, to groupId: String) throws -> String {
        // Simulate adding member, return welcome message
        Thread.sleep(forTimeInterval: 0.02)
        return "welcome_message_\(memberId)"
    }
    
    func removeMember(_ memberId: String, from groupId: String) throws {
        // Simulate removing member
        Thread.sleep(forTimeInterval: 0.015)
    }
    
    func encryptMessage(_ message: String, groupId: String) throws -> String {
        // Simulate encryption
        Thread.sleep(forTimeInterval: 0.003)
        return "encrypted_\(message)"
    }
    
    func decryptMessage(_ encrypted: String, groupId: String) throws -> String {
        // Simulate decryption
        Thread.sleep(forTimeInterval: 0.003)
        return encrypted.replacingOccurrences(of: "encrypted_", with: "")
    }
    
    func exportGroupState(_ groupId: String) throws -> Data {
        // Simulate state export
        return Data(count: 10240)
    }
    
    func importGroupState(_ data: Data, groupId: String) throws {
        // Simulate state import
        Thread.sleep(forTimeInterval: 0.05)
    }
    
    func cleanupMemory() -> Bool {
        return true
    }
    
    func clearCaches() {
        // Clear internal caches
    }
    
    func enableCaching() {
        // Enable caching
    }
    
    func enableLowPowerMode() {
        // Enable low power optimizations
    }
    
    func disableLowPowerMode() {
        // Disable low power mode
    }
    
    func enableBackgroundSync() {
        // Enable background sync
    }
    
    func disableBackgroundSync() {
        // Disable background sync
    }
    
    func refreshGroupKeys(groupId: String) throws {
        Thread.sleep(forTimeInterval: 0.02)
    }
    
    func syncGroupWithServer(groupId: String) throws {
        Thread.sleep(forTimeInterval: 0.1)
    }
    
    func encryptMessageBatch(_ messages: [String], groupId: String) throws -> [String] {
        return try messages.map { try encryptMessage($0, groupId: groupId) }
    }
    
    func uploadKeyPackage(_ keyPackage: String) throws {
        Thread.sleep(forTimeInterval: 0.05)
    }
    
    func uploadKeyPackageBatch(_ packages: [String]) throws {
        Thread.sleep(forTimeInterval: 0.1)
    }
    
    func createAddCommit(_ memberId: String, groupId: String) throws -> String {
        return "commit_\(memberId)"
    }
}

class MLSDatabase {
    static let shared = MLSDatabase()
    
    func connect() throws {
        Thread.sleep(forTimeInterval: 0.01)
    }
    
    func disconnect() {
        // Disconnect
    }
    
    func cleanupTestData() throws {
        // Cleanup
    }
    
    func insertGroup(groupId: String, name: String) throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func getGroup(groupId: String) throws -> GroupData {
        Thread.sleep(forTimeInterval: 0.001)
        return GroupData(id: groupId, name: "Group")
    }
    
    func updateGroup(groupId: String, name: String) throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func deleteGroup(groupId: String) throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func getAllGroups() throws -> [GroupData] {
        Thread.sleep(forTimeInterval: 0.05)
        return []
    }
    
    func bulkInsertGroups(_ groups: [GroupData]) throws {
        Thread.sleep(forTimeInterval: Double(groups.count) * 0.0001)
    }
    
    func bulkUpdateGroups(_ groups: [GroupData]) throws {
        Thread.sleep(forTimeInterval: Double(groups.count) * 0.0001)
    }
    
    func bulkDeleteGroups(_ groupIds: [String]) throws {
        Thread.sleep(forTimeInterval: Double(groupIds.count) * 0.0001)
    }
    
    func insertMember(memberId: String, groupId: String) throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func insertMessage(groupId: String, senderId: String, content: String) throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func getGroupsByTimestampRange(from: Date, to: Date) throws -> [GroupData] {
        Thread.sleep(forTimeInterval: 0.01)
        return []
    }
    
    func searchGroupsByMetadata(_ query: String) throws -> [GroupData] {
        Thread.sleep(forTimeInterval: 0.02)
        return []
    }
    
    func getGroupsWithMembers() throws -> [(GroupData, [String])] {
        Thread.sleep(forTimeInterval: 0.03)
        return []
    }
    
    func getGroupsWithMembersAndMessages() throws -> [(GroupData, [String], [String])] {
        Thread.sleep(forTimeInterval: 0.05)
        return []
    }
    
    func beginTransaction() throws {
        Thread.sleep(forTimeInterval: 0.001)
    }
    
    func commitTransaction() throws {
        Thread.sleep(forTimeInterval: 0.002)
    }
    
    func getDatabaseSize() throws -> Int {
        return 1024 * 1024
    }
    
    func vacuum() throws {
        Thread.sleep(forTimeInterval: 0.1)
    }
}

class NetworkMonitor {
    static let shared = NetworkMonitor()
    
    var totalBytesSent: Int = 0
    
    func startMonitoring() {
        totalBytesSent = 0
    }
    
    func stopMonitoring() {
        // Stop monitoring
    }
    
    func simulateUnstableNetwork() {
        // Simulate network issues
    }
    
    func restoreNormalNetwork() {
        // Restore normal network
    }
}

class EnergyMonitor {
    static let shared = EnergyMonitor()
    
    private var startEnergy: Double = 0
    
    func startMonitoring() {
        startEnergy = getCurrentEnergy()
    }
    
    func stopMonitoring() -> Double {
        let endEnergy = getCurrentEnergy()
        return endEnergy - startEnergy
    }
    
    private func getCurrentEnergy() -> Double {
        // Simulate energy reading
        return Double.random(in: 0...100)
    }
}

// MARK: - Data Structures

struct GroupData {
    let id: String
    let name: String
    var timestamp: Date?
    var metadata: String?
    
    init(id: String, name: String, timestamp: Date? = nil, metadata: String? = nil) {
        self.id = id
        self.name = name
        self.timestamp = timestamp
        self.metadata = metadata
    }
}

// MARK: - Extensions

extension Data {
    func compressed() -> Data? {
        // Simulate compression
        return self
    }
}
