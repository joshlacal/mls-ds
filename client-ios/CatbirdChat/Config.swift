import Foundation

/// Configuration for the Catbird MLS client
enum Config {
    /// Server endpoint URL
    static let serverURL = "http://localhost:3000"
    
    /// Default MLS cipher suite
    static let defaultCipherSuite = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"
    
    /// KeyPackage lifetime in seconds (24 hours)
    static let keyPackageLifetime: TimeInterval = 24 * 60 * 60
    
    /// Maximum message size in bytes (1 MB)
    static let maxMessageSize = 1_048_576
    
    /// Sync interval in seconds
    static let syncInterval: TimeInterval = 5.0
}
