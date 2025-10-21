import Foundation

/// Models matching the server's lexicon definitions

struct ConvoView: Codable {
    let id: String
    let members: [MemberInfo]
    let createdAt: Date
    let createdBy: String
    let unreadCount: Int
    let epoch: Int
    let title: String?
}

struct MemberInfo: Codable {
    let did: String
}

struct MessageView: Codable {
    let id: String
    let ciphertext: String
    let epoch: Int
    let sender: MemberInfo
    let sentAt: Date
}

struct CreateConvoRequest: Codable {
    let didList: [String]?
    let title: String?
}

struct AddMembersRequest: Codable {
    let convoId: String
    let didList: [String]
    let commit: String?
    let welcome: String?
}

struct SendMessageRequest: Codable {
    let convoId: String
    let ciphertext: String
    let epoch: Int
    let senderDid: String
}

struct PublishKeyPackageRequest: Codable {
    let keyPackage: String
    let cipherSuite: String
    let expires: Date
}

struct BlobRef: Codable {
    let cid: String
    let size: Int64
}

// Local models for app use

struct Conversation: Identifiable {
    let id: String
    let title: String
    let members: [String]
    let lastMessage: String?
    let lastMessageTime: Date?
    let unreadCount: Int
    let epoch: Int
}

struct Message: Identifiable {
    let id: String
    let convoId: String
    let senderDid: String
    let content: String
    let sentAt: Date
    let isFromMe: Bool
}
