import XCTest
@testable import CatbirdChat

/// End-to-end tests for MLS group operations
final class MLSGroupTests: XCTestCase {
    
    var mockServer: MockMLSServer!
    var client: CatbirdClient!
    
    override func setUp() {
        super.setUp()
        mockServer = MockMLSServer.shared
        mockServer.reset()
        client = CatbirdClient(baseURL: "http://localhost:8080")
        client.setAuthToken(mockServer.authToken ?? "")
    }
    
    override func tearDown() {
        mockServer.reset()
        super.tearDown()
    }
    
    // MARK: - Group Creation Tests
    
    func testCreateEmptyGroup() async throws {
        let creator = TestData.generateDID(0)
        let members = [creator]
        
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Empty Group",
            createdBy: creator
        )
        
        XCTAssertEqual(convo.members.count, 1)
        XCTAssertEqual(convo.members.first, creator)
        XCTAssertEqual(convo.title, "Empty Group")
        XCTAssertEqual(convo.epoch, 1)
    }
    
    func testCreateGroupWithMultipleMembers() async throws {
        let members = TestData.generateMultipleDIDs(count: 5)
        let creator = members[0]
        
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test Group",
            createdBy: creator
        )
        
        XCTAssertEqual(convo.members.count, 5)
        XCTAssertEqual(Set(convo.members), Set(members))
        XCTAssertEqual(convo.createdBy, creator)
    }
    
    func testCreateGroupWithTitle() async throws {
        let members = TestData.generateMultipleDIDs(count: 3)
        let title = "My Awesome Group"
        
        let convo = try await mockServer.createConversation(
            members: members,
            title: title,
            createdBy: members[0]
        )
        
        XCTAssertEqual(convo.title, title)
    }
    
    func testCreateMultipleGroups() async throws {
        let creator = TestData.generateDID(0)
        
        let convo1 = try await mockServer.createConversation(
            members: [creator],
            title: "Group 1",
            createdBy: creator
        )
        
        let convo2 = try await mockServer.createConversation(
            members: [creator],
            title: "Group 2",
            createdBy: creator
        )
        
        XCTAssertNotEqual(convo1.id, convo2.id)
    }
    
    // MARK: - Add Members Tests
    
    func testAddSingleMember() async throws {
        let members = TestData.generateMultipleDIDs(count: 2)
        let convo = try await mockServer.createConversation(
            members: [members[0]],
            title: "Test",
            createdBy: members[0]
        )
        
        let initialEpoch = convo.epoch
        
        try await mockServer.addMembers(to: convo.id, dids: [members[1]])
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.members.count, 2)
        XCTAssertTrue(mockServer.isMember(convoId: convo.id, did: members[1]))
        XCTAssertEqual(updated.epoch, initialEpoch + 1)
    }
    
    func testAddMultipleMembers() async throws {
        let creator = TestData.generateDID(0)
        let newMembers = TestData.generateMultipleDIDs(count: 5).filter { $0 != creator }
        
        let convo = try await mockServer.createConversation(
            members: [creator],
            title: "Test",
            createdBy: creator
        )
        
        try await mockServer.addMembers(to: convo.id, dids: Array(newMembers.prefix(3)))
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.members.count, 4)
    }
    
    func testAddDuplicateMember() async throws {
        let member = TestData.generateDID(0)
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Test",
            createdBy: member
        )
        
        do {
            try await mockServer.addMembers(to: convo.id, dids: [member])
            XCTFail("Should have thrown conflict error")
        } catch MockError.conflict {
            // Expected
        }
    }
    
    func testAddMembersToNonexistentGroup() async throws {
        let member = TestData.generateDID(0)
        
        do {
            try await mockServer.addMembers(to: "nonexistent", dids: [member])
            XCTFail("Should have thrown not found error")
        } catch MockError.notFound {
            // Expected
        }
    }
    
    // MARK: - Remove Members Tests
    
    func testRemoveMember() async throws {
        let members = TestData.generateMultipleDIDs(count: 3)
        let convo = try await mockServer.createConversation(
            members: members,
            title: "Test",
            createdBy: members[0]
        )
        
        try await mockServer.removeMember(from: convo.id, did: members[1])
        
        let updated = try await mockServer.getConversation(convo.id)
        XCTAssertEqual(updated.members.count, 2)
        XCTAssertFalse(mockServer.isMember(convoId: convo.id, did: members[1]))
        XCTAssertEqual(updated.epoch, convo.epoch + 1)
    }
    
    func testRemoveNonexistentMember() async throws {
        let member = TestData.generateDID(0)
        let convo = try await mockServer.createConversation(
            members: [member],
            title: "Test",
            createdBy: member
        )
        
        do {
            try await mockServer.removeMember(from: convo.id, did: TestData.generateDID(999))
            XCTFail("Should have thrown not found error")
        } catch MockError.notFound {
            // Expected
        }
    }
    
    // MARK: - List Conversations Tests
    
    func testListConversations() async throws {
        let user = TestData.generateDID(0)
        
        _ = try await mockServer.createConversation(
            members: [user],
            title: "Convo 1",
            createdBy: user
        )
        
        _ = try await mockServer.createConversation(
            members: [user],
            title: "Convo 2",
            createdBy: user
        )
        
        let convos = try await mockServer.listConversations(for: user)
        XCTAssertEqual(convos.count, 2)
    }
    
    func testListConversationsFiltered() async throws {
        let user1 = TestData.generateDID(0)
        let user2 = TestData.generateDID(1)
        
        _ = try await mockServer.createConversation(
            members: [user1],
            title: "User1 Only",
            createdBy: user1
        )
        
        _ = try await mockServer.createConversation(
            members: [user1, user2],
            title: "Both Users",
            createdBy: user1
        )
        
        let user1Convos = try await mockServer.listConversations(for: user1)
        let user2Convos = try await mockServer.listConversations(for: user2)
        
        XCTAssertEqual(user1Convos.count, 2)
        XCTAssertEqual(user2Convos.count, 1)
    }
}
