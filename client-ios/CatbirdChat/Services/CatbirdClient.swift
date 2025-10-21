import Foundation

/// Network client for Catbird MLS server
class CatbirdClient {
    private let baseURL: URL
    private var authToken: String?
    
    init(baseURL: String = Config.serverURL) {
        self.baseURL = URL(string: baseURL)!
    }
    
    func setAuthToken(_ token: String) {
        self.authToken = token
    }
    
    // MARK: - API Methods
    
    func createConvo(request: CreateConvoRequest) async throws -> ConvoView {
        try await post("/xrpc/blue.catbird.mls.createConvo", body: request)
    }
    
    func addMembers(request: AddMembersRequest) async throws {
        let _: EmptyResponse = try await post("/xrpc/blue.catbird.mls.addMembers", body: request)
    }
    
    func sendMessage(request: SendMessageRequest) async throws {
        let _: EmptyResponse = try await post("/xrpc/blue.catbird.mls.sendMessage", body: request)
    }
    
    func getMessages(convoId: String, sinceMessage: String? = nil) async throws -> [MessageView] {
        var components = URLComponents(url: baseURL.appendingPathComponent("/xrpc/blue.catbird.mls.getMessages"), resolvingAgainstBaseURL: false)!
        var queryItems = [URLQueryItem(name: "convoId", value: convoId)]
        if let since = sinceMessage {
            queryItems.append(URLQueryItem(name: "sinceMessage", value: since))
        }
        components.queryItems = queryItems
        
        let response: MessagesResponse = try await get(components.url!)
        return response.messages
    }
    
    func publishKeyPackage(request: PublishKeyPackageRequest) async throws {
        let _: EmptyResponse = try await post("/xrpc/blue.catbird.mls.publishKeyPackage", body: request)
    }
    
    func getKeyPackages(dids: [String]) async throws -> [KeyPackageInfo] {
        var components = URLComponents(url: baseURL.appendingPathComponent("/xrpc/blue.catbird.mls.getKeyPackages"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "dids", value: dids.joined(separator: ","))]
        
        let response: KeyPackagesResponse = try await get(components.url!)
        return response.keyPackages
    }
    
    func uploadBlob(data: Data) async throws -> BlobRef {
        try await post("/xrpc/blue.catbird.mls.uploadBlob", body: data, contentType: "application/octet-stream")
    }
    
    // MARK: - HTTP Methods
    
    private func post<T: Encodable, R: Decodable>(_ path: String, body: T, contentType: String = "application/json") async throws -> R {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        if contentType == "application/json" {
            request.httpBody = try JSONEncoder().encode(body)
        } else if let data = body as? Data {
            request.httpBody = data
        }
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw CatbirdError.httpError((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        
        return try JSONDecoder().decode(R.self, from: data)
    }
    
    private func get<R: Decodable>(_ url: URL) async throws -> R {
        var request = URLRequest(url: url)
        
        if let token = authToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw CatbirdError.httpError((response as? HTTPURLResponse)?.statusCode ?? -1)
        }
        
        return try JSONDecoder().decode(R.self, from: data)
    }
}

// MARK: - Response Types

private struct EmptyResponse: Codable {}

private struct MessagesResponse: Codable {
    let messages: [MessageView]
}

struct KeyPackageInfo: Codable {
    let did: String
    let keyPackage: String
    let cipherSuite: String
}

private struct KeyPackagesResponse: Codable {
    let keyPackages: [KeyPackageInfo]
}

enum CatbirdError: Error {
    case httpError(Int)
    case invalidResponse
    case unauthorized
}
