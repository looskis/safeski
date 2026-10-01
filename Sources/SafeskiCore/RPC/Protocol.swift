import Foundation

/// Wire protocol: 4-byte big-endian length prefix + JSON. One request, one response, per message.
/// Methods are strings like "keys.list"; params/result are JSON.
public struct RPCRequest: Codable {
    public var id: Int
    public var method: String
    public var params: JSONValue
    /// Optional bearer token for callers that cannot be identified by peer credentials.
    public var token: String?
    public init(id: Int, method: String, params: JSONValue = .object([:]), token: String? = nil) {
        self.id = id; self.method = method; self.params = params; self.token = token
    }
}

public struct RPCError: Codable, Equatable {
    public var code: String
    public var message: String
    public init(code: String, message: String) { self.code = code; self.message = message }
    public init(_ e: Error) {
        if let s = e as? SafeskiError { code = s.code; message = s.message }
        else { code = "internal"; message = e.localizedDescription }
    }
    public var asError: SafeskiError { SafeskiError.fromCode(code, message: message) }
}

public struct RPCResponse: Codable {
    public var id: Int
    public var result: JSONValue?
    public var error: RPCError?
    public init(id: Int, result: JSONValue? = nil, error: RPCError? = nil) { self.id = id; self.result = result; self.error = error }
}

public enum RPCMethod {
    public static let status = "status"
    public static let keysList = "keys.list"
    public static let keysCreate = "keys.create"
    public static let keysGet = "keys.get"
    public static let keysDelete = "keys.delete"
    public static let keysSign = "keys.sign"
    public static let keysAgree = "keys.agree"
    public static let secretsList = "secrets.list"
    public static let secretsSet = "secrets.set"
    public static let secretsGet = "secrets.get"
    public static let secretsDelete = "secrets.delete"
    public static let policyReload = "policy.reload"
    public static let auditTail = "audit.tail"
    public static let devicesList = "devices.list"
    public static let whoami = "whoami"
    public static let approvalsClear = "approvals.clear"
}

// Typed params/results shared by client and server.
public struct SignParams: Codable {
    public var key: String
    public var data: Data
    public var digest: Bool
    public var purpose: String?
    public init(key: String, data: Data, digest: Bool, purpose: String? = nil) { self.key = key; self.data = data; self.digest = digest; self.purpose = purpose }
}
public struct SignResult: Codable { public var signature: Data; public init(signature: Data) { self.signature = signature } }
public struct AgreeParams: Codable {
    public var key: String; public var peerPublicKey: Data
    public init(key: String, peerPublicKey: Data) { self.key = key; self.peerPublicKey = peerPublicKey }
}
public struct AgreeResult: Codable { public var sharedSecret: Data }
public struct CreateKeyParams: Codable {
    public var name: String; public var kind: KeyKind; public var access: AccessPolicy; public var comment: String?
    public init(name: String, kind: KeyKind, access: AccessPolicy, comment: String?) { self.name = name; self.kind = kind; self.access = access; self.comment = comment }
}
public struct NameParams: Codable { public var name: String; public init(name: String) { self.name = name } }
public struct SetSecretParams: Codable {
    public var name: String; public var value: Data; public var contentType: String
    public init(name: String, value: Data, contentType: String) { self.name = name; self.value = value; self.contentType = contentType }
}
public struct SecretValue: Codable { public var value: Data; public var contentType: String }
public struct TailParams: Codable { public var n: Int; public init(n: Int) { self.n = n } }

public struct StatusResult: Codable {
    public var version: String
    public var deviceID: String
    public var deviceName: String
    public var pid: Int
    public var uptimeSeconds: Double
    public var socket: String
    public var sshSocket: String?
    public var keys: Int
    public var secrets: Int
    public var auditHead: Int
    public var policyLoaded: Date?
    public var extra: [String: JSONValue]?
}

public enum Version {
    public static let string = "0.1.0"
}
