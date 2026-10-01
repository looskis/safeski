import Foundation

/// What the CLI talks to: either the running agent (remote) or the store in-process (local).
public protocol Backend {
    var isRemote: Bool { get }
    func status() throws -> StatusResult
    func whoami() throws -> CallerIdentity
    func listKeys() throws -> [KeySummary]
    func getKey(_ name: String) throws -> KeySummary
    func createKey(_ p: CreateKeyParams) throws -> KeySummary
    func deleteKey(_ name: String) throws
    func sign(_ p: SignParams) throws -> Data
    func agree(_ p: AgreeParams) throws -> Data
    func listSecrets() throws -> [SecretSummary]
    func setSecret(_ p: SetSecretParams) throws -> SecretSummary
    func getSecret(_ name: String, purpose: String?) throws -> SecretValue
    func deleteSecret(_ name: String) throws
    func reloadPolicy() throws
    func clearApprovals() throws
    func auditTail(_ n: Int) throws -> [AuditEvent]
    func listDevices() throws -> [DevicePublicRecord]
    func call(_ method: String, params: JSONValue) throws -> JSONValue
}

public final class LocalBackend: Backend {
    public let service: Service
    public let caller: CallerIdentity
    public var isRemote: Bool { false }

    public init(paths: SafeskiPaths = .default) throws {
        let store = Store(paths: paths)
        service = try Service(store: store, interactive: true)
        caller = .local()
    }

    public func status() throws -> StatusResult { try service.status(socket: "(local)", sshSocket: nil) }
    public func whoami() throws -> CallerIdentity { caller }
    public func listKeys() throws -> [KeySummary] { try service.listKeys(caller: caller) }
    public func getKey(_ name: String) throws -> KeySummary { try service.getKey(name, caller: caller) }
    public func createKey(_ p: CreateKeyParams) throws -> KeySummary { try service.createKey(p, caller: caller) }
    public func deleteKey(_ name: String) throws { try service.deleteKey(name, caller: caller) }
    public func sign(_ p: SignParams) throws -> Data { try service.sign(p, caller: caller) }
    public func agree(_ p: AgreeParams) throws -> Data { try service.agree(p, caller: caller) }
    public func listSecrets() throws -> [SecretSummary] { try service.listSecrets(caller: caller) }
    public func setSecret(_ p: SetSecretParams) throws -> SecretSummary { try service.setSecret(p, caller: caller) }
    public func getSecret(_ name: String, purpose: String?) throws -> SecretValue { try service.getSecret(name, purpose: purpose, caller: caller) }
    public func deleteSecret(_ name: String) throws { try service.deleteSecret(name, caller: caller) }
    public func reloadPolicy() throws { try service.reloadPolicy() }
    public func clearApprovals() throws { service.approvals.clear() }
    public func auditTail(_ n: Int) throws -> [AuditEvent] { try service.audit.tail(n) }
    public func listDevices() throws -> [DevicePublicRecord] { try service.store.listDevices() }
    public func call(_ method: String, params: JSONValue) throws -> JSONValue {
        let resp = service.dispatch(RPCRequest(id: 0, method: method, params: params), caller: caller, socket: "(local)", sshSocket: nil)
        if let e = resp.error { throw e.asError }
        return resp.result ?? .null
    }
}

public final class RemoteBackend: Backend {
    public let client: RPCClient
    public var isRemote: Bool { true }

    /// `brokerUser` (uid or username; "" = caller's own uid) routes the connection through the
    /// root broker socket: a `_broker.connect` hello is sent once after connecting.
    public init(socketPath: String, token: String? = nil, brokerUser: String? = nil) {
        let hello = brokerUser.map { BrokerProtocol.connectRequest(user: $0) }
        client = RPCClient(socketPath: socketPath, token: token, connectHello: hello)
    }

    public func status() throws -> StatusResult { try client.call(RPCMethod.status, as: StatusResult.self) }
    public func whoami() throws -> CallerIdentity { try client.call(RPCMethod.whoami, as: CallerIdentity.self) }
    public func listKeys() throws -> [KeySummary] { try client.call(RPCMethod.keysList, as: [KeySummary].self) }
    public func getKey(_ name: String) throws -> KeySummary { try client.call(RPCMethod.keysGet, NameParams(name: name), as: KeySummary.self) }
    public func createKey(_ p: CreateKeyParams) throws -> KeySummary { try client.call(RPCMethod.keysCreate, p, as: KeySummary.self) }
    public func deleteKey(_ name: String) throws { _ = try client.call(RPCMethod.keysDelete, params: try JSONValue(NameParams(name: name))) }
    public func sign(_ p: SignParams) throws -> Data { try client.call(RPCMethod.keysSign, p, as: SignResult.self).signature }
    public func agree(_ p: AgreeParams) throws -> Data {
        let r = try client.call(RPCMethod.keysAgree, params: try JSONValue(p))
        guard let s = r["sharedSecret"]?.stringValue, let d = Data(base64Encoded: s) else { throw SafeskiError.rpc("bad agree result") }
        return d
    }
    public func listSecrets() throws -> [SecretSummary] { try client.call(RPCMethod.secretsList, as: [SecretSummary].self) }
    public func setSecret(_ p: SetSecretParams) throws -> SecretSummary { try client.call(RPCMethod.secretsSet, p, as: SecretSummary.self) }
    public func getSecret(_ name: String, purpose: String?) throws -> SecretValue {
        var params: [String: JSONValue] = ["name": .string(name)]
        if let p = purpose { params["purpose"] = .string(p) }
        return try client.call(RPCMethod.secretsGet, params: .object(params)).decode(SecretValue.self)
    }
    public func deleteSecret(_ name: String) throws { _ = try client.call(RPCMethod.secretsDelete, params: try JSONValue(NameParams(name: name))) }
    public func reloadPolicy() throws { _ = try client.call(RPCMethod.policyReload) }
    public func clearApprovals() throws { _ = try client.call(RPCMethod.approvalsClear) }
    public func auditTail(_ n: Int) throws -> [AuditEvent] { try client.call(RPCMethod.auditTail, TailParams(n: n), as: [AuditEvent].self) }
    public func listDevices() throws -> [DevicePublicRecord] { try client.call(RPCMethod.devicesList, as: [DevicePublicRecord].self) }
    public func call(_ method: String, params: JSONValue) throws -> JSONValue { try client.call(method, params: params) }
}

public enum BackendFactory {
    /// Prefer the running agent; fall back to in-process if no agent socket is listening.
    ///
    /// Broker routing: if `SAFESKI_USER` is set the request goes through the root broker to that
    /// user's agent (error if the broker is not running). If no agent socket is listening but the
    /// broker is, the caller's own agent is reached through the broker (useful from contexts that
    /// cannot see the per-user runtime dir); if the broker knows no agent for us, fall back to local.
    public static func make(paths: SafeskiPaths = .default, forceLocal: Bool = false) throws -> Backend {
        let env = ProcessInfo.processInfo.environment
        let token = env["SAFESKI_TOKEN"]
        if !forceLocal {
            let brokerSock = BrokerConfig.socketPath
            if let user = env["SAFESKI_USER"], !user.isEmpty {
                guard UnixSocketClient.isListening(path: brokerSock) else {
                    throw SafeskiError.io("SAFESKI_USER is set but the broker is not listening at \(brokerSock) (see `safeski broker install`)")
                }
                let b = RemoteBackend(socketPath: brokerSock, token: token, brokerUser: user)
                try b.client.connect()
                return b
            }
            if let sock = env["SAFESKI_SOCKET"], !sock.isEmpty, UnixSocketClient.isListening(path: sock) {
                return RemoteBackend(socketPath: sock, token: token)
            }
            if UnixSocketClient.isListening(path: paths.agentSocket.path) {
                return RemoteBackend(socketPath: paths.agentSocket.path, token: token)
            }
            if UnixSocketClient.isListening(path: brokerSock) {
                let b = RemoteBackend(socketPath: brokerSock, token: token, brokerUser: "")
                do { try b.client.connect(); return b }
                catch SafeskiError.notFound { /* no agent registered for us: use the store in-process */ }
            }
        }
        return try LocalBackend(paths: paths)
    }
}
