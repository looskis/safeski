import CryptoKit
import Foundation
import LocalAuthentication

/// The authorization-enforcing facade over `Store`. Every operation takes a `CallerIdentity`,
/// evaluates policy, runs approval, logs to audit, then performs the operation.
/// Used in-process by the CLI (local mode) and by the agent's RPC dispatcher.
public final class Service {
    public let store: Store
    public let approvals: ApprovalBroker
    public private(set) var policy: PolicyDocument
    public private(set) var policyLoaded: Date?
    public let audit: AuditLog
    private let lock = NSRecursiveLock()
    public let startTime = Date()
    /// Extension hook: other modules (proxy, oidc) register RPC methods here.
    public var extraMethods: [String: (JSONValue, CallerIdentity) throws -> JSONValue] = [:]
    public var statusExtras: () -> [String: JSONValue] = { [:] }

    public init(store: Store, interactive: Bool) throws {
        self.store = store
        self.approvals = ApprovalBroker(interactive: interactive)
        self.audit = try AuditLog(url: store.paths.auditLog)
        self.policy = PolicyDocument()
        try reloadPolicy()
    }

    public func reloadPolicy() throws {
        lock.lock(); defer { lock.unlock() }
        policy = try Policy.load(from: store.paths.policy)
        policyLoaded = Date()
    }

    /// Reload policy if the file changed since last load.
    public func reloadPolicyIfChanged() {
        guard let loaded = policyLoaded,
              let attrs = try? FileManager.default.attributesOfItem(atPath: store.paths.policy.path),
              let mtime = attrs[.modificationDate] as? Date, mtime > loaded else { return }
        try? reloadPolicy()
    }

    // MARK: authorization

    private func authorize(kind: String, resource: String, caller: CallerIdentity, action: String, purpose: String?,
                           detail: [String: JSONValue]? = nil) throws {
        reloadPolicyIfChanged()
        let decision = Policy.evaluate(policy, kind: kind, resource: resource, caller: caller)
        do {
            let how = try approvals.authorize(decision: decision, caller: caller, kind: kind, resource: resource, purpose: purpose)
            var d = detail ?? [:]
            d["via"] = .string(how)
            if let p = purpose { d["purpose"] = .string(p) }
            try audit.append(action: action, resource: resource, outcome: how == "allow" || how == "cached" ? "allow" : "approved", caller: caller, detail: d)
        } catch {
            var d = detail ?? [:]
            d["error"] = .string(error.localizedDescription)
            _ = try? audit.append(action: action, resource: resource, outcome: "deny", caller: caller, detail: d)
            throw error
        }
    }

    /// Resolve a bearer token to a CallerIdentity (for RPC requests carrying `token`).
    public func resolveToken(_ token: String, base: CallerIdentity) -> CallerIdentity? {
        let h = Data(SHA256.hash(data: Data(token.utf8))).hexString
        for (name, tp) in policy.tokens where tp.hash == h {
            if let e = tp.expires, e < Date() { return nil }
            // Token callers are identified by the token alone: peer identity is not trusted
            // (it may be a relay such as the broker or a container socket proxy), so drop every
            // attribute that policy rules or the approval cache could otherwise match on.
            var c = base
            c.tokenName = name
            c.transport = "token"
            c.path = nil; c.parentPath = nil; c.teamID = nil; c.signingID = nil; c.signatureValid = nil
            c.uid = nil; c.gid = nil; c.commandLine = nil
            return c
        }
        return nil
    }

    // MARK: keys

    public func listKeys(caller: CallerIdentity) throws -> [KeySummary] {
        try store.listKeys().map(\.summary)
    }

    public func getKey(_ name: String, caller: CallerIdentity) throws -> KeySummary {
        try store.loadKey(name).summary
    }

    public func createKey(_ p: CreateKeyParams, caller: CallerIdentity) throws -> KeySummary {
        lock.lock(); defer { lock.unlock() }
        guard caller.transport == "local" || (caller.uid == getuid() && caller.tokenName == nil) else {
            throw SafeskiError.denied("only the owning user may create keys")
        }
        let rec = try store.createKey(name: p.name, kind: p.kind, access: p.access, comment: p.comment)
        try audit.append(action: "key.create", resource: p.name, outcome: "allow", caller: caller,
                         detail: ["kind": .string(p.kind.rawValue), "access": .string(p.access.rawValue)])
        return rec.summary
    }

    public func deleteKey(_ name: String, caller: CallerIdentity) throws {
        lock.lock(); defer { lock.unlock() }
        guard caller.transport == "local" || (caller.uid == getuid() && caller.tokenName == nil) else {
            throw SafeskiError.denied("only the owning user may delete keys")
        }
        try store.deleteKey(name)
        try audit.append(action: "key.delete", resource: name, outcome: "allow", caller: caller)
    }

    public func sign(_ p: SignParams, caller: CallerIdentity) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        try authorize(kind: "key", resource: p.key, caller: caller, action: "key.sign", purpose: p.purpose,
                      detail: ["digest": .bool(p.digest), "bytes": .number(Double(p.data.count))])
        return try store.sign(key: p.key, data: p.data, isDigest: p.digest, context: approvals.context)
    }

    public func agree(_ p: AgreeParams, caller: CallerIdentity) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        try authorize(kind: "key", resource: p.key, caller: caller, action: "key.agree", purpose: nil)
        return try store.agree(key: p.key, peerPublicKey: p.peerPublicKey, context: approvals.context)
    }

    // MARK: secrets

    public func listSecrets(caller: CallerIdentity) throws -> [SecretSummary] {
        try store.listSecrets().map(\.summary)
    }

    public func setSecret(_ p: SetSecretParams, caller: CallerIdentity) throws -> SecretSummary {
        lock.lock(); defer { lock.unlock() }
        guard caller.transport == "local" || (caller.uid == getuid() && caller.tokenName == nil) else {
            throw SafeskiError.denied("only the owning user may write secrets")
        }
        let rec = try store.setSecret(name: p.name, value: p.value, contentType: p.contentType)
        try audit.append(action: "secret.set", resource: p.name, outcome: "allow", caller: caller)
        return rec.summary
    }

    public func getSecret(_ name: String, purpose: String?, caller: CallerIdentity) throws -> SecretValue {
        lock.lock(); defer { lock.unlock() }
        try authorize(kind: "secret", resource: name, caller: caller, action: "secret.get", purpose: purpose)
        let rec = try store.loadSecret(name)
        let value = try store.getSecret(name, context: approvals.context)
        return SecretValue(value: value, contentType: rec.contentType)
    }

    public func deleteSecret(_ name: String, caller: CallerIdentity) throws {
        lock.lock(); defer { lock.unlock() }
        guard caller.transport == "local" || (caller.uid == getuid() && caller.tokenName == nil) else {
            throw SafeskiError.denied("only the owning user may delete secrets")
        }
        try store.deleteSecret(name)
        try audit.append(action: "secret.delete", resource: name, outcome: "allow", caller: caller)
    }

    // MARK: status

    public func status(socket: String, sshSocket: String?) throws -> StatusResult {
        let dev = try store.loadDevice()
        return StatusResult(version: Version.string, deviceID: dev.deviceID, deviceName: dev.name, pid: Int(getpid()),
                            uptimeSeconds: Date().timeIntervalSince(startTime), socket: socket, sshSocket: sshSocket,
                            keys: (try? store.listKeys().count) ?? 0, secrets: (try? store.listSecrets().count) ?? 0,
                            auditHead: audit.head.seq, policyLoaded: policyLoaded, extra: statusExtras())
    }

    // MARK: RPC dispatch

    public func dispatch(_ req: RPCRequest, caller rawCaller: CallerIdentity, socket: String, sshSocket: String?) -> RPCResponse {
        var caller = rawCaller
        if let t = req.token {
            guard let resolved = resolveToken(t, base: rawCaller) else {
                return RPCResponse(id: req.id, error: RPCError(code: "denied", message: "invalid or expired token"))
            }
            caller = resolved
        }
        do {
            let result: JSONValue
            switch req.method {
            case RPCMethod.status: result = try JSONValue(try status(socket: socket, sshSocket: sshSocket))
            case RPCMethod.whoami: result = try JSONValue(caller)
            case RPCMethod.keysList: result = try JSONValue(try listKeys(caller: caller))
            case RPCMethod.keysGet: result = try JSONValue(try getKey(try req.params.decode(NameParams.self).name, caller: caller))
            case RPCMethod.keysCreate: result = try JSONValue(try createKey(try req.params.decode(CreateKeyParams.self), caller: caller))
            case RPCMethod.keysDelete: try deleteKey(try req.params.decode(NameParams.self).name, caller: caller); result = .bool(true)
            case RPCMethod.keysSign:
                let sig = try sign(try req.params.decode(SignParams.self), caller: caller)
                result = try JSONValue(SignResult(signature: sig))
            case RPCMethod.keysAgree:
                let ss = try agree(try req.params.decode(AgreeParams.self), caller: caller)
                result = .object(["sharedSecret": .string(ss.base64EncodedString())])
            case RPCMethod.secretsList: result = try JSONValue(try listSecrets(caller: caller))
            case RPCMethod.secretsSet: result = try JSONValue(try setSecret(try req.params.decode(SetSecretParams.self), caller: caller))
            case RPCMethod.secretsGet:
                let name = try req.params.decode(NameParams.self).name
                result = try JSONValue(try getSecret(name, purpose: req.params["purpose"]?.stringValue, caller: caller))
            case RPCMethod.secretsDelete: try deleteSecret(try req.params.decode(NameParams.self).name, caller: caller); result = .bool(true)
            case RPCMethod.policyReload:
                guard caller.uid == getuid(), caller.tokenName == nil else { throw SafeskiError.denied("owner only") }
                try reloadPolicy(); result = .bool(true)
            case RPCMethod.approvalsClear:
                guard caller.uid == getuid(), caller.tokenName == nil else { throw SafeskiError.denied("owner only") }
                approvals.clear(); result = .bool(true)
            case RPCMethod.auditTail:
                guard caller.uid == getuid(), caller.tokenName == nil else { throw SafeskiError.denied("owner only") }
                result = try JSONValue(try audit.tail(try req.params.decode(TailParams.self).n))
            case RPCMethod.devicesList:
                result = try JSONValue(try store.listDevices())
            default:
                guard let h = extraMethods[req.method] else { throw SafeskiError.rpc("unknown method \(req.method)") }
                result = try h(req.params, caller)
            }
            return RPCResponse(id: req.id, result: result)
        } catch {
            return RPCResponse(id: req.id, error: RPCError(error))
        }
    }
}
