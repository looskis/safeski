import CryptoKit
import Darwin
import Foundation
import Testing
@testable import SafeskiCore

@Suite("Framing")
struct FramingTests {
    private func makePipe() throws -> (read: Int32, write: Int32) {
        var fds: [Int32] = [-1, -1]
        try #require(pipe(&fds) == 0)
        return (fds[0], fds[1])
    }

    @Test func roundTrip() throws {
        let (r, w) = try makePipe()
        defer { close(r) }
        let payloads = [Data(), Data("hi".utf8), Data((0..<10_000).map { UInt8($0 & 0xff) })]
        for p in payloads { try Framing.writeFrame(fd: w, p) }
        for p in payloads { #expect(try Framing.readFrame(fd: r) == p) }
        close(w)
        #expect(try Framing.readFrame(fd: r) == nil)   // clean EOF
    }

    @Test func headerIsBigEndianLength() throws {
        let (r, w) = try makePipe()
        defer { close(r); close(w) }
        try Framing.writeFrame(fd: w, Data(repeating: 0xaa, count: 0x0102))
        let header = try #require(try Framing.readExact(fd: r, count: 4))
        #expect(header == Data([0, 0, 0x01, 0x02]))
    }

    @Test func oversizedFrameRejected() throws {
        let (r, w) = try makePipe()
        defer { close(r); close(w) }
        let n = UInt32(Framing.maxFrame + 1)
        try Framing.writeAll(fd: w, Data([UInt8(n >> 24), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)]))
        let e = safeskiError { _ = try Framing.readFrame(fd: r) }
        #expect(e?.code == "rpc")
        #expect(e?.message.contains("frame too large") == true)

        // exactly maxFrame is accepted by the header check (it then waits for the body)
        #expect(Framing.maxFrame == 16 * 1024 * 1024)
    }

    @Test func truncatedFrameRejected() throws {
        let (r, w) = try makePipe()
        try Framing.writeAll(fd: w, Data([0, 0, 0, 10, 1, 2, 3]))
        close(w)
        let e = safeskiError { _ = try Framing.readFrame(fd: r) }
        close(r)
        #expect(e?.code == "rpc")
        #expect(e?.message.contains("truncated") == true)
    }
}

@Suite("JSONValue")
struct JSONValueTests {
    @Test func integersRenderWithoutFraction() throws {
        #expect(JSONValue.number(3).description == "3")
        #expect(JSONValue.number(-2).description == "-2")
        #expect(JSONValue.number(0).description == "0")
        #expect(JSONValue.number(3.5).description == "3.5")
        #expect(JSONValue.number(1_000_000).description == "1000000")
        let enc = String(decoding: try JSONEncoder().encode(JSONValue.object(["uid": .number(501), "ttl": .number(0.5)])), as: UTF8.self)
        #expect(enc.contains("\"uid\":501"))
        #expect(enc.contains("\"ttl\":0.5"))
        #expect(!enc.contains("501.0"))
    }

    @Test func encodeDecodeRoundTrip() throws {
        let v: JSONValue = .object([
            "s": .string("str"), "b": .bool(true), "n": .null, "i": .number(42), "f": .number(-1.25),
            "a": .array([.number(1), .string("two"), .null, .object(["k": .bool(false)])]),
        ])
        let data = try JSONEncoder().encode(v)
        let back = try JSONDecoder().decode(JSONValue.self, from: data)
        #expect(back == v)
        #expect(v.description == #"{"a":[1,"two",null,{"k":false}],"b":true,"f":-1.25,"i":42,"n":null,"s":"str"}"#)

        let parsed = try JSONDecoder().decode(JSONValue.self, from: Data(#"{"x":[1,2,{"y":"z"}],"t":true,"nil":null}"#.utf8))
        #expect(parsed["x"]?[2]?["y"]?.stringValue == "z")
        #expect(parsed["x"]?[5] == nil)
        #expect(parsed["t"]?.boolValue == true)
        #expect(parsed["nil"]?.isNull == true)
        #expect(parsed["x"]?.arrayValue?.count == 3)
        #expect(parsed["missing"] == nil)
        #expect(parsed["t"]?["nested"] == nil)
    }

    @Test func accessors() {
        #expect(JSONValue.number(7).intValue == 7)
        #expect(JSONValue.number(7).doubleValue == 7)
        #expect(JSONValue.string("7").intValue == nil)
        #expect(JSONValue.array([.string("a"), .number(1), .string("b")]).stringArray == ["a", "b"])
        #expect(JSONValue.object(["a": .null]).objectValue?.count == 1)
        #expect(JSONValue.null.objectValue == nil)
    }

    @Test func codableBridging() throws {
        let p = SignParams(key: "k", data: Data([1, 2, 3]), digest: true, purpose: "p")
        let v = try JSONValue(p)
        #expect(v["key"]?.stringValue == "k")
        #expect(v["digest"]?.boolValue == true)
        #expect(v["data"]?.stringValue == Data([1, 2, 3]).base64EncodedString())
        let back = try v.decode(SignParams.self)
        #expect(back.key == "k" && back.data == Data([1, 2, 3]) && back.digest && back.purpose == "p")
    }
}

/// A live agent on a temp socket, torn down when `stop()` is called.
private final class LiveAgent {
    let home: TempHome
    let store: Store
    let server: AgentServer
    let device: DeviceIdentity

    init(prefix: String, policy: String? = nil) throws {
        home = try TempHome(prefix)
        store = Store(paths: home.paths)
        device = try store.initialize(name: "agent-test")
        if let policy { try home.writePolicy(policy) }
        server = try AgentServer(paths: home.paths, interactive: false)
        server.log = { _ in }
        try server.start()
    }

    var socketPath: String { home.paths.agentSocket.path }
    func client(token: String? = nil) -> RPCClient { RPCClient(socketPath: socketPath, token: token) }

    func stop() {
        server.stop()
        home.cleanup()
    }
}

@Suite("RPC over a live agent", .enclaveSerialized)
struct AgentRPCTests {
    static let allowAll = "[defaults]\napprove = \"never\"\n"

    @Test func statusAndWhoami() throws {
        let agent = try LiveAgent(prefix: "rpc-status", policy: Self.allowAll)
        defer { agent.stop() }
        #expect(agent.socketPath.utf8.count < 104)
        #expect(UnixSocketClient.isListening(path: agent.socketPath))
        let client = agent.client()

        let status = try client.call(RPCMethod.status, as: StatusResult.self)
        #expect(status.deviceID == agent.device.deviceID)
        #expect(status.deviceName == "agent-test")
        #expect(status.pid == Int(getpid()))
        #expect(status.socket == agent.socketPath)
        #expect(status.sshSocket == nil)
        #expect(status.keys == 0 && status.secrets == 0)
        #expect(status.auditHead == 1)   // agent.start
        #expect(status.version == Version.string)
        #expect(status.policyLoaded != nil)

        let me = try client.call(RPCMethod.whoami, as: CallerIdentity.self)
        #expect(me.transport == "unix")
        #expect(me.uid == getuid())
        #expect(me.pid == getpid())
        #expect(me.tokenName == nil)
        let exe = try #require(CallerIdentity.resolvePath(pid: getpid()))
        let path = try #require(me.path)
        // path is either the executable or (for a bundle) the bundle that contains it
        #expect(exe == path || exe.hasPrefix(path + "/"), "exe=\(exe) path=\(path)")
        #expect(me.commandLine?.isEmpty == false)

        // several calls on one connection
        for _ in 0..<3 { _ = try client.call(RPCMethod.status) }
        // and a second, independent connection
        _ = try agent.client().call(RPCMethod.whoami)
    }

    @Test func keysCreateSignVerify() throws {
        let agent = try LiveAgent(prefix: "rpc-keys", policy: Self.allowAll)
        defer { agent.stop() }
        let client = agent.client()

        let created = try client.call(RPCMethod.keysCreate, CreateKeyParams(name: "k", kind: .enclaveSigning, access: .none, comment: "rpc"), as: KeySummary.self)
        #expect(created.name == "k" && created.kind == .enclaveSigning && created.comment == "rpc")
        #expect(created.publicKey.count == 65)
        #expect(try client.call(RPCMethod.keysList, as: [KeySummary].self).map(\.name) == ["k"])
        #expect(try client.call(RPCMethod.keysGet, NameParams(name: "k"), as: KeySummary.self).publicKey == created.publicKey)

        let msg = Data("rpc sign".utf8)
        let sig = try client.call(RPCMethod.keysSign, SignParams(key: "k", data: msg, digest: false, purpose: "test"), as: SignResult.self).signature
        let pub = try P256.Signing.PublicKey(x963Representation: created.publicKey)
        #expect(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: sig), for: msg))

        let dsig = try client.call(RPCMethod.keysSign, SignParams(key: "k", data: Data(SHA256.hash(data: msg)), digest: true), as: SignResult.self).signature
        #expect(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: dsig), for: msg))

        // agreement through RPC
        let ea = try client.call(RPCMethod.keysCreate, CreateKeyParams(name: "ea", kind: .enclaveAgreement, access: .none, comment: nil), as: KeySummary.self)
        let peer = P256.KeyAgreement.PrivateKey()
        let r = try client.call(RPCMethod.keysAgree, params: try JSONValue(AgreeParams(key: "ea", peerPublicKey: peer.publicKey.x963Representation)))
        let sharedB64 = try #require(r["sharedSecret"]?.stringValue)
        let shared = try #require(Data(base64Encoded: sharedB64))
        let expected = try peer.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: ea.publicKey)).withUnsafeBytes { Data($0) }
        #expect(shared == expected)

        #expect(try client.call(RPCMethod.keysDelete, params: try JSONValue(NameParams(name: "ea"))) == .bool(true))
        #expect(safeskiError { _ = try client.call(RPCMethod.keysGet, NameParams(name: "ea"), as: KeySummary.self) }?.code == "not_found")

        // the audit log recorded it all
        let tail = try client.call(RPCMethod.auditTail, TailParams(n: 100), as: [AuditEvent].self)
        #expect(tail.map(\.action).contains("key.create"))
        #expect(tail.filter { $0.action == "key.sign" }.count == 2)
        #expect(tail.last?.action == "key.delete")
        #expect(tail.first { $0.action == "key.sign" }?.detail?["purpose"] == .string("test"))
        #expect(tail.first { $0.action == "key.sign" }?.caller?.transport == "unix")
    }

    @Test func secretsSetGet() throws {
        let agent = try LiveAgent(prefix: "rpc-secrets", policy: Self.allowAll)
        defer { agent.stop() }
        let client = agent.client()
        let summary = try client.call(RPCMethod.secretsSet, SetSecretParams(name: "API", value: Data("sk-123".utf8), contentType: "text"), as: SecretSummary.self)
        #expect(summary.name == "API" && summary.recipients == [agent.device.deviceID])
        let v = try client.call(RPCMethod.secretsGet, params: .object(["name": .string("API"), "purpose": .string("test")])).decode(SecretValue.self)
        #expect(v.value == Data("sk-123".utf8))
        #expect(v.contentType == "text")
        #expect(try client.call(RPCMethod.secretsList, as: [SecretSummary].self).map(\.name) == ["API"])
        #expect(try client.call(RPCMethod.secretsDelete, params: try JSONValue(NameParams(name: "API"))) == .bool(true))
        #expect(safeskiError { _ = try client.call(RPCMethod.secretsGet, params: .object(["name": .string("API")])) }?.code == "not_found")

        // RemoteBackend goes through the same path
        let backend = RemoteBackend(socketPath: agent.socketPath)
        _ = try backend.setSecret(SetSecretParams(name: "B", value: Data([1]), contentType: "binary"))
        #expect(try backend.getSecret("B", purpose: nil).value == Data([1]))
        #expect(backend.isRemote)
        #expect(try backend.whoami().transport == "unix")
    }

    @Test func unknownMethodAndBadRequests() throws {
        let agent = try LiveAgent(prefix: "rpc-unknown", policy: Self.allowAll)
        defer { agent.stop() }
        let client = agent.client()
        let e = safeskiError { _ = try client.call("no.such.method") }
        #expect(e?.code == "rpc")
        #expect(e?.message.contains("unknown method no.such.method") == true)

        // bad params decode as invalid input, the connection survives
        let bad = safeskiError { _ = try client.call(RPCMethod.keysGet, params: .object(["nope": .number(1)])) }
        #expect(bad != nil)
        _ = try client.call(RPCMethod.status)

        // a malformed frame gets an error response rather than a dropped connection
        let fd = try UnixSocketClient.connect(path: agent.socketPath)
        defer { close(fd) }
        try Framing.writeFrame(fd: fd, Data("not json".utf8))
        let resp = try JSONDecoder.safeski.decode(RPCResponse.self, from: try #require(try Framing.readFrame(fd: fd)))
        #expect(resp.error?.code == "invalid_format")
    }

    @Test func policyDenyAfterReload() throws {
        let agent = try LiveAgent(prefix: "rpc-policy", policy: Self.allowAll)
        defer { agent.stop() }
        let client = agent.client()
        _ = try client.call(RPCMethod.secretsSet, SetSecretParams(name: "S", value: Data("v".utf8), contentType: "text"), as: SecretSummary.self)
        #expect(try client.call(RPCMethod.secretsGet, params: .object(["name": .string("S")])).decode(SecretValue.self).value == Data("v".utf8))

        try agent.home.writePolicy("""
        [defaults]
        approve = "never"
        [secrets.S]
        rules = [ { uid = \(getuid()), approve = "deny" } ]
        """)
        #expect(try client.call(RPCMethod.policyReload) == .bool(true))
        let e = safeskiError { _ = try client.call(RPCMethod.secretsGet, params: .object(["name": .string("S")])) }
        #expect(e?.code == "denied")
        #expect(e?.message.contains("rule denies") == true)
        #expect(try client.call(RPCMethod.auditTail, TailParams(n: 1), as: [AuditEvent].self).first?.outcome == "deny")

        // an unmatched caller under rules is denied too; other secrets stay open
        _ = try client.call(RPCMethod.secretsSet, SetSecretParams(name: "T", value: Data("t".utf8), contentType: "text"), as: SecretSummary.self)
        #expect(try client.call(RPCMethod.secretsGet, params: .object(["name": .string("T")])).decode(SecretValue.self).value == Data("t".utf8))

        // approval required but the agent is headless -> approval_failed
        try agent.home.writePolicy("[defaults]\napprove = \"once\"\n")
        _ = try client.call(RPCMethod.policyReload)
        #expect(safeskiError { _ = try client.call(RPCMethod.secretsGet, params: .object(["name": .string("T")])) }?.code == "approval_failed")
    }

    @Test func tokenAuth() throws {
        let token = "tok-" + UUID().uuidString
        let agent = try LiveAgent(prefix: "rpc-token", policy: """
        [defaults]
        approve = "never"

        [secrets.S]
        rules = [
          { token = "t", approve = "never" },
          { uid = \(getuid()), approve = "never" },
        ]

        [secrets.OWNER_ONLY]
        rules = [ { uid = \(getuid()), approve = "never" } ]

        [tokens.t]
        hash = "\(sha256Hex(token))"
        comment = "test token"

        [tokens.expired]
        hash = "\(sha256Hex("expired-token"))"
        expires = "2000-01-01T00:00:00Z"
        """)
        defer { agent.stop() }
        let owner = agent.client()
        _ = try owner.call(RPCMethod.secretsSet, SetSecretParams(name: "S", value: Data("for-token".utf8), contentType: "text"), as: SecretSummary.self)
        _ = try owner.call(RPCMethod.secretsSet, SetSecretParams(name: "OWNER_ONLY", value: Data("mine".utf8), contentType: "text"), as: SecretSummary.self)

        let tc = agent.client(token: token)
        let me = try tc.call(RPCMethod.whoami, as: CallerIdentity.self)
        #expect(me.tokenName == "t")
        #expect(me.transport == "token")
        #expect(me.path == nil && me.teamID == nil && me.signingID == nil && me.parentPath == nil)
        #expect(me.uid == nil && me.commandLine == nil)   // relay peer credentials are not attributed to the token

        let v = try tc.call(RPCMethod.secretsGet, params: .object(["name": .string("S")])).decode(SecretValue.self)
        #expect(v.value == Data("for-token".utf8))
        let ev = try owner.call(RPCMethod.auditTail, TailParams(n: 1), as: [AuditEvent].self).first
        #expect(ev?.action == "secret.get" && ev?.caller?.tokenName == "t")

        // token callers only match token rules (a `uid` rule must not match the relay's uid), and cannot do owner-only things
        let ownerOnly = safeskiError { _ = try tc.call(RPCMethod.secretsGet, params: .object(["name": .string("OWNER_ONLY")])) }
        #expect(ownerOnly?.code == "denied")
        #expect(ownerOnly?.message.contains("no rule for token t") == true)
        #expect(safeskiError { _ = try tc.call(RPCMethod.policyReload) }?.code == "denied")
        #expect(safeskiError { _ = try tc.call(RPCMethod.approvalsClear) }?.code == "denied")
        #expect(safeskiError { _ = try tc.call(RPCMethod.auditTail, TailParams(n: 1), as: [AuditEvent].self) }?.code == "denied")
        #expect(safeskiError { _ = try tc.call(RPCMethod.keysCreate, CreateKeyParams(name: "k", kind: .enclaveSigning, access: .none, comment: nil), as: KeySummary.self) }?.code == "denied")
        #expect(safeskiError { _ = try tc.call(RPCMethod.secretsSet, SetSecretParams(name: "X", value: Data(), contentType: "text"), as: SecretSummary.self) }?.code == "denied")
        #expect(safeskiError { _ = try tc.call(RPCMethod.secretsDelete, params: try JSONValue(NameParams(name: "S"))) }?.code == "denied")

        // bad / expired tokens are rejected before dispatch
        for bad in ["wrong-token", "expired-token", ""] {
            let e = safeskiError { _ = try agent.client(token: bad).call(RPCMethod.whoami) }
            #expect(e?.code == "denied", Comment(rawValue: bad))
            #expect(e?.message.contains("invalid or expired token") == true, Comment(rawValue: bad))
        }
    }
}
