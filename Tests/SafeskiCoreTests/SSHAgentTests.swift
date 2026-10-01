import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

// MARK: - protocol round trips

@Test func sshAgentRequestRoundTrips() throws {
    let cases: [SSHAgentRequest] = [
        .requestIdentities,
        .signRequest(keyBlob: Data([1, 2, 3]), data: Data("hello".utf8), flags: 0x02),
        .lock, .unlock,
        .extensionRequest(name: "query"),
        .unsupported(type: SSHAgentMessage.addIdentity),
        .unsupported(type: SSHAgentMessage.removeAllIdentities),
    ]
    for c in cases {
        let encoded = SSHAgentProtocol.encodeRequest(c)
        #expect(try SSHAgentProtocol.parseRequest(encoded) == c)
    }
}

@Test func sshAgentRepliesRoundTrip() throws {
    let ids = [SSHIdentity(blob: Data([0, 0, 0, 3, 0x61, 0x62, 0x63]), comment: "one"),
               SSHIdentity(blob: Data([0, 0, 0, 1, 0x7a]), comment: "safeski:two")]
    let answer = SSHAgentProtocol.identitiesAnswer(ids)
    #expect(answer.first == SSHAgentMessage.identitiesAnswer)
    #expect(try SSHAgentProtocol.parseIdentitiesAnswer(answer) == ids)
    #expect(try SSHAgentProtocol.parseIdentitiesAnswer(SSHAgentProtocol.identitiesAnswer([])) == [])

    let sig = Data(repeating: 0xab, count: 70)
    let resp = SSHAgentProtocol.signResponse(sig)
    #expect(resp.first == SSHAgentMessage.signResponse)
    #expect(try SSHAgentProtocol.parseSignResponse(resp) == sig)

    #expect(SSHAgentProtocol.isFailure(SSHAgentProtocol.failureReply))
    #expect(!SSHAgentProtocol.isFailure(SSHAgentProtocol.successReply))
}

@Test func sshAgentMalformedFramesThrow() {
    #expect(throws: (any Error).self) { try SSHAgentProtocol.parseRequest(Data()) }
    // sign request with truncated body
    #expect(throws: (any Error).self) { try SSHAgentProtocol.parseRequest(Data([SSHAgentMessage.signRequest, 0, 0, 0, 9, 1])) }
    // length claims more than present
    #expect(throws: (any Error).self) { try SSHAgentProtocol.parseRequest(Data([SSHAgentMessage.extension, 0xff, 0xff, 0xff, 0xff])) }
}

@Test func ecdsaSignatureBlobRoundTrip() throws {
    let key = P256.Signing.PrivateKey()
    let raw = try key.signature(for: Data("msg".utf8)).rawRepresentation
    let blob = try ECDSAFormat.rawToSSH(raw)
    let (type, _) = try SSHAgentProtocol.splitSignatureBlob(blob)
    #expect(type == "ecdsa-sha2-nistp256")
    #expect(try SSHAgentProtocol.ecdsaRawFromSSH(blob) == raw)
    // high-bit r/s get a leading zero on the wire and must come back as fixed 32-byte halves
    let hi = Data(repeating: 0xff, count: 64)
    #expect(try SSHAgentProtocol.ecdsaRawFromSSH(try ECDSAFormat.rawToSSH(hi)) == hi)
    let lo = Data(repeating: 0, count: 31) + Data([7]) + Data(repeating: 0, count: 31) + Data([9])
    #expect(try SSHAgentProtocol.ecdsaRawFromSSH(try ECDSAFormat.rawToSSH(lo)) == lo)
}

@Test func ed25519SignatureBlob() throws {
    let sig = Data(repeating: 0x5a, count: 64)
    let blob = try SSHAgentProtocol.ed25519SignatureBlob(sig)
    let (type, s) = try SSHAgentProtocol.splitSignatureBlob(blob)
    #expect(type == "ssh-ed25519")
    #expect(s == sig)
    #expect(throws: (any Error).self) { try SSHAgentProtocol.ed25519SignatureBlob(Data(repeating: 1, count: 63)) }
}

@Test func sshKeyIdentityMapping() throws {
    let p256 = P256.Signing.PrivateKey().publicKey
    let ed = Curve25519.Signing.PrivateKey().publicKey
    func summary(_ name: String, _ kind: KeyKind, _ pk: Data, labels: [String: String] = [:], comment: String? = nil) -> KeySummary {
        KeySummary(name: name, kind: kind, deviceID: "dev", access: .none, publicKey: pk, created: Date(), labels: labels, comment: comment)
    }
    let a = try #require(SSHKeys.identity(for: summary("a", .enclaveSigning, p256.x963Representation)))
    #expect(a.type == "ecdsa-sha2-nistp256")
    #expect(a.comment == "safeski:a")
    #expect(a.blob == p256.sshBlob)
    #expect(a.authorizedKeyLine == p256.sshAuthorizedKey(comment: "safeski:a"))
    #expect(a.fingerprint == p256.sshFingerprint)

    let b = try #require(SSHKeys.identity(for: summary("b", .softwareEd25519, ed.rawRepresentation, comment: "me@host")))
    #expect(b.type == "ssh-ed25519")
    #expect(b.comment == "me@host")
    #expect(b.authorizedKeyLine.hasPrefix("ssh-ed25519 "))

    #expect(SSHKeys.identity(for: summary("c", .enclaveSigning, p256.x963Representation, labels: ["ssh": "false"])) == nil)
    #expect(SSHKeys.identity(for: summary("d", .enclaveAgreement, p256.x963Representation)) == nil)
    #expect(SSHKeys.identity(for: summary("e", .softwareX25519, ed.rawRepresentation)) == nil)
}

// MARK: - end to end against a real Service and socket

/// Temp home + short runtime dir for one test. Removed on deinit.
final class TempHome {
    let paths: SafeskiPaths
    let socket: String
    init() throws {
        let tag = String(UUID().uuidString.prefix(8))
        let root = URL(fileURLWithPath: "/tmp/ssk-t-\(tag)")
        paths = SafeskiPaths(root: root)
        socket = "/tmp/ssk-t-\(tag).sock"
        try paths.ensureLayout()
    }
    deinit {
        try? FileManager.default.removeItem(at: paths.root)
        unlink(socket)
    }
}

/// Minimal raw-protocol ssh-agent client.
struct RawAgentClient {
    let fd: Int32
    init(path: String) throws { fd = try UnixSocketClient.connect(path: path) }
    func close() { Darwin.close(fd) }
    func roundTrip(_ req: Data) throws -> Data {
        try Framing.writeFrame(fd: fd, req)
        guard let reply = try Framing.readFrame(fd: fd) else { throw SafeskiError.rpc("agent closed connection") }
        return reply
    }
    func call(_ req: SSHAgentRequest) throws -> Data { try roundTrip(SSHAgentProtocol.encodeRequest(req)) }
}

@Test func sshAgentEndToEnd() throws {
    guard Enclave.isAvailable else {
        Issue.record("Secure Enclave not available in this process; skipping end-to-end test")
        return
    }
    let home = try TempHome()
    let store = Store(paths: home.paths)
    try store.initialize(name: "test")
    // Silent policy: no prompts in tests.
    try FileIO.writePrivate(Data("[defaults]\napprove = \"never\"\n".utf8), to: home.paths.policy)

    let service = try Service(store: store, interactive: false)
    let local = CallerIdentity.local()
    let ec = try service.createKey(CreateKeyParams(name: "ec", kind: .enclaveSigning, access: .none, comment: nil), caller: local)
    let ed = try service.createKey(CreateKeyParams(name: "ed", kind: .softwareEd25519, access: .none, comment: "ed@test"), caller: local)
    _ = try service.createKey(CreateKeyParams(name: "hidden", kind: .enclaveSigning, access: .none, comment: nil), caller: local)
    var hidden = try store.loadKey("hidden"); hidden.labels["ssh"] = "false"; try store.saveKey(hidden, overwrite: true)
    _ = try service.createKey(CreateKeyParams(name: "agree", kind: .enclaveAgreement, access: .none, comment: nil), caller: local)

    let server = SSHAgentServer(service: service, path: home.socket)
    try server.start()
    defer { server.stop() }

    let client = try RawAgentClient(path: home.socket)
    defer { client.close() }

    // identities: ec + ed, not the hidden or agreement keys
    let ids = try SSHAgentProtocol.parseIdentitiesAnswer(try client.call(.requestIdentities))
    #expect(ids.count == 2)
    let ecPub = try P256.Signing.PublicKey(x963Representation: ec.publicKey)
    let edPub = try Curve25519.Signing.PublicKey(rawRepresentation: ed.publicKey)
    let ecID = try #require(ids.first { $0.type == "ecdsa-sha2-nistp256" })
    let edID = try #require(ids.first { $0.type == "ssh-ed25519" })
    #expect(ecID.blob == ecPub.sshBlob)
    #expect(ecID.comment == "safeski:ec")
    #expect(edID.comment == "ed@test")

    // ECDSA sign -> verifies with CryptoKit over the original data (SHA-256 applied by the signer)
    let msg = Data("sign me with the enclave".utf8)
    let ecResp = try client.call(.signRequest(keyBlob: ecID.blob, data: msg, flags: 0))
    #expect(!SSHAgentProtocol.isFailure(ecResp))
    let ecRaw = try SSHAgentProtocol.ecdsaRawFromSSH(try SSHAgentProtocol.parseSignResponse(ecResp))
    #expect(ecPub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: ecRaw), for: msg))

    // Ed25519 sign
    let edResp = try client.call(.signRequest(keyBlob: edID.blob, data: msg, flags: 0))
    #expect(!SSHAgentProtocol.isFailure(edResp))
    let (edType, edSig) = try SSHAgentProtocol.splitSignatureBlob(try SSHAgentProtocol.parseSignResponse(edResp))
    #expect(edType == "ssh-ed25519")
    #expect(edPub.isValidSignature(edSig, for: msg))

    // unknown key, unsupported ops, and garbage all get FAILURE and keep the connection alive
    #expect(SSHAgentProtocol.isFailure(try client.call(.signRequest(keyBlob: Data([1, 2, 3]), data: msg, flags: 0))))
    #expect(SSHAgentProtocol.isFailure(try client.call(.unsupported(type: SSHAgentMessage.addIdentity))))
    #expect(SSHAgentProtocol.isFailure(try client.call(.lock)))
    #expect(SSHAgentProtocol.isFailure(try client.call(.extensionRequest(name: "query"))))
    #expect(SSHAgentProtocol.isFailure(try client.roundTrip(Data([SSHAgentMessage.signRequest, 0, 0, 0, 200]))))
    #expect(SSHAgentProtocol.isFailure(try client.roundTrip(Data())))
    // still serving after the malformed frames
    #expect(try SSHAgentProtocol.parseIdentitiesAnswer(try client.call(.requestIdentities)).count == 2)

    // audit shows the signs under purpose "ssh"
    let signs = try service.audit.tail(50).filter { $0.action == "key.sign" }
    #expect(signs.map(\.resource).contains("ec"))
    #expect(signs.map(\.resource).contains("ed"))
    #expect(signs.allSatisfy { $0.detail?["purpose"]?.stringValue == "ssh" })
}
