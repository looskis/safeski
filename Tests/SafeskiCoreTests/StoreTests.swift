import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

@Suite("Store", .requiresEnclave, .enclaveSerialized)
struct StoreTests {
    private func initializedStore(_ prefix: String = "store") throws -> (TempHome, Store) {
        let home = try TempHome(prefix)
        let store = Store(paths: home.paths)
        try store.initialize(name: "test-device")
        return (home, store)
    }

    @Test func initializeCreatesLayout() throws {
        let home = try TempHome("init")
        defer { home.cleanup() }
        let store = Store(paths: home.paths)
        #expect(!store.isInitialized)
        #expect(safeskiError { _ = try store.loadDevice() }?.code == "not_found")

        let dev = try store.initialize(name: "my-mac")
        #expect(store.isInitialized)
        #expect(dev.name == "my-mac")
        #expect(dev.deviceID.count == 16)
        #expect(Data(hexString: dev.deviceID) != nil)
        #expect(dev.identityPublicKey.count == 65 && dev.vaultPublicKey.count == 65)
        #expect(dev.deviceID == Data(SHA256.hash(data: dev.identityPublicKey)).prefix(8).hexString)
        let loaded = try store.loadDevice()
        #expect(loaded.deviceID == dev.deviceID && loaded.name == dev.name)
        #expect(loaded.identityBlob == dev.identityBlob && loaded.vaultBlob == dev.vaultBlob)
        #expect(loaded.identityPublicKey == dev.identityPublicKey && loaded.vaultPublicKey == dev.vaultPublicKey)
        #expect(abs(loaded.created.timeIntervalSince(dev.created)) < 1)

        let p = home.paths
        for dir in [p.keys, p.secrets, p.devices, p.auditDir, p.logs, p.sessions, p.runtime, p.tls] {
            var isDir: ObjCBool = false
            #expect(FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir) && isDir.boolValue, "\(dir.lastPathComponent)")
            #expect(try posixMode(dir) == 0o700, "\(dir.lastPathComponent)")
        }
        #expect(try posixMode(p.root) == 0o700)
        #expect(try posixMode(p.device) == 0o600)
        #expect(try posixMode(p.policy) == 0o600)
        #expect(String(decoding: try FileIO.read(p.policy), as: UTF8.self) == PolicyDocument.defaultTOML)

        // keys are usable from their blobs
        _ = try store.identityKey()
        _ = try store.vaultKey()
        #expect(try store.identityKey().publicKey.x963Representation == dev.identityPublicKey)
        #expect(try store.vaultKey().publicKey.x963Representation == dev.vaultPublicKey)
    }

    @Test func initializeDoesNotClobberExistingPolicy() throws {
        let home = try TempHome("initpol")
        defer { home.cleanup() }
        try home.writePolicy("[defaults]\napprove = \"never\"\n")
        try Store(paths: home.paths).initialize()
        #expect(String(decoding: try FileIO.read(home.paths.policy), as: UTF8.self) == "[defaults]\napprove = \"never\"\n")
    }

    @Test func doubleInitThrowsAlreadyExists() throws {
        let (home, store) = try initializedStore("dbl")
        defer { home.cleanup() }
        let e = safeskiError { _ = try store.initialize() }
        #expect(e?.code == "already_exists")
    }

    @Test func createKeyAllKinds() throws {
        let (home, store) = try initializedStore("keys")
        defer { home.cleanup() }
        let dev = try store.loadDevice()
        #expect(try store.listKeys().isEmpty)

        let es = try store.createKey(name: "es", kind: .enclaveSigning, access: .none, comment: "c", labels: ["a": "b"])
        #expect(es.kind == .enclaveSigning && es.blob != nil && es.envelope == nil && es.publicKey.count == 65)
        #expect(es.deviceID == dev.deviceID && es.comment == "c" && es.labels == ["a": "b"] && es.access == .none)

        let ea = try store.createKey(name: "ea", kind: .enclaveAgreement, access: .none)
        #expect(ea.kind == .enclaveAgreement && ea.blob != nil && ea.envelope == nil && ea.publicKey.count == 65)

        let ed = try store.createKey(name: "ed", kind: .softwareEd25519, access: .none)
        #expect(ed.kind == .softwareEd25519 && ed.blob == nil && ed.publicKey.count == 32)
        #expect(ed.envelope?.aad == "key:ed")
        #expect(ed.envelope?.recipients.map(\.deviceID) == [dev.deviceID])

        let x = try store.createKey(name: "x", kind: .softwareX25519, access: .none)
        #expect(x.kind == .softwareX25519 && x.blob == nil && x.publicKey.count == 32)
        #expect(x.envelope?.aad == "key:x")

        #expect(try store.listKeys().map(\.name) == ["ea", "ed", "es", "x"])
        let esLoaded = try store.loadKey("es")
        #expect(esLoaded.name == es.name && esLoaded.kind == es.kind && esLoaded.blob == es.blob && esLoaded.publicKey == es.publicKey)
        #expect(esLoaded.labels == es.labels && esLoaded.comment == es.comment)
        #expect(try posixMode(home.paths.keys.appendingPathComponent("es.json")) == 0o600)

        #expect(safeskiError { _ = try store.createKey(name: "es", kind: .enclaveSigning, access: .none) }?.code == "already_exists")
        #expect(safeskiError { _ = try store.loadKey("nope") }?.code == "not_found")
        #expect(safeskiError { _ = try store.createKey(name: "bad name", kind: .enclaveSigning, access: .none) }?.code == "invalid_format")

        try store.deleteKey("x")
        #expect(try store.listKeys().map(\.name) == ["ea", "ed", "es"])
        #expect(safeskiError { try store.deleteKey("x") }?.code == "not_found")
    }

    @Test func enclaveSignDataAndDigest() throws {
        let (home, store) = try initializedStore("sign")
        defer { home.cleanup() }
        let rec = try store.createKey(name: "k", kind: .enclaveSigning, access: .none)
        let pub = try P256.Signing.PublicKey(x963Representation: rec.publicKey)
        let message = Data("sign me".utf8)

        let raw = try store.sign(key: "k", data: message, isDigest: false)
        #expect(raw.count == 64)
        #expect(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: message))
        #expect(!pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: Data("other".utf8)))

        let digest = Data(SHA256.hash(data: message))
        let rawD = try store.sign(key: "k", data: digest, isDigest: true)
        #expect(rawD.count == 64)
        // signing the pre-hashed digest yields a signature over the original message
        #expect(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: rawD), for: message))
        #expect(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: rawD), for: SHA256.hash(data: message)))

        #expect(safeskiError { _ = try store.sign(key: "k", data: Data([1, 2, 3]), isDigest: true) }?.code == "invalid_format")
        #expect(safeskiError { _ = try store.sign(key: "missing", data: message, isDigest: false) }?.code == "not_found")
    }

    @Test func ed25519SignVerify() throws {
        let (home, store) = try initializedStore("ed")
        defer { home.cleanup() }
        let rec = try store.createKey(name: "ed", kind: .softwareEd25519, access: .none)
        let pub = try Curve25519.Signing.PublicKey(rawRepresentation: rec.publicKey)
        let message = Data("ed25519 message".utf8)
        let sig = try store.sign(key: "ed", data: message, isDigest: false)
        #expect(sig.count == 64)
        #expect(pub.isValidSignature(sig, for: message))
        #expect(!pub.isValidSignature(sig, for: Data("tampered".utf8)))
        #expect(safeskiError { _ = try store.sign(key: "ed", data: Data(SHA256.hash(data: message)), isDigest: true) }?.code == "unsupported")
    }

    @Test func nonSigningKindsCannotSign() throws {
        let (home, store) = try initializedStore("nosign")
        defer { home.cleanup() }
        _ = try store.createKey(name: "ea", kind: .enclaveAgreement, access: .none)
        _ = try store.createKey(name: "x", kind: .softwareX25519, access: .none)
        #expect(safeskiError { _ = try store.sign(key: "ea", data: Data([1]), isDigest: false) }?.code == "unsupported")
        #expect(safeskiError { _ = try store.sign(key: "x", data: Data([1]), isDigest: false) }?.code == "unsupported")
        _ = try store.createKey(name: "es", kind: .enclaveSigning, access: .none)
        #expect(safeskiError { _ = try store.agree(key: "es", peerPublicKey: Data()) }?.code == "unsupported")
    }

    @Test func enclaveAgreementMatchesCryptoKit() throws {
        let (home, store) = try initializedStore("ecdh")
        defer { home.cleanup() }
        let rec = try store.createKey(name: "ea", kind: .enclaveAgreement, access: .none)
        let peer = P256.KeyAgreement.PrivateKey()
        let shared = try store.agree(key: "ea", peerPublicKey: peer.publicKey.x963Representation)
        let expected = try peer.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: rec.publicKey))
            .withUnsafeBytes { Data($0) }
        #expect(shared.count == 32)
        #expect(shared == expected)
        #expect((try? store.agree(key: "ea", peerPublicKey: Data([1, 2, 3]))) == nil)
    }

    @Test func x25519AgreementMatchesCryptoKit() throws {
        let (home, store) = try initializedStore("x25519")
        defer { home.cleanup() }
        let rec = try store.createKey(name: "x", kind: .softwareX25519, access: .none)
        let peer = Curve25519.KeyAgreement.PrivateKey()
        let shared = try store.agree(key: "x", peerPublicKey: peer.publicKey.rawRepresentation)
        let expected = try peer.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: rec.publicKey))
            .withUnsafeBytes { Data($0) }
        #expect(shared.count == 32)
        #expect(shared == expected)
    }

    @Test func secretsLifecycle() throws {
        let (home, store) = try initializedStore("sec")
        defer { home.cleanup() }
        let dev = try store.loadDevice()
        #expect(try store.listSecrets().isEmpty)
        #expect(safeskiError { _ = try store.getSecret("nope") }?.code == "not_found")

        let a = try store.setSecret(name: "A", value: Data("alpha".utf8), labels: ["env": "dev"])
        #expect(a.name == "A" && a.contentType == "text" && a.labels == ["env": "dev"])
        #expect(a.envelope.aad == "secret:A")
        #expect(a.envelope.recipients.map(\.deviceID) == [dev.deviceID])
        #expect(a.summary.recipients == [dev.deviceID])
        _ = try store.setSecret(name: "b", value: Data([0, 1, 2, 255]), contentType: "binary")
        #expect(try store.getSecret("A") == Data("alpha".utf8))
        #expect(try store.getSecret("b") == Data([0, 1, 2, 255]))
        #expect(try store.listSecrets().map(\.name) == ["A", "b"])
        #expect(try posixMode(home.paths.secrets.appendingPathComponent("A.json")) == 0o600)

        // overwrite keeps created, bumps updated, preserves labels when nil
        let a2 = try store.setSecret(name: "A", value: Data("alpha2".utf8), contentType: "env")
        #expect(abs(a2.created.timeIntervalSince(a.created)) < 1)
        #expect(a2.updated >= a.updated)
        #expect(a2.labels == ["env": "dev"])
        #expect(a2.contentType == "env")
        #expect(try store.getSecret("A") == Data("alpha2".utf8))
        #expect(try store.loadSecret("A").contentType == "env")

        try store.deleteSecret("A")
        #expect(try store.listSecrets().map(\.name) == ["b"])
        #expect(safeskiError { try store.deleteSecret("A") }?.code == "not_found")
        #expect(safeskiError { _ = try store.setSecret(name: "../etc", value: Data()) }?.code == "invalid_format")
    }

    @Test func namesValidate() {
        for ok in ["a", "A-b_c.1", "ANTHROPIC_API_KEY", "github-ssh", String(repeating: "x", count: 64)] {
            #expect(safeskiError { try Names.validate(ok) } == nil, "\(ok)")
        }
        for bad in ["", ".hidden", "a/b", "a b", "a:b", "é", "a\n", "..", String(repeating: "x", count: 65)] {
            #expect(safeskiError { try Names.validate(bad) }?.code == "invalid_format", "\(bad.debugDescription)")
        }
    }

    @Test func reshareAllToSecondDevice() throws {
        let (home, store) = try initializedStore("reshare")
        defer { home.cleanup() }
        let me = try store.loadDevice()

        // material created before the second device exists
        _ = try store.setSecret(name: "s", value: Data("shared secret".utf8))
        let ed = try store.createKey(name: "ed", kind: .softwareEd25519, access: .none)
        _ = try store.createKey(name: "es", kind: .enclaveSigning, access: .none)   // no envelope; untouched by reshare
        #expect(try store.loadSecret("s").envelope.recipients.count == 1)

        // a "second device" whose vault private key we hold in software
        let otherVault = P256.KeyAgreement.PrivateKey()
        let other = DevicePublicRecord(deviceID: "fake0000deadbeef", name: "other-mac",
                                       identityPublicKey: P256.Signing.PrivateKey().publicKey.x963Representation,
                                       vaultPublicKey: otherVault.publicKey.x963Representation,
                                       created: Date(), hardwareModel: "Test1,1")
        try store.saveDevice(other)
        #expect(try store.listDevices().map(\.deviceID) == [other.deviceID])
        #expect(try store.allRecipients().map(\.deviceID) == [me.deviceID, other.deviceID])

        let n = try store.reshareAll()
        #expect(n == 2)   // one secret + one software key
        #expect(try store.reshareAll() == 0)

        let s = try store.loadSecret("s")
        #expect(s.envelope.recipients.map(\.deviceID) == [me.deviceID, other.deviceID])
        #expect(try store.loadKey("ed").envelope?.recipients.count == 2)
        #expect(try store.loadKey("ed").publicKey == ed.publicKey)
        #expect(try store.loadKey("es").envelope == nil)
        // this device still opens everything
        #expect(try store.getSecret("s") == Data("shared secret".utf8))

        // the other device can unwrap the DEK with plain ECDH + HKDF (reimplemented here)
        let rec = try #require(s.envelope.recipients.first { $0.deviceID == other.deviceID })
        let eph = try P256.KeyAgreement.PublicKey(x963Representation: rec.ephemeralPublicKey)
        let shared = try otherVault.sharedSecretFromKeyAgreement(with: eph)
        let wk = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: rec.ephemeralPublicKey,
                                                sharedInfo: Data(("safeski-envelope-v1:" + other.deviceID).utf8), outputByteCount: 32)
        let dek = try AES.GCM.open(try AES.GCM.SealedBox(combined: rec.wrappedDEK), using: wk, authenticating: Data(other.deviceID.utf8))
        #expect(dek.count == 32)
        #expect(try Envelope.open(s.envelope, dek: SymmetricKey(data: dek)) == Data("shared secret".utf8))

        // and the same for the resharded software key
        let kenv = try #require(try store.loadKey("ed").envelope)
        let krec = try #require(kenv.recipients.first { $0.deviceID == other.deviceID })
        let kshared = try otherVault.sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(x963Representation: krec.ephemeralPublicKey))
        let kwk = kshared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: krec.ephemeralPublicKey,
                                                  sharedInfo: Data(("safeski-envelope-v1:" + other.deviceID).utf8), outputByteCount: 32)
        let kdek = try AES.GCM.open(try AES.GCM.SealedBox(combined: krec.wrappedDEK), using: kwk, authenticating: Data(other.deviceID.utf8))
        let priv = try Curve25519.Signing.PrivateKey(rawRepresentation: try Envelope.open(kenv, dek: SymmetricKey(data: kdek)))
        #expect(priv.publicKey.rawRepresentation == ed.publicKey)

        // new secrets are sealed to both devices directly
        let t = try store.setSecret(name: "t", value: Data("new".utf8))
        #expect(t.envelope.recipients.map(\.deviceID) == [me.deviceID, other.deviceID])

        try store.removeDevice(other.deviceID)
        #expect(try store.listDevices().isEmpty)
        #expect(safeskiError { try store.removeDevice(other.deviceID) }?.code == "not_found")
    }
}
