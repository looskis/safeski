import CryptoKit
import Foundation
import LocalAuthentication

/// File-backed keystore + secret store + device identity. Not thread-safe by itself; the agent
/// serializes through `Service`.
public final class Store {
    public let paths: SafeskiPaths
    private let enc = JSONEncoder.safeski
    private let dec = JSONDecoder.safeski

    public init(paths: SafeskiPaths = .default) { self.paths = paths }

    public var isInitialized: Bool { FileIO.exists(paths.device) }

    // MARK: device

    public func loadDevice() throws -> DeviceIdentity {
        guard isInitialized else { throw SafeskiError.notFound("safeski is not initialized; run `safeski init`") }
        return try dec.decode(DeviceIdentity.self, from: FileIO.read(paths.device))
    }

    @discardableResult
    public func initialize(name: String? = nil, vaultAccess: AccessPolicy = .none) throws -> DeviceIdentity {
        try Enclave.requireAvailable()
        if isInitialized { throw SafeskiError.alreadyExists("device already initialized at \(paths.root.path)") }
        try paths.ensureLayout()
        let identity = try EnclaveSigningKey(create: .none)
        let vault = try EnclaveAgreementKey(create: vaultAccess)
        let id = Data(SHA256.hash(data: identity.publicKey.x963Representation)).prefix(8).hexString
        let dev = DeviceIdentity(deviceID: id, name: name ?? Host.current().localizedName ?? "mac",
                                 identityBlob: identity.blob, identityPublicKey: identity.publicKey.x963Representation,
                                 vaultBlob: vault.blob, vaultPublicKey: vault.publicKey.x963Representation,
                                 created: Date(), hardwareModel: Store.hardwareModel())
        try FileIO.writePrivate(try enc.encode(dev), to: paths.device)
        if !FileIO.exists(paths.policy) {
            try FileIO.writePrivate(Data(PolicyDocument.defaultTOML.utf8), to: paths.policy)
        }
        return dev
    }

    static func hardwareModel() -> String? {
        var size = 0
        sysctlbyname("hw.model", nil, &size, nil, 0)
        guard size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        sysctlbyname("hw.model", &buf, &size, nil, 0)
        return String(cString: buf)
    }

    public func identityKey(context: LAContext? = nil) throws -> EnclaveSigningKey {
        try EnclaveSigningKey(blob: try loadDevice().identityBlob, context: context)
    }
    public func vaultKey(context: LAContext? = nil) throws -> EnclaveAgreementKey {
        try EnclaveAgreementKey(blob: try loadDevice().vaultBlob, context: context)
    }

    // MARK: other devices

    public func listDevices() throws -> [DevicePublicRecord] {
        guard FileIO.exists(paths.devices) else { return [] }
        let files = (try? FileManager.default.contentsOfDirectory(at: paths.devices, includingPropertiesForKeys: nil)) ?? []
        return try files.filter { $0.pathExtension == "json" }.map { try dec.decode(DevicePublicRecord.self, from: FileIO.read($0)) }
            .sorted { $0.name < $1.name }
    }
    public func saveDevice(_ rec: DevicePublicRecord) throws {
        try paths.ensureLayout()
        try FileIO.writePrivate(try enc.encode(rec), to: paths.devices.appendingPathComponent("\(rec.deviceID).json"))
    }
    public func removeDevice(_ id: String) throws {
        let u = paths.devices.appendingPathComponent("\(id).json")
        guard FileIO.exists(u) else { throw SafeskiError.notFound("device \(id)") }
        try FileManager.default.removeItem(at: u)
    }

    /// All envelope recipients: this device plus every enrolled device.
    public func allRecipients() throws -> [Envelope.RecipientKey] {
        let me = try loadDevice()
        var out = [try Envelope.RecipientKey(deviceID: me.deviceID, vaultPublicKeyX963: me.vaultPublicKey)]
        for d in try listDevices() {
            out.append(try Envelope.RecipientKey(deviceID: d.deviceID, vaultPublicKeyX963: d.vaultPublicKey))
        }
        return out
    }

    // MARK: keys

    private func keyURL(_ name: String) -> URL { paths.keys.appendingPathComponent("\(name).json") }

    public func listKeys() throws -> [KeyRecord] {
        guard FileIO.exists(paths.keys) else { return [] }
        let files = (try? FileManager.default.contentsOfDirectory(at: paths.keys, includingPropertiesForKeys: nil)) ?? []
        return try files.filter { $0.pathExtension == "json" && !$0.lastPathComponent.hasPrefix(".") }
            .map { try dec.decode(KeyRecord.self, from: FileIO.read($0)) }
            .sorted { $0.name < $1.name }
    }

    public func loadKey(_ name: String) throws -> KeyRecord {
        try Names.validate(name)
        let u = keyURL(name)
        guard FileIO.exists(u) else { throw SafeskiError.notFound("key '\(name)'") }
        return try dec.decode(KeyRecord.self, from: FileIO.read(u))
    }

    public func saveKey(_ rec: KeyRecord, overwrite: Bool = false) throws {
        try Names.validate(rec.name)
        try paths.ensureLayout()
        if !overwrite, FileIO.exists(keyURL(rec.name)) { throw SafeskiError.alreadyExists("key '\(rec.name)'") }
        try FileIO.writePrivate(try enc.encode(rec), to: keyURL(rec.name))
    }

    public func deleteKey(_ name: String) throws {
        try Names.validate(name)
        guard FileIO.exists(keyURL(name)) else { throw SafeskiError.notFound("key '\(name)'") }
        try FileManager.default.removeItem(at: keyURL(name))
    }

    public func createKey(name: String, kind: KeyKind, access: AccessPolicy, comment: String? = nil,
                          labels: [String: String] = [:]) throws -> KeyRecord {
        try Names.validate(name)
        if FileIO.exists(keyURL(name)) { throw SafeskiError.alreadyExists("key '\(name)'") }
        let dev = try loadDevice()
        let rec: KeyRecord
        switch kind {
        case .enclaveSigning:
            let k = try EnclaveSigningKey(create: access)
            rec = KeyRecord(name: name, kind: kind, deviceID: dev.deviceID, access: access, blob: k.blob, envelope: nil,
                            publicKey: k.publicKey.x963Representation, labels: labels, comment: comment)
        case .enclaveAgreement:
            let k = try EnclaveAgreementKey(create: access)
            rec = KeyRecord(name: name, kind: kind, deviceID: dev.deviceID, access: access, blob: k.blob, envelope: nil,
                            publicKey: k.publicKey.x963Representation, labels: labels, comment: comment)
        case .softwareEd25519:
            let k = Curve25519.Signing.PrivateKey()
            let env = try Envelope.seal(k.rawRepresentation, aad: "key:\(name)", recipients: try allRecipients())
            rec = KeyRecord(name: name, kind: kind, deviceID: dev.deviceID, access: access, blob: nil, envelope: env,
                            publicKey: k.publicKey.rawRepresentation, labels: labels, comment: comment)
        case .softwareX25519:
            let k = Curve25519.KeyAgreement.PrivateKey()
            let env = try Envelope.seal(k.rawRepresentation, aad: "key:\(name)", recipients: try allRecipients())
            rec = KeyRecord(name: name, kind: kind, deviceID: dev.deviceID, access: access, blob: nil, envelope: env,
                            publicKey: k.publicKey.rawRepresentation, labels: labels, comment: comment)
        }
        try saveKey(rec)
        return rec
    }

    /// Sign with a named key. `digest` = true means `data` is a 32-byte SHA-256 digest.
    /// Returns raw signature: r||s for P-256 (64 bytes), 64-byte Ed25519 signature for Ed25519.
    public func sign(key name: String, data: Data, isDigest: Bool, context: LAContext? = nil) throws -> Data {
        let rec = try loadKey(name)
        switch rec.kind {
        case .enclaveSigning:
            guard let blob = rec.blob else { throw SafeskiError.invalidFormat("key '\(name)' has no blob") }
            let k = try EnclaveSigningKey(blob: blob, context: context)
            return isDigest ? try k.sign(digest: data) : try k.sign(data)
        case .softwareEd25519:
            guard let env = rec.envelope else { throw SafeskiError.invalidFormat("key '\(name)' has no envelope") }
            if isDigest { throw SafeskiError.unsupported("Ed25519 signs the message, not a digest") }
            let dev = try loadDevice()
            let raw = try Envelope.open(env, deviceID: dev.deviceID, vaultKey: try vaultKey(context: context))
            let k = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
            return try k.signature(for: data)
        default:
            throw SafeskiError.unsupported("key '\(name)' (\(rec.kind.rawValue)) cannot sign")
        }
    }

    /// ECDH with a named agreement key. Returns the raw shared secret bytes.
    public func agree(key name: String, peerPublicKey: Data, context: LAContext? = nil) throws -> Data {
        let rec = try loadKey(name)
        switch rec.kind {
        case .enclaveAgreement:
            guard let blob = rec.blob else { throw SafeskiError.invalidFormat("key '\(name)' has no blob") }
            let k = try EnclaveAgreementKey(blob: blob, context: context)
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            return try k.sharedSecret(with: peer).withUnsafeBytes { Data($0) }
        case .softwareX25519:
            guard let env = rec.envelope else { throw SafeskiError.invalidFormat("key '\(name)' has no envelope") }
            let dev = try loadDevice()
            let raw = try Envelope.open(env, deviceID: dev.deviceID, vaultKey: try vaultKey(context: context))
            let k = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            return try k.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        default:
            throw SafeskiError.unsupported("key '\(name)' (\(rec.kind.rawValue)) cannot do key agreement")
        }
    }

    // MARK: secrets

    private func secretURL(_ name: String) -> URL { paths.secrets.appendingPathComponent("\(name).json") }

    public func listSecrets() throws -> [SecretRecord] {
        guard FileIO.exists(paths.secrets) else { return [] }
        let files = (try? FileManager.default.contentsOfDirectory(at: paths.secrets, includingPropertiesForKeys: nil)) ?? []
        return try files.filter { $0.pathExtension == "json" && !$0.lastPathComponent.hasPrefix(".") }
            .map { try dec.decode(SecretRecord.self, from: FileIO.read($0)) }
            .sorted { $0.name < $1.name }
    }

    public func loadSecret(_ name: String) throws -> SecretRecord {
        try Names.validate(name)
        let u = secretURL(name)
        guard FileIO.exists(u) else { throw SafeskiError.notFound("secret '\(name)'") }
        return try dec.decode(SecretRecord.self, from: FileIO.read(u))
    }

    public func setSecret(name: String, value: Data, contentType: String = "text", labels: [String: String]? = nil) throws -> SecretRecord {
        try Names.validate(name)
        try paths.ensureLayout()
        let env = try Envelope.seal(value, aad: "secret:\(name)", recipients: try allRecipients())
        var rec: SecretRecord
        if let existing = try? loadSecret(name) {
            rec = existing
            rec.envelope = env; rec.updated = Date(); rec.contentType = contentType
            if let labels { rec.labels = labels }
        } else {
            rec = SecretRecord(name: name, envelope: env, created: Date(), updated: Date(), labels: labels ?? [:], contentType: contentType)
        }
        try FileIO.writePrivate(try enc.encode(rec), to: secretURL(name))
        return rec
    }

    public func getSecret(_ name: String, context: LAContext? = nil) throws -> Data {
        let rec = try loadSecret(name)
        let dev = try loadDevice()
        return try Envelope.open(rec.envelope, deviceID: dev.deviceID, vaultKey: try vaultKey(context: context))
    }

    public func deleteSecret(_ name: String) throws {
        try Names.validate(name)
        guard FileIO.exists(secretURL(name)) else { throw SafeskiError.notFound("secret '\(name)'") }
        try FileManager.default.removeItem(at: secretURL(name))
    }

    /// Re-wrap every secret and software key so that all current recipients can open them.
    /// Call after enrolling a new device.
    public func reshareAll(context: LAContext? = nil) throws -> Int {
        let dev = try loadDevice()
        let vault = try vaultKey(context: context)
        let recipients = try allRecipients()
        var n = 0
        for var s in try listSecrets() {
            let dek = try Envelope.unwrapDEK(s.envelope, deviceID: dev.deviceID, vaultKey: vault)
            let updated = try Envelope.addRecipients(s.envelope, dek: dek, recipients: recipients)
            if updated != s.envelope { s.envelope = updated; s.updated = Date(); try FileIO.writePrivate(try enc.encode(s), to: secretURL(s.name)); n += 1 }
        }
        for var k in try listKeys() where k.envelope != nil {
            let dek = try Envelope.unwrapDEK(k.envelope!, deviceID: dev.deviceID, vaultKey: vault)
            let updated = try Envelope.addRecipients(k.envelope!, dek: dek, recipients: recipients)
            if updated != k.envelope { k.envelope = updated; try saveKey(k, overwrite: true); n += 1 }
        }
        return n
    }
}
