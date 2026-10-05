import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Access-control policy enforced by the Secure Enclave for a key.
public enum AccessPolicy: String, Codable, CaseIterable {
    case none
    case userPresence = "user-presence"
    case biometryAny = "biometry-any"
    case biometryCurrentSet = "biometry-current-set"
    case devicePasscode = "device-passcode"

    public var requiresInteraction: Bool { self != .none }

    func secAccessControl() throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        switch self {
        case .none: break
        case .userPresence: flags.insert(.userPresence)
        case .biometryAny: flags.insert(.biometryAny)
        case .biometryCurrentSet: flags.insert(.biometryCurrentSet)
        case .devicePasscode: flags.insert(.devicePasscode)
        }
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err) else {
            throw SafeskiError.io("SecAccessControlCreateWithFlags: \(err?.takeRetainedValue().localizedDescription ?? "unknown")")
        }
        return ac
    }
}

public enum Enclave {
    /// True when this process can use the Secure Enclave. Setting `SAFESKI_DISABLE_ENCLAVE=1` forces
    /// false, which is how the test suite reproduces machines without one (CI VMs). It can only
    /// make safeski refuse to work; it never substitutes software keys.
    public static var isAvailable: Bool {
        if let v = getenv("SAFESKI_DISABLE_ENCLAVE"), String(cString: v) == "1" { return false }
        return SecureEnclave.isAvailable
    }

    public static func requireAvailable() throws {
        guard isAvailable else { throw SafeskiError.enclaveUnavailable }
    }

    /// Shared LAContext so that biometric approvals can be reused across operations within the
    /// allowable reuse window (max 300s on macOS).
    public static func makeContext(reason: String, reuseSeconds: TimeInterval = 0) -> LAContext {
        let ctx = LAContext()
        ctx.localizedReason = reason
        if reuseSeconds > 0 {
            ctx.touchIDAuthenticationAllowableReuseDuration = min(reuseSeconds, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        }
        return ctx
    }
}

/// A 32-byte digest supplied by the caller (already hashed). Lets us sign pre-hashed input
/// (PKCS#11 CKM_ECDSA, SSH, JWT) through CryptoKit's generic `signature(for: Digest)`.
public struct PrehashedSHA256Digest: Digest {
    public static var byteCount: Int { 32 }
    private let bytes: [UInt8]

    public init(_ data: Data) throws {
        guard data.count == 32 else { throw SafeskiError.invalidFormat("digest must be 32 bytes") }
        bytes = Array(data)
    }
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    public var description: String { "SHA256 digest: \(Data(bytes).hexString)" }
    public func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    public static func == (a: PrehashedSHA256Digest, b: PrehashedSHA256Digest) -> Bool { a.bytes == b.bytes }
}

/// Wrapper around an enclave-resident P-256 signing key.
public struct EnclaveSigningKey {
    public let key: SecureEnclave.P256.Signing.PrivateKey

    public init(create access: AccessPolicy, context: LAContext? = nil) throws {
        try Enclave.requireAvailable()
        let ac = try access.secAccessControl()
        key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: ac, authenticationContext: context)
    }

    public init(blob: Data, context: LAContext? = nil) throws {
        try Enclave.requireAvailable()
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        } catch {
            throw SafeskiError.invalidFormat("enclave key blob rejected: \(error.localizedDescription)")
        }
    }

    public var blob: Data { key.dataRepresentation }
    public var publicKey: P256.Signing.PublicKey { key.publicKey }

    /// Sign arbitrary data (SHA-256 is applied). Returns the raw r||s (64 bytes).
    public func sign(_ data: Data) throws -> Data {
        try mapAuthError { try key.signature(for: data).rawRepresentation }
    }

    /// Sign a caller-supplied 32-byte SHA-256 digest. Returns raw r||s.
    public func sign(digest: Data) throws -> Data {
        let d = try PrehashedSHA256Digest(digest)
        return try mapAuthError { try key.signature(for: d).rawRepresentation }
    }

    private func mapAuthError<T>(_ body: () throws -> T) throws -> T {
        do { return try body() }
        catch let e as SafeskiError { throw e }
        catch {
            let ns = error as NSError
            if ns.domain == LAErrorDomain || ns.localizedDescription.lowercased().contains("auth") || ns.localizedDescription.lowercased().contains("cancel") {
                throw SafeskiError.approvalFailed(ns.localizedDescription)
            }
            throw SafeskiError.io("enclave sign: \(ns.localizedDescription)")
        }
    }
}

/// Wrapper around an enclave-resident P-256 key-agreement key (used for secret envelopes).
public struct EnclaveAgreementKey {
    public let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    public init(create access: AccessPolicy, context: LAContext? = nil) throws {
        try Enclave.requireAvailable()
        let ac = try access.secAccessControl()
        key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac, authenticationContext: context)
    }

    public init(blob: Data, context: LAContext? = nil) throws {
        try Enclave.requireAvailable()
        do {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        } catch {
            throw SafeskiError.invalidFormat("enclave agreement key blob rejected: \(error.localizedDescription)")
        }
    }

    public var blob: Data { key.dataRepresentation }
    public var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }

    public func sharedSecret(with peer: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        do { return try key.sharedSecretFromKeyAgreement(with: peer) }
        catch {
            let ns = error as NSError
            if ns.domain == LAErrorDomain { throw SafeskiError.approvalFailed(ns.localizedDescription) }
            throw SafeskiError.io("enclave ecdh: \(ns.localizedDescription)")
        }
    }
}

/// Signature format conversions for P-256 ECDSA.
public enum ECDSAFormat {
    /// raw r||s (64 bytes) -> DER SEQUENCE { INTEGER r, INTEGER s }
    public static func rawToDER(_ raw: Data) throws -> Data {
        guard let sig = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else {
            throw SafeskiError.invalidFormat("bad raw signature length \(raw.count)")
        }
        return sig.derRepresentation
    }
    public static func derToRaw(_ der: Data) throws -> Data {
        guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: der) else {
            throw SafeskiError.invalidFormat("bad DER signature")
        }
        return sig.rawRepresentation
    }
    /// raw r||s -> SSH signature blob: string "ecdsa-sha2-nistp256", string(mpint r, mpint s)
    public static func rawToSSH(_ raw: Data) throws -> Data {
        guard raw.count == 64 else { throw SafeskiError.invalidFormat("bad raw signature length \(raw.count)") }
        var inner = SSHWire()
        inner.writeMPInt(raw.prefix(32))
        inner.writeMPInt(raw.suffix(32))
        var outer = SSHWire()
        outer.writeString("ecdsa-sha2-nistp256")
        outer.writeString(inner.data)
        return outer.data
    }
}

/// Public key encodings for P-256.
public enum PublicKeyFormat: String, Codable, CaseIterable {
    case ssh, pem, jwk, raw, hex, der
}

public extension P256.Signing.PublicKey {
    /// SSH public key blob: string "ecdsa-sha2-nistp256", string "nistp256", string Q(x963)
    var sshBlob: Data {
        var w = SSHWire()
        w.writeString("ecdsa-sha2-nistp256")
        w.writeString("nistp256")
        w.writeString(x963Representation)
        return w.data
    }
    func sshAuthorizedKey(comment: String) -> String {
        "ecdsa-sha2-nistp256 \(sshBlob.base64EncodedString()) \(comment)"
    }
    var sshFingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: sshBlob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
    var jwk: [String: JSONValue] {
        let raw = rawRepresentation
        return [
            "kty": .string("EC"), "crv": .string("P-256"),
            "x": .string(Base64URL.encode(raw.prefix(32))),
            "y": .string(Base64URL.encode(raw.suffix(32))),
        ]
    }
    /// RFC 7638 JWK thumbprint (SHA-256, base64url).
    var jwkThumbprint: String {
        let raw = rawRepresentation
        let canon = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(Base64URL.encode(raw.prefix(32)))\",\"y\":\"\(Base64URL.encode(raw.suffix(32)))\"}"
        return Base64URL.encode(Data(SHA256.hash(data: Data(canon.utf8))))
    }
    func encoded(_ format: PublicKeyFormat, comment: String = "") throws -> String {
        switch format {
        case .ssh: return sshAuthorizedKey(comment: comment)
        case .pem: return pemRepresentation
        case .der: return derRepresentation.base64EncodedString()
        case .raw: return rawRepresentation.base64EncodedString()
        case .hex: return rawRepresentation.hexString
        case .jwk:
            let data = try JSONEncoder.safeski.encode(JSONValue.object(jwk))
            return String(decoding: data, as: UTF8.self)
        }
    }
}
