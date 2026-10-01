import CryptoKit
import Foundation

/// ssh-agent wire protocol (draft-miller-ssh-agent). Every message is a uint32 length prefix
/// (handled by `Framing`) followed by a one-byte type and a type-specific body in RFC 4251 wire
/// encoding. safeski only answers list and sign; everything that would mutate the agent's key
/// set (add/remove/lock) is refused because keys are managed by safeski, not by ssh-add.
public enum SSHAgentMessage {
    // Replies
    public static let failure: UInt8 = 5
    public static let success: UInt8 = 6
    public static let identitiesAnswer: UInt8 = 12
    public static let signResponse: UInt8 = 14
    public static let extensionFailure: UInt8 = 28
    // Requests
    public static let requestIdentities: UInt8 = 11
    public static let signRequest: UInt8 = 13
    public static let addIdentity: UInt8 = 17
    public static let removeIdentity: UInt8 = 18
    public static let removeAllIdentities: UInt8 = 19
    public static let addSmartcardKey: UInt8 = 20
    public static let removeSmartcardKey: UInt8 = 21
    public static let lock: UInt8 = 22
    public static let unlock: UInt8 = 23
    public static let addIdConstrained: UInt8 = 25
    public static let addSmartcardKeyConstrained: UInt8 = 26
    public static let `extension`: UInt8 = 27

    // Sign request flags (only meaningful for RSA keys; ignored for ECDSA/Ed25519).
    public static let flagRSASHA256: UInt32 = 0x02
    public static let flagRSASHA512: UInt32 = 0x04
}

/// A key as advertised to ssh clients: the public key blob plus a comment.
public struct SSHIdentity: Equatable {
    /// Wire-format public key (e.g. string "ssh-ed25519", string key).
    public var blob: Data
    public var comment: String

    public init(blob: Data, comment: String) { self.blob = blob; self.comment = comment }

    /// Key type name, taken from the first string of the blob ("ecdsa-sha2-nistp256", "ssh-ed25519").
    public var type: String {
        var r = SSHWire.Reader(blob)
        guard let t = try? r.readString() else { return "unknown" }
        return String(decoding: t, as: UTF8.self)
    }

    /// authorized_keys / allowed_signers style line: "<type> <base64 blob> <comment>".
    public var authorizedKeyLine: String { "\(type) \(blob.base64EncodedString()) \(comment)" }

    /// OpenSSH-style SHA256 fingerprint.
    public var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}

/// A parsed client request.
public enum SSHAgentRequest: Equatable {
    case requestIdentities
    case signRequest(keyBlob: Data, data: Data, flags: UInt32)
    case lock
    case unlock
    /// Extension request with its name (reply: FAILURE; safeski has no extensions).
    case extensionRequest(name: String)
    /// Any add/remove identity or smartcard operation (reply: FAILURE).
    case unsupported(type: UInt8)
}

public enum SSHAgentProtocol {
    // MARK: parsing requests

    /// Parse a request frame (type byte + body). Throws on malformed input; callers must turn
    /// that into an `SSH_AGENT_FAILURE` reply rather than dropping the connection.
    public static func parseRequest(_ frame: Data) throws -> SSHAgentRequest {
        var r = SSHWire.Reader(frame)
        let type = try r.readByte()
        switch type {
        case SSHAgentMessage.requestIdentities:
            return .requestIdentities
        case SSHAgentMessage.signRequest:
            let blob = try r.readString()
            let data = try r.readString()
            let flags = try r.readUInt32()
            return .signRequest(keyBlob: blob, data: data, flags: flags)
        case SSHAgentMessage.lock:
            return .lock
        case SSHAgentMessage.unlock:
            return .unlock
        case SSHAgentMessage.extension:
            let name = try r.readString()
            return .extensionRequest(name: String(decoding: name, as: UTF8.self))
        default:
            return .unsupported(type: type)
        }
    }

    // MARK: encoding requests (used by tests and in-process clients)

    public static func encodeRequest(_ req: SSHAgentRequest) -> Data {
        var w = SSHWire()
        switch req {
        case .requestIdentities:
            w.writeByte(SSHAgentMessage.requestIdentities)
        case let .signRequest(keyBlob, data, flags):
            w.writeByte(SSHAgentMessage.signRequest)
            w.writeString(keyBlob)
            w.writeString(data)
            w.writeUInt32(flags)
        case .lock:
            w.writeByte(SSHAgentMessage.lock)
            w.writeString("")
        case .unlock:
            w.writeByte(SSHAgentMessage.unlock)
            w.writeString("")
        case .extensionRequest(let name):
            w.writeByte(SSHAgentMessage.extension)
            w.writeString(name)
        case .unsupported(let type):
            w.writeByte(type)
        }
        return w.data
    }

    // MARK: encoding replies

    public static var failureReply: Data { Data([SSHAgentMessage.failure]) }
    public static var successReply: Data { Data([SSHAgentMessage.success]) }

    /// SSH_AGENT_IDENTITIES_ANSWER: uint32 count, then (string blob, string comment) per key.
    public static func identitiesAnswer(_ ids: [SSHIdentity]) -> Data {
        var w = SSHWire()
        w.writeByte(SSHAgentMessage.identitiesAnswer)
        w.writeUInt32(UInt32(ids.count))
        for id in ids {
            w.writeString(id.blob)
            w.writeString(id.comment)
        }
        return w.data
    }

    /// SSH_AGENT_SIGN_RESPONSE: string signature-blob (already in "string type, string sig" form).
    public static func signResponse(_ signatureBlob: Data) -> Data {
        var w = SSHWire()
        w.writeByte(SSHAgentMessage.signResponse)
        w.writeString(signatureBlob)
        return w.data
    }

    // MARK: parsing replies (clients / tests)

    public static func parseIdentitiesAnswer(_ frame: Data) throws -> [SSHIdentity] {
        var r = SSHWire.Reader(frame)
        guard try r.readByte() == SSHAgentMessage.identitiesAnswer else {
            throw SafeskiError.invalidFormat("ssh-agent: not an identities answer")
        }
        let n = try r.readUInt32()
        var out: [SSHIdentity] = []
        for _ in 0..<n {
            let blob = try r.readString()
            let comment = try r.readString()
            out.append(SSHIdentity(blob: blob, comment: String(decoding: comment, as: UTF8.self)))
        }
        return out
    }

    public static func parseSignResponse(_ frame: Data) throws -> Data {
        var r = SSHWire.Reader(frame)
        guard try r.readByte() == SSHAgentMessage.signResponse else {
            throw SafeskiError.invalidFormat("ssh-agent: not a sign response")
        }
        return try r.readString()
    }

    public static func isFailure(_ frame: Data) -> Bool { frame.first == SSHAgentMessage.failure }

    // MARK: signature blobs

    /// Ed25519 signature blob: string "ssh-ed25519", string sig(64).
    public static func ed25519SignatureBlob(_ sig: Data) throws -> Data {
        guard sig.count == 64 else { throw SafeskiError.invalidFormat("bad ed25519 signature length \(sig.count)") }
        var w = SSHWire()
        w.writeString("ssh-ed25519")
        w.writeString(sig)
        return w.data
    }

    /// Split a signature blob into (type, raw signature bytes). For ECDSA the raw part is the
    /// inner (mpint r, mpint s) string; use `ecdsaRawFromSSH` to get r||s.
    public static func splitSignatureBlob(_ blob: Data) throws -> (type: String, signature: Data) {
        var r = SSHWire.Reader(blob)
        let t = try r.readString()
        let s = try r.readString()
        return (String(decoding: t, as: UTF8.self), s)
    }

    /// SSH ECDSA signature blob -> raw r||s (64 bytes). Inverse of `ECDSAFormat.rawToSSH`.
    public static func ecdsaRawFromSSH(_ blob: Data) throws -> Data {
        let (type, inner) = try splitSignatureBlob(blob)
        guard type == "ecdsa-sha2-nistp256" else { throw SafeskiError.invalidFormat("not an ecdsa-sha2-nistp256 signature") }
        var r = SSHWire.Reader(inner)
        let rr = try r.readString()
        let ss = try r.readString()
        func fixed(_ m: Data) throws -> Data {
            var b = Data(m)
            while b.first == 0 && b.count > 32 { b.removeFirst() }
            guard b.count <= 32 else { throw SafeskiError.invalidFormat("mpint too large") }
            return Data(repeating: 0, count: 32 - b.count) + b
        }
        return try fixed(rr) + fixed(ss)
    }
}

/// Maps safeski keys onto ssh identities.
public enum SSHKeys {
    /// The identity ssh clients see for a key, or nil when the key is not ssh-capable
    /// (wrong kind, or labelled `ssh = "false"`).
    public static func identity(for key: KeySummary) -> SSHIdentity? {
        if key.labels["ssh"]?.lowercased() == "false" { return nil }
        let comment = key.comment ?? "safeski:\(key.name)"
        switch key.kind {
        case .enclaveSigning:
            guard let pk = try? P256.Signing.PublicKey(x963Representation: key.publicKey) else { return nil }
            return SSHIdentity(blob: pk.sshBlob, comment: comment)
        case .softwareEd25519:
            guard key.publicKey.count == 32 else { return nil }
            var w = SSHWire()
            w.writeString("ssh-ed25519")
            w.writeString(key.publicKey)
            return SSHIdentity(blob: w.data, comment: comment)
        default:
            return nil
        }
    }

    /// All ssh-capable keys with their identities, in store order.
    public static func identities(for keys: [KeySummary]) -> [(key: KeySummary, identity: SSHIdentity)] {
        keys.compactMap { k in identity(for: k).map { (k, $0) } }
    }

    /// Convert a raw signature from `Service.sign` into the ssh signature blob for the key's type.
    public static func signatureBlob(kind: KeyKind, raw: Data) throws -> Data {
        switch kind {
        case .enclaveSigning: return try ECDSAFormat.rawToSSH(raw)
        case .softwareEd25519: return try SSHAgentProtocol.ed25519SignatureBlob(raw)
        default: throw SafeskiError.unsupported("\(kind.rawValue) cannot produce ssh signatures")
        }
    }
}
