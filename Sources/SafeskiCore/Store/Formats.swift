import Foundation

/// On-disk formats. All are versioned JSON so a future sync layer can ship them between devices.
/// Device-bound material (enclave blobs) is only meaningful on the device that created it, so every
/// record carries the `deviceID` that owns it.

public enum KeyKind: String, Codable, CaseIterable {
    /// P-256 ECDSA key living in the Secure Enclave.
    case enclaveSigning = "enclave-signing"
    /// P-256 ECDH key living in the Secure Enclave.
    case enclaveAgreement = "enclave-agreement"
    /// Software Ed25519 key, stored as an envelope encrypted to this device's enclave agreement key.
    case softwareEd25519 = "software-ed25519"
    /// Software X25519 key, stored as an envelope.
    case softwareX25519 = "software-x25519"

    public var isEnclave: Bool { self == .enclaveSigning || self == .enclaveAgreement }
    public var canSign: Bool { self == .enclaveSigning || self == .softwareEd25519 }
}

public struct KeyRecord: Codable, Equatable {
    public var version: Int = 1
    public var name: String
    public var kind: KeyKind
    public var deviceID: String
    public var access: AccessPolicy
    /// Enclave wrapped blob (for enclave kinds), base64.
    public var blob: Data?
    /// Software private key material, as an envelope encrypted to this device.
    public var envelope: SecretEnvelope?
    /// Public key: x963 for P-256, raw 32 bytes for Ed25519/X25519.
    public var publicKey: Data
    public var created: Date
    public var labels: [String: String]
    public var comment: String?

    public init(name: String, kind: KeyKind, deviceID: String, access: AccessPolicy, blob: Data?, envelope: SecretEnvelope?,
                publicKey: Data, created: Date = Date(), labels: [String: String] = [:], comment: String? = nil) {
        self.name = name; self.kind = kind; self.deviceID = deviceID; self.access = access
        self.blob = blob; self.envelope = envelope; self.publicKey = publicKey
        self.created = created; self.labels = labels; self.comment = comment
    }

    /// Public-only projection for RPC/listing.
    public var summary: KeySummary {
        KeySummary(name: name, kind: kind, deviceID: deviceID, access: access, publicKey: publicKey,
                   created: created, labels: labels, comment: comment)
    }
}

public struct KeySummary: Codable, Equatable {
    public var name: String
    public var kind: KeyKind
    public var deviceID: String
    public var access: AccessPolicy
    public var publicKey: Data
    public var created: Date
    public var labels: [String: String]
    public var comment: String?
}

/// Multi-recipient envelope. A random 256-bit DEK encrypts the payload with AES-GCM; the DEK is
/// wrapped once per recipient device using ECDH(ephemeral, device agreement key) + HKDF + AES-GCM.
/// Adding a device later = add a recipient entry; no payload re-encryption needed if the DEK is known.
public struct SecretEnvelope: Codable, Equatable {
    public struct Recipient: Codable, Equatable {
        public var deviceID: String
        /// Ephemeral P-256 public key (x963).
        public var ephemeralPublicKey: Data
        /// AES-GCM(nonce || ciphertext || tag) of the DEK under the derived wrapping key.
        public var wrappedDEK: Data
    }
    public var version: Int = 1
    public var recipients: [Recipient]
    /// AES-GCM combined (nonce || ciphertext || tag).
    public var ciphertext: Data
    /// Additional authenticated data bound into the payload encryption (e.g. "secret:NAME").
    public var aad: String
    public var created: Date
}

public struct SecretRecord: Codable, Equatable {
    public var version: Int = 1
    public var name: String
    public var envelope: SecretEnvelope
    public var created: Date
    public var updated: Date
    public var labels: [String: String]
    /// Optional MIME-ish hint: "text", "binary", "env", "json".
    public var contentType: String

    public var summary: SecretSummary {
        SecretSummary(name: name, created: created, updated: updated, labels: labels, contentType: contentType,
                      recipients: envelope.recipients.map(\.deviceID))
    }
}

public struct SecretSummary: Codable, Equatable {
    public var name: String
    public var created: Date
    public var updated: Date
    public var labels: [String: String]
    public var contentType: String
    public var recipients: [String]
}

/// This device's identity: two enclave keys created at `safeski init`.
/// - identity (signing): signs the audit chain, device enrollment, and acts as the default JWT key.
/// - vault (agreement): recipient key for every secret envelope on this device.
public struct DeviceIdentity: Codable, Equatable {
    public var version: Int = 1
    public var deviceID: String
    public var name: String
    public var identityBlob: Data
    public var identityPublicKey: Data   // x963
    public var vaultBlob: Data
    public var vaultPublicKey: Data      // x963
    public var created: Date
    public var hardwareModel: String?

    /// Public projection, shareable with other devices for enrollment.
    public var publicRecord: DevicePublicRecord {
        DevicePublicRecord(deviceID: deviceID, name: name, identityPublicKey: identityPublicKey,
                           vaultPublicKey: vaultPublicKey, created: created, hardwareModel: hardwareModel)
    }
}

/// Another device's public keys, stored under devices/<id>.json after enrollment.
public struct DevicePublicRecord: Codable, Equatable {
    public var version: Int = 1
    public var deviceID: String
    public var name: String
    public var identityPublicKey: Data
    public var vaultPublicKey: Data
    public var created: Date
    public var hardwareModel: String?
    /// Signature by the enrolling device's identity key over the canonical record, once enrolled.
    public var enrollmentSignature: Data?
    public var enrolledBy: String?

    public init(deviceID: String, name: String, identityPublicKey: Data, vaultPublicKey: Data, created: Date,
                hardwareModel: String?, enrollmentSignature: Data? = nil, enrolledBy: String? = nil) {
        self.deviceID = deviceID; self.name = name; self.identityPublicKey = identityPublicKey
        self.vaultPublicKey = vaultPublicKey; self.created = created; self.hardwareModel = hardwareModel
        self.enrollmentSignature = enrollmentSignature; self.enrolledBy = enrolledBy
    }

    /// Canonical bytes signed at enrollment (excludes signature fields).
    public var canonicalBytes: Data {
        let base = DevicePublicRecord(deviceID: deviceID, name: name, identityPublicKey: identityPublicKey,
                                      vaultPublicKey: vaultPublicKey, created: created, hardwareModel: hardwareModel)
        return (try? JSONEncoder.safeskiCompact.encode(base)) ?? Data()
    }
}
