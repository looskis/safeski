import CryptoKit
import Foundation

/// Hybrid encryption helpers for `SecretEnvelope`.
public enum Envelope {
    static let hkdfInfoPrefix = "safeski-envelope-v1:"

    public struct RecipientKey {
        public let deviceID: String
        public let vaultPublicKey: P256.KeyAgreement.PublicKey
        public init(deviceID: String, vaultPublicKey: P256.KeyAgreement.PublicKey) {
            self.deviceID = deviceID; self.vaultPublicKey = vaultPublicKey
        }
        public init(deviceID: String, vaultPublicKeyX963: Data) throws {
            self.deviceID = deviceID
            self.vaultPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: vaultPublicKeyX963)
        }
    }

    static func wrappingKey(shared: SharedSecret, ephemeral: Data, deviceID: String) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral,
                                       sharedInfo: Data((hkdfInfoPrefix + deviceID).utf8), outputByteCount: 32)
    }

    public static func seal(_ plaintext: Data, aad: String, recipients: [RecipientKey]) throws -> SecretEnvelope {
        guard !recipients.isEmpty else { throw SafeskiError.invalidFormat("envelope needs at least one recipient") }
        let dek = SymmetricKey(size: .bits256)
        let box = try AES.GCM.seal(plaintext, using: dek, authenticating: Data(aad.utf8))
        guard let combined = box.combined else { throw SafeskiError.io("AES-GCM combined representation unavailable") }
        let dekData = dek.withUnsafeBytes { Data($0) }
        var recs: [SecretEnvelope.Recipient] = []
        for r in recipients {
            recs.append(try wrapDEK(dekData, for: r))
        }
        return SecretEnvelope(recipients: recs, ciphertext: combined, aad: aad, created: Date())
    }

    static func wrapDEK(_ dek: Data, for r: RecipientKey) throws -> SecretEnvelope.Recipient {
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: r.vaultPublicKey)
        let ephPub = eph.publicKey.x963Representation
        let wk = wrappingKey(shared: shared, ephemeral: ephPub, deviceID: r.deviceID)
        let wrapped = try AES.GCM.seal(dek, using: wk, authenticating: Data(r.deviceID.utf8))
        guard let combined = wrapped.combined else { throw SafeskiError.io("AES-GCM combined representation unavailable") }
        return .init(deviceID: r.deviceID, ephemeralPublicKey: ephPub, wrappedDEK: combined)
    }

    /// Unwrap the DEK for `deviceID` using that device's enclave agreement key.
    public static func unwrapDEK(_ env: SecretEnvelope, deviceID: String, vaultKey: EnclaveAgreementKey) throws -> SymmetricKey {
        guard let rec = env.recipients.first(where: { $0.deviceID == deviceID }) else {
            throw SafeskiError.denied("this device (\(deviceID)) is not a recipient of the envelope")
        }
        let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: rec.ephemeralPublicKey)
        let shared = try vaultKey.sharedSecret(with: ephPub)
        let wk = wrappingKey(shared: shared, ephemeral: rec.ephemeralPublicKey, deviceID: deviceID)
        let box = try AES.GCM.SealedBox(combined: rec.wrappedDEK)
        let dek: Data
        do { dek = try AES.GCM.open(box, using: wk, authenticating: Data(deviceID.utf8)) }
        catch { throw SafeskiError.invalidFormat("envelope DEK unwrap failed (wrong device key or corrupted)") }
        return SymmetricKey(data: dek)
    }

    public static func open(_ env: SecretEnvelope, deviceID: String, vaultKey: EnclaveAgreementKey) throws -> Data {
        let dek = try unwrapDEK(env, deviceID: deviceID, vaultKey: vaultKey)
        return try open(env, dek: dek)
    }

    public static func open(_ env: SecretEnvelope, dek: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: env.ciphertext)
        do { return try AES.GCM.open(box, using: dek, authenticating: Data(env.aad.utf8)) }
        catch { throw SafeskiError.invalidFormat("envelope payload authentication failed") }
    }

    /// Add recipients to an existing envelope (requires unwrapping the DEK on this device first).
    public static func addRecipients(_ env: SecretEnvelope, dek: SymmetricKey, recipients: [RecipientKey]) throws -> SecretEnvelope {
        var out = env
        let dekData = dek.withUnsafeBytes { Data($0) }
        for r in recipients where !out.recipients.contains(where: { $0.deviceID == r.deviceID }) {
            out.recipients.append(try wrapDEK(dekData, for: r))
        }
        return out
    }
}
