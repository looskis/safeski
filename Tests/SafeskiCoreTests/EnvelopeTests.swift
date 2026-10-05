import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

@Suite("Envelope", .requiresEnclave, .enclaveSerialized)
struct EnvelopeTests {
    private func recipient(_ id: String) throws -> (Envelope.RecipientKey, EnclaveAgreementKey) {
        let k = try EnclaveAgreementKey(create: .none)
        return (Envelope.RecipientKey(deviceID: id, vaultPublicKey: k.publicKey), k)
    }
    private func dekBytes(_ k: SymmetricKey) -> Data { k.withUnsafeBytes { Data($0) } }

    @Test func sealOpenRoundTrip() throws {
        let (r, k) = try recipient("dev1")
        let plain = Data("hello enclave".utf8)
        let env = try Envelope.seal(plain, aad: "secret:x", recipients: [r])
        #expect(env.version == 1)
        #expect(env.aad == "secret:x")
        #expect(env.recipients.count == 1)
        #expect(env.recipients[0].deviceID == "dev1")
        #expect(env.recipients[0].ephemeralPublicKey.count == 65)
        #expect(env.ciphertext.count == 12 + plain.count + 16)
        #expect(try Envelope.open(env, deviceID: "dev1", vaultKey: k) == plain)

        // empty plaintext is fine too
        let empty = try Envelope.seal(Data(), aad: "e", recipients: [r])
        #expect(try Envelope.open(empty, deviceID: "dev1", vaultKey: k) == Data())
    }

    @Test func x963RecipientInitializer() throws {
        let (r, k) = try recipient("dev1")
        let viaX963 = try Envelope.RecipientKey(deviceID: "dev1", vaultPublicKeyX963: r.vaultPublicKey.x963Representation)
        let env = try Envelope.seal(Data([1, 2, 3]), aad: "a", recipients: [viaX963])
        #expect(try Envelope.open(env, deviceID: "dev1", vaultKey: k) == Data([1, 2, 3]))
        #expect((try? Envelope.RecipientKey(deviceID: "x", vaultPublicKeyX963: Data([4, 5]))) == nil)
    }

    @Test func noRecipientsIsAnError() {
        let e = safeskiError { _ = try Envelope.seal(Data([1]), aad: "a", recipients: []) }
        #expect(e?.code == "invalid_format")
    }

    @Test func wrongDeviceIDIsDenied() throws {
        let (r, k) = try recipient("dev1")
        let env = try Envelope.seal(Data([9]), aad: "a", recipients: [r])
        let e = safeskiError { _ = try Envelope.open(env, deviceID: "dev2", vaultKey: k) }
        #expect(e?.code == "denied")
        #expect(e?.message.contains("dev2") == true)
    }

    @Test func wrongKeyForRecipientFails() throws {
        let (r1, _) = try recipient("dev1")
        let (_, k2) = try recipient("dev2")
        let env = try Envelope.seal(Data([9]), aad: "a", recipients: [r1])
        // right device id, wrong private key
        let e = safeskiError { _ = try Envelope.open(env, deviceID: "dev1", vaultKey: k2) }
        #expect(e?.code == "invalid_format")
        #expect(e?.message.contains("DEK unwrap failed") == true)
    }

    @Test func tamperedCiphertextIsInvalidFormat() throws {
        let (r, k) = try recipient("dev1")
        var env = try Envelope.seal(Data("payload".utf8), aad: "a", recipients: [r])
        env.ciphertext[env.ciphertext.startIndex + env.ciphertext.count / 2] ^= 0x01
        let e = safeskiError { _ = try Envelope.open(env, deviceID: "dev1", vaultKey: k) }
        #expect(e?.code == "invalid_format")
        #expect(e?.message.contains("payload authentication failed") == true)
    }

    @Test func tamperedWrappedDEKIsInvalidFormat() throws {
        let (r, k) = try recipient("dev1")
        var env = try Envelope.seal(Data("payload".utf8), aad: "a", recipients: [r])
        env.recipients[0].wrappedDEK[env.recipients[0].wrappedDEK.startIndex + 20] ^= 0xff
        let e = safeskiError { _ = try Envelope.open(env, deviceID: "dev1", vaultKey: k) }
        #expect(e?.code == "invalid_format")
        #expect(e?.message.contains("DEK unwrap failed") == true)
    }

    @Test func aadMismatchFails() throws {
        let (r, k) = try recipient("dev1")
        var env = try Envelope.seal(Data("payload".utf8), aad: "secret:a", recipients: [r])
        env.aad = "secret:b"
        let e = safeskiError { _ = try Envelope.open(env, deviceID: "dev1", vaultKey: k) }
        #expect(e?.code == "invalid_format")
        // the DEK unwrap itself still works; only the payload check fails
        #expect(e?.message.contains("payload authentication failed") == true)
    }

    @Test func multiRecipient() throws {
        let (r1, k1) = try recipient("dev1")
        let (r2, k2) = try recipient("dev2")
        let plain = Data("shared".utf8)
        let env = try Envelope.seal(plain, aad: "a", recipients: [r1, r2])
        #expect(env.recipients.map(\.deviceID) == ["dev1", "dev2"])
        #expect(try Envelope.open(env, deviceID: "dev1", vaultKey: k1) == plain)
        #expect(try Envelope.open(env, deviceID: "dev2", vaultKey: k2) == plain)
        // each recipient has its own ephemeral key and wrapped DEK
        #expect(env.recipients[0].ephemeralPublicKey != env.recipients[1].ephemeralPublicKey)
        #expect(env.recipients[0].wrappedDEK != env.recipients[1].wrappedDEK)
    }

    @Test func addRecipients() throws {
        let (r1, k1) = try recipient("dev1")
        let (r2, k2) = try recipient("dev2")
        let plain = Data("later".utf8)
        let env = try Envelope.seal(plain, aad: "a", recipients: [r1])
        #expect(safeskiError { _ = try Envelope.open(env, deviceID: "dev2", vaultKey: k2) }?.code == "denied")

        let dek = try Envelope.unwrapDEK(env, deviceID: "dev1", vaultKey: k1)
        let env2 = try Envelope.addRecipients(env, dek: dek, recipients: [r2])
        #expect(env2.recipients.count == 2)
        #expect(env2.ciphertext == env.ciphertext)   // payload is not re-encrypted
        #expect(try Envelope.open(env2, deviceID: "dev2", vaultKey: k2) == plain)
        #expect(try Envelope.open(env2, deviceID: "dev1", vaultKey: k1) == plain)

        // adding an already-present recipient is a no-op
        let env3 = try Envelope.addRecipients(env2, dek: dek, recipients: [r1, r2])
        #expect(env3 == env2)
    }

    @Test func unwrapDEKIsSameForEveryRecipient() throws {
        let (r1, k1) = try recipient("dev1")
        let (r2, k2) = try recipient("dev2")
        let (r3, k3) = try recipient("dev3")
        let env = try Envelope.seal(Data("x".utf8), aad: "a", recipients: [r1, r2, r3])
        let d1 = dekBytes(try Envelope.unwrapDEK(env, deviceID: "dev1", vaultKey: k1))
        let d2 = dekBytes(try Envelope.unwrapDEK(env, deviceID: "dev2", vaultKey: k2))
        let d3 = dekBytes(try Envelope.unwrapDEK(env, deviceID: "dev3", vaultKey: k3))
        #expect(d1.count == 32)
        #expect(d1 == d2 && d2 == d3)
        // and the DEK opens the payload directly
        #expect(try Envelope.open(env, dek: SymmetricKey(data: d1)) == Data("x".utf8))
    }

    @Test func envelopeCodableRoundTrip() throws {
        let (r, k) = try recipient("dev1")
        let env = try Envelope.seal(Data("codable".utf8), aad: "a", recipients: [r])
        let data = try JSONEncoder.safeski.encode(env)
        let back = try JSONDecoder.safeski.decode(SecretEnvelope.self, from: data)
        #expect(back.recipients == env.recipients)
        #expect(back.ciphertext == env.ciphertext)
        #expect(back.aad == env.aad)
        #expect(try Envelope.open(back, deviceID: "dev1", vaultKey: k) == Data("codable".utf8))
    }
}
