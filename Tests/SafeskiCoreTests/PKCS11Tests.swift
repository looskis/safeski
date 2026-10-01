import CommonCrypto
import Darwin
import Foundation
import Security
import Testing
@testable import SafeskiCore

// Note: this file deliberately verifies with Security.framework and hashes with CommonCrypto.
// Importing CryptoKit into the test target breaks the Testing macro plugin lookup with the
// Command Line Tools toolchain ("plugin for module 'TestingMacros' not found").

/// End-to-end test of libsafeski-pkcs11.dylib: an in-process AgentServer on a temp socket, a
/// fresh enclave key, and the module driven through its CK_FUNCTION_LIST the way any PKCS#11
/// consumer would. Skipped when the dylib has not been built (`swift build` first).
enum PKCS11Fixture {
    static let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static let modulePath = packageRoot.appendingPathComponent(".build/debug/libsafeski-pkcs11.dylib").path
    static var moduleExists: Bool { FileManager.default.fileExists(atPath: modulePath) }

    static func sha256(_ d: Data) -> Data {
        var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        d.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(d.count), &out) }
        return Data(out)
    }

    /// Raw r||s -> DER ECDSA-Sig-Value, as SecKeyVerifySignature expects.
    static func der(rawSignature s: [UInt8]) -> Data {
        func int(_ b: ArraySlice<UInt8>) -> [UInt8] {
            var v = Array(b.drop { $0 == 0 })
            if v.isEmpty { v = [0] }
            if v[0] & 0x80 != 0 { v.insert(0, at: 0) }
            return [0x02, UInt8(v.count)] + v
        }
        let body = int(s[0..<32]) + int(s[32..<64])
        return Data([0x30, UInt8(body.count)] + body)
    }

    /// Verifies with Security.framework (independent of the module and of CryptoKit).
    static func verify(publicKeyX963: Data, rawSignature: [UInt8], digest: Data) -> Bool {
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                      kSecAttrKeyClass: kSecAttrKeyClassPublic, kSecAttrKeySizeInBits: 256]
        guard let key = SecKeyCreateWithData(publicKeyX963 as CFData, attrs as CFDictionary, nil) else { return false }
        return SecKeyVerifySignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, der(rawSignature: rawSignature) as CFData, nil)
    }
}

/// Minimal typed view of the v2.40 function list and struct layouts (LP64, natural alignment).
private struct P11 {
    typealias ULong = UInt
    typealias RV = UInt
    typealias F_Initialize = @convention(c) (UnsafeMutableRawPointer?) -> RV
    typealias F_Finalize = @convention(c) (UnsafeMutableRawPointer?) -> RV
    typealias F_GetSlotList = @convention(c) (UInt8, UnsafeMutablePointer<ULong>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_GetTokenInfo = @convention(c) (ULong, UnsafeMutableRawPointer?) -> RV
    typealias F_OpenSession = @convention(c) (ULong, ULong, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_CloseSession = @convention(c) (ULong) -> RV
    typealias F_GetAttributeValue = @convention(c) (ULong, ULong, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_FindObjectsInit = @convention(c) (ULong, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_FindObjects = @convention(c) (ULong, UnsafeMutablePointer<ULong>?, ULong, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_FindObjectsFinal = @convention(c) (ULong) -> RV
    typealias F_SignInit = @convention(c) (ULong, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_Sign = @convention(c) (ULong, UnsafeMutablePointer<UInt8>?, ULong, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_VerifyInit = @convention(c) (ULong, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_Verify = @convention(c) (ULong, UnsafeMutablePointer<UInt8>?, ULong, UnsafeMutablePointer<UInt8>?, ULong) -> RV

    let list: UnsafeRawPointer
    func fn<T>(_ i: Int, _: T.Type) -> T {
        unsafeBitCast(list.load(fromByteOffset: 8 + 8 * i, as: UnsafeRawPointer.self), to: T.self)
    }

    /// Builds a CK_ATTRIBUTE array; a nil value is a size query. Returns (buffer, owned pointers).
    static func template(_ items: [(ULong, Data?)]) -> (UnsafeMutableRawPointer, [UnsafeMutableRawPointer]) {
        let base = UnsafeMutableRawPointer.allocate(byteCount: max(1, 24 * items.count), alignment: 8)
        var owned: [UnsafeMutableRawPointer] = []
        for (i, (type, value)) in items.enumerated() {
            base.storeBytes(of: type, toByteOffset: 24 * i, as: ULong.self)
            var p: UnsafeMutableRawPointer? = nil
            if let value {
                p = UnsafeMutableRawPointer.allocate(byteCount: max(1, value.count), alignment: 8)
                value.withUnsafeBytes { if $0.count > 0 { p!.copyMemory(from: $0.baseAddress!, byteCount: $0.count) } }
                owned.append(p!)
            }
            base.storeBytes(of: p, toByteOffset: 24 * i + 8, as: UnsafeMutableRawPointer?.self)
            base.storeBytes(of: ULong(value?.count ?? 0), toByteOffset: 24 * i + 16, as: ULong.self)
        }
        return (base, owned)
    }
    static func mechanism(_ m: ULong) -> UnsafeMutableRawPointer {
        let p = UnsafeMutableRawPointer.allocate(byteCount: 24, alignment: 8)
        p.initializeMemory(as: UInt8.self, repeating: 0, count: 24)
        p.storeBytes(of: m, toByteOffset: 0, as: ULong.self)
        return p
    }
}

@Test(.enabled(if: PKCS11Fixture.moduleExists, "build libsafeski-pkcs11.dylib first"))
func pkcs11ModuleSignsWithEnclaveKeyThroughAgent() throws {
    // Short root: the agent socket path must fit sockaddr_un.
    let root = URL(fileURLWithPath: "/tmp/ssk-p11-test-\(getpid())")
    try? FileManager.default.removeItem(at: root)
    defer { try? FileManager.default.removeItem(at: root) }
    setenv("SAFESKI_RUNTIME_DIR", root.appendingPathComponent("run").path, 1)
    let paths = SafeskiPaths(root: root)
    let store = Store(paths: paths)
    _ = try store.initialize(name: "p11-test", vaultAccess: .none)
    try FileIO.writePrivate(Data("[defaults]\napprove = \"never\"\nttl = 60\n".utf8), to: paths.policy)
    let key = try store.createKey(name: "p11test", kind: .enclaveSigning, access: .none)

    let agent = try AgentServer(paths: paths, interactive: false)
    try agent.start()
    defer { agent.stop() }
    setenv("SAFESKI_SOCKET", paths.agentSocket.path, 1)

    let dl = try #require(dlopen(PKCS11Fixture.modulePath, RTLD_NOW | RTLD_LOCAL), "dlopen failed")
    defer { dlclose(dl) }
    let sym = try #require(dlsym(dl, "C_GetFunctionList"), "C_GetFunctionList not exported")
    typealias F_GetFunctionList = @convention(c) (UnsafeMutablePointer<UnsafeRawPointer?>?) -> UInt
    var listPtr: UnsafeRawPointer?
    #expect(unsafeBitCast(sym, to: F_GetFunctionList.self)(&listPtr) == 0)
    let p11 = P11(list: try #require(listPtr))
    #expect(p11.list.load(fromByteOffset: 0, as: UInt8.self) == 2)
    #expect(p11.list.load(fromByteOffset: 1, as: UInt8.self) == 40)

    #expect(p11.fn(0, P11.F_Initialize.self)(nil) == 0)
    defer { _ = p11.fn(1, P11.F_Finalize.self)(nil) }
    #expect(p11.fn(0, P11.F_Initialize.self)(nil) == 0x191, "second C_Initialize is CKR_CRYPTOKI_ALREADY_INITIALIZED")

    var count: UInt = 0
    #expect(p11.fn(4, P11.F_GetSlotList.self)(1, nil, &count) == 0)
    #expect(count == 1)
    let tok = UnsafeMutableRawPointer.allocate(byteCount: 208, alignment: 8); defer { tok.deallocate() }
    #expect(p11.fn(6, P11.F_GetTokenInfo.self)(0, tok) == 0)
    #expect(String(decoding: Data(bytes: tok, count: 7), as: UTF8.self) == "safeski")
    let dev = try store.loadDevice()
    #expect(String(decoding: Data(bytes: tok + 80, count: 16), as: UTF8.self) == dev.deviceID)

    var session: UInt = 0
    #expect(p11.fn(12, P11.F_OpenSession.self)(0, 0x4, nil, nil, &session) == 0)
    defer { _ = p11.fn(13, P11.F_CloseSession.self)(session) }

    func find(_ items: [(UInt, Data?)]) -> [UInt] {
        let (t, owned) = P11.template(items)
        defer { owned.forEach { $0.deallocate() }; t.deallocate() }
        guard p11.fn(26, P11.F_FindObjectsInit.self)(session, t, UInt(items.count)) == 0 else { return [] }
        var out = [UInt](repeating: 0, count: 16), n: UInt = 0
        guard p11.fn(27, P11.F_FindObjects.self)(session, &out, 16, &n) == 0 else { return [] }
        _ = p11.fn(28, P11.F_FindObjectsFinal.self)(session)
        return Array(out[0..<Int(n)])
    }
    func attr(_ obj: UInt, _ type: UInt) throws -> Data {
        let (t, _) = P11.template([(type, nil)])
        defer { t.deallocate() }
        try #require(p11.fn(24, P11.F_GetAttributeValue.self)(session, obj, t, 1) == 0)
        let n = Int(t.load(fromByteOffset: 16, as: UInt.self))
        let buf = UnsafeMutableRawPointer.allocate(byteCount: max(1, n), alignment: 8); defer { buf.deallocate() }
        t.storeBytes(of: buf, toByteOffset: 8, as: UnsafeMutableRawPointer?.self)
        try #require(p11.fn(24, P11.F_GetAttributeValue.self)(session, obj, t, 1) == 0)
        return Data(bytes: buf, count: n)
    }
    func ulong(_ v: UInt) -> Data { withUnsafeBytes(of: v) { Data($0) } }

    let pubs = find([(0x0, ulong(2))])              // CKA_CLASS = CKO_PUBLIC_KEY
    #expect(pubs.count == 1)
    let pub = try #require(pubs.first)
    #expect(try attr(pub, 0x3) == Data("p11test".utf8))                 // CKA_LABEL
    #expect(try attr(pub, 0x181) == Data([0x04, 0x41]) + key.publicKey)  // CKA_EC_POINT
    #expect(try attr(pub, 0x180) == Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]))
    let id = try attr(pub, 0x102)
    #expect(id == PKCS11Fixture.sha256(key.publicKey).prefix(20))

    let privs = find([(0x0, ulong(3)), (0x102, id)])  // CKO_PRIVATE_KEY with the same CKA_ID
    #expect(privs.count == 1)
    let priv = try #require(privs.first)
    #expect(find([(0x3, Data("nope".utf8))]).isEmpty)
    #expect(find([]).count == 2, "empty template matches every object")

    // CKM_ECDSA over a digest, with size query and buffer-too-small first.
    let message = Data("hello from the enclave".utf8)
    let digestData = PKCS11Fixture.sha256(message)
    var digest = [UInt8](digestData)
    let ecdsa = P11.mechanism(0x1041); defer { ecdsa.deallocate() }
    #expect(p11.fn(42, P11.F_SignInit.self)(session, ecdsa, priv) == 0)
    var sigLen: UInt = 0
    #expect(p11.fn(43, P11.F_Sign.self)(session, &digest, 32, nil, &sigLen) == 0)
    #expect(sigLen == 64)
    var sig = [UInt8](repeating: 0, count: 64)
    var small: UInt = 1
    #expect(p11.fn(43, P11.F_Sign.self)(session, &digest, 32, &sig, &small) == 0x150)
    #expect(p11.fn(43, P11.F_Sign.self)(session, &digest, 32, &sig, &sigLen) == 0)
    #expect(PKCS11Fixture.verify(publicKeyX963: key.publicKey, rawSignature: sig, digest: digestData))
    #expect(p11.fn(43, P11.F_Sign.self)(session, &digest, 32, &sig, &sigLen) == 0x91, "operation is consumed")

    // CKM_ECDSA with a non-digest-sized input is rejected.
    #expect(p11.fn(42, P11.F_SignInit.self)(session, ecdsa, priv) == 0)
    var short = [UInt8](repeating: 1, count: 5)
    #expect(p11.fn(43, P11.F_Sign.self)(session, &short, 5, &sig, &sigLen) == 0x21)

    // CKM_ECDSA_SHA256 hashes the message itself.
    let ecdsaSHA = P11.mechanism(0x1044); defer { ecdsaSHA.deallocate() }
    var msg = [UInt8](message)
    #expect(p11.fn(42, P11.F_SignInit.self)(session, ecdsaSHA, priv) == 0)
    sigLen = 64
    #expect(p11.fn(43, P11.F_Sign.self)(session, &msg, UInt(msg.count), &sig, &sigLen) == 0)
    #expect(PKCS11Fixture.verify(publicKeyX963: key.publicKey, rawSignature: sig, digest: digestData))

    // Signing with the public-key object is refused; verifying with it works.
    #expect(p11.fn(42, P11.F_SignInit.self)(session, ecdsa, pub) == 0x68)
    #expect(p11.fn(48, P11.F_VerifyInit.self)(session, ecdsaSHA, pub) == 0)
    #expect(p11.fn(49, P11.F_Verify.self)(session, &msg, UInt(msg.count), &sig, 64) == 0)
    sig[0] ^= 1
    #expect(p11.fn(48, P11.F_VerifyInit.self)(session, ecdsaSHA, pub) == 0)
    #expect(p11.fn(49, P11.F_Verify.self)(session, &msg, UInt(msg.count), &sig, 64) == 0xC0)

    // The agent audited the signatures on behalf of this process.
    let signs = try agent.service.audit.tail(20).filter { $0.action == "key.sign" }
    #expect(signs.count == 2)
    #expect(signs.allSatisfy { $0.resource == "p11test" && $0.outcome == "allow" })
}
