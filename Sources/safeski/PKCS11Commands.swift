import ArgumentParser
import CryptoKit
import Darwin
import Foundation
import SafeskiCore

/// `safeski pkcs11`: locate, exercise and explain the PKCS#11 module (libsafeski-pkcs11.dylib).
///
/// The CLI deliberately does not link the module or its C header; `test` loads it with dlopen
/// exactly the way OpenSSL, OpenSC or OpenSSH would, and drives it through the CK_FUNCTION_LIST.
struct PKCS11Cmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "pkcs11",
        abstract: "Expose enclave keys to PKCS#11 consumers (OpenSSL, pkcs11-tool, Java, ssh).",
        subcommands: [Path.self, Test.self, Setup.self])

    /// Resolution order: $SAFESKI_PKCS11, then next to the running executable, then ../lib.
    static func candidates() -> [String] {
        var out: [String] = []
        if let env = ProcessInfo.processInfo.environment["SAFESKI_PKCS11"], !env.isEmpty { out.append(env) }
        let exe = CallerIdentity.resolvePath(pid: getpid())
            ?? URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
        let dir = URL(fileURLWithPath: exe).deletingLastPathComponent()
        out.append(dir.appendingPathComponent("libsafeski-pkcs11.dylib").path)
        out.append(dir.appendingPathComponent("../lib/libsafeski-pkcs11.dylib").standardizedFileURL.path)
        return out
    }

    static func resolveModule() -> String? {
        candidates().first { FileManager.default.fileExists(atPath: $0) }
    }

    struct Path: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the path of the PKCS#11 module.")
        func run() throws {
            if let p = PKCS11Cmd.resolveModule() { print(p); return }
            Output.fail("module not found; looked in:\n  " + PKCS11Cmd.candidates().joined(separator: "\n  ")
                        + "\nbuild it with `swift build` or set SAFESKI_PKCS11")
        }
    }

    struct Test: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Load the module and run an end-to-end sign/verify check against the agent.")
        @Option(help: "Module path (default: `safeski pkcs11 path`).") var module: String?
        @Option(help: "Key label to sign with (default: first enclave signing key).") var key: String?

        func run() throws {
            guard let path = module ?? PKCS11Cmd.resolveModule() else { Output.fail("module not found; pass --module") }
            do {
                try PKCS11Harness(modulePath: path, keyLabel: key, log: { print($0) }).run()
                print("pkcs11: all checks passed")
            } catch {
                Output.fail("pkcs11 test failed: \(error)")
            }
        }
    }

    struct Setup: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Show how to point PKCS#11 consumers at the safeski module.")
        func run() throws {
            let module = PKCS11Cmd.resolveModule() ?? PKCS11Cmd.candidates().first!
            print("""
            safeski PKCS#11 module
              \(module)

            The module is a read-only hardware token named "safeski" (slot 0). Every enclave
            signing key appears as a CKO_PUBLIC_KEY / CKO_PRIVATE_KEY pair labelled with the key
            name; CKA_ID is the first 20 bytes of SHA-256 over the public point. Mechanisms:
            CKM_ECDSA (input: 32-byte SHA-256 digest) and CKM_ECDSA_SHA256. Keys are not
            CKA_PRIVATE, so no PIN is required; C_Login accepts any PIN. Policy, approvals and
            audit are enforced by the running safeski agent, which must be up
            (`safeski agent start`). Set SAFESKI_SOCKET / SAFESKI_TOKEN to reach a non-default agent;
            SAFESKI_PKCS11_DEBUG=1 traces every call to stderr.

            Quick check
              safeski pkcs11 test

            OpenSC pkcs11-tool
              pkcs11-tool --module \(module) -L
              pkcs11-tool --module \(module) -O
              openssl dgst -sha256 -binary -out digest.bin message.txt
              pkcs11-tool --module \(module) --sign --mechanism ECDSA --label KEY \\
                  --signature-format sequence -i digest.bin -o sig.der
              safeski pubkey KEY --format pem > KEY.pem
              openssl pkeyutl -verify -pubin -inkey KEY.pem -in digest.bin -sigfile sig.der

            OpenSSL 3 (pkcs11-provider, e.g. `brew install pkcs11-provider`)
              # openssl.cnf
              [openssl_init]
              providers = provider_sect
              [provider_sect]
              default = default_sect
              pkcs11 = pkcs11_sect
              [default_sect]
              activate = 1
              [pkcs11_sect]
              module = /opt/homebrew/lib/ossl-modules/pkcs11.dylib
              pkcs11-module-path = \(module)
              pkcs11-module-quirks = no-deinit
              activate = 1

              openssl pkeyutl -provider pkcs11 -provider default -sign -rawin -digest sha256 \\
                  -inkey "pkcs11:token=safeski;object=KEY;type=private" -in message.txt -out sig.der

            Java (SunPKCS11)
              # safeski-pkcs11.cfg
              name = safeski
              library = \(module)
              slot = 0

              keytool -keystore NONE -storetype PKCS11 \\
                  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg safeski-pkcs11.cfg -list

            OpenSSH
              ssh-keygen -D \(module)                 # list public keys (ecdsa-sha2-nistp256)
              ssh -I \(module) user@host             # use the token for one connection
              ssh-add -s \(module)                   # load into ssh-agent (ssh-agent -P must allow the path)
              # ~/.ssh/config
              Host *
                PKCS11Provider \(module)

            Note: the safeski agent already provides an SSH agent socket (`safeski agent env`), which
            is the simpler route for ssh; PKCS#11 is for tools that cannot speak the agent protocol.
            """)
        }
    }
}

// MARK: - dlopen harness

/// Drives a PKCS#11 module through its function list using the documented v2.40 struct layouts
/// (natural alignment, LP64). Shared in spirit with the Swift Testing test; both are consumers of
/// the module, not part of it.
final class PKCS11Harness {
    typealias ULong = UInt
    typealias RV = UInt
    typealias Handle = UInt

    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ s: String) { description = s }
    }

    // Constants (PKCS#11 v2.40).
    static let CKF_SERIAL_SESSION: ULong = 0x4
    static let CKA_CLASS: ULong = 0x0, CKA_LABEL: ULong = 0x3, CKA_ID: ULong = 0x102
    static let CKA_KEY_TYPE: ULong = 0x100, CKA_EC_PARAMS: ULong = 0x180, CKA_EC_POINT: ULong = 0x181
    static let CKA_SIGN: ULong = 0x108, CKA_SENSITIVE: ULong = 0x103, CKA_VALUE: ULong = 0x11
    static let CKO_PUBLIC_KEY: ULong = 2, CKO_PRIVATE_KEY: ULong = 3
    static let CKK_EC: ULong = 3
    static let CKM_ECDSA: ULong = 0x1041, CKM_ECDSA_SHA256: ULong = 0x1044
    static let CKR_OK: RV = 0, CKR_BUFFER_TOO_SMALL: RV = 0x150, CKR_ATTRIBUTE_SENSITIVE: RV = 0x11
    static let CKR_SIGNATURE_INVALID: RV = 0xC0
    static let CK_UNAVAILABLE_INFORMATION: ULong = ULong.max

    // Function pointer types, in CK_FUNCTION_LIST order.
    typealias F_Initialize = @convention(c) (UnsafeMutableRawPointer?) -> RV
    typealias F_Finalize = @convention(c) (UnsafeMutableRawPointer?) -> RV
    typealias F_GetInfo = @convention(c) (UnsafeMutableRawPointer?) -> RV
    typealias F_GetSlotList = @convention(c) (UInt8, UnsafeMutablePointer<ULong>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_GetSlotInfo = @convention(c) (ULong, UnsafeMutableRawPointer?) -> RV
    typealias F_GetTokenInfo = @convention(c) (ULong, UnsafeMutableRawPointer?) -> RV
    typealias F_GetMechanismList = @convention(c) (ULong, UnsafeMutablePointer<ULong>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_OpenSession = @convention(c) (ULong, ULong, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Handle>?) -> RV
    typealias F_CloseSession = @convention(c) (Handle) -> RV
    typealias F_Login = @convention(c) (Handle, ULong, UnsafeMutablePointer<UInt8>?, ULong) -> RV
    typealias F_GetAttributeValue = @convention(c) (Handle, Handle, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_FindObjectsInit = @convention(c) (Handle, UnsafeMutableRawPointer?, ULong) -> RV
    typealias F_FindObjects = @convention(c) (Handle, UnsafeMutablePointer<Handle>?, ULong, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_FindObjectsFinal = @convention(c) (Handle) -> RV
    typealias F_SignInit = @convention(c) (Handle, UnsafeMutableRawPointer?, Handle) -> RV
    typealias F_Sign = @convention(c) (Handle, UnsafeMutablePointer<UInt8>?, ULong, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_SignUpdate = @convention(c) (Handle, UnsafeMutablePointer<UInt8>?, ULong) -> RV
    typealias F_SignFinal = @convention(c) (Handle, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<ULong>?) -> RV
    typealias F_VerifyInit = @convention(c) (Handle, UnsafeMutableRawPointer?, Handle) -> RV
    typealias F_Verify = @convention(c) (Handle, UnsafeMutablePointer<UInt8>?, ULong, UnsafeMutablePointer<UInt8>?, ULong) -> RV

    let modulePath: String
    let keyLabel: String?
    let log: (String) -> Void
    private var dl: UnsafeMutableRawPointer?
    private var list: UnsafeRawPointer!

    init(modulePath: String, keyLabel: String?, log: @escaping (String) -> Void) {
        self.modulePath = modulePath; self.keyLabel = keyLabel; self.log = log
    }
    deinit { if let dl { dlclose(dl) } }

    /// Function pointer `i` (0 = C_Initialize) of the CK_FUNCTION_LIST: 2-byte version, padded to 8.
    private func fn<T>(_ i: Int, _: T.Type) -> T {
        unsafeBitCast(list.load(fromByteOffset: 8 + 8 * i, as: UnsafeRawPointer.self), to: T.self)
    }
    private func check(_ rv: RV, _ what: String) throws {
        if rv != Self.CKR_OK { throw Failure("\(what) returned CKR 0x\(String(rv, radix: 16))") }
    }
    private func field(_ buf: UnsafeMutableRawPointer, _ offset: Int, _ len: Int) -> String {
        let d = Data(bytes: buf + offset, count: len)
        return String(decoding: d, as: UTF8.self).trimmingCharacters(in: .whitespaces.union(CharacterSet(charactersIn: "\0")))
    }

    /// A CK_ATTRIBUTE array (24 bytes each: type, pValue, ulValueLen) with owned value buffers.
    final class Template {
        let count: Int
        let base: UnsafeMutableRawPointer
        private var owned: [UnsafeMutableRawPointer] = []
        init(_ items: [(ULong, Data?)]) {
            count = items.count
            base = UnsafeMutableRawPointer.allocate(byteCount: max(1, 24 * items.count), alignment: 8)
            for (i, (type, value)) in items.enumerated() {
                base.storeBytes(of: type, toByteOffset: 24 * i, as: ULong.self)
                if let value {
                    let p = UnsafeMutableRawPointer.allocate(byteCount: max(1, value.count), alignment: 8)
                    value.withUnsafeBytes { if $0.count > 0 { p.copyMemory(from: $0.baseAddress!, byteCount: $0.count) } }
                    owned.append(p)
                    base.storeBytes(of: p, toByteOffset: 24 * i + 8, as: UnsafeMutableRawPointer?.self)
                    base.storeBytes(of: ULong(value.count), toByteOffset: 24 * i + 16, as: ULong.self)
                } else {
                    base.storeBytes(of: nil, toByteOffset: 24 * i + 8, as: UnsafeMutableRawPointer?.self)
                    base.storeBytes(of: 0, toByteOffset: 24 * i + 16, as: ULong.self)
                }
            }
        }
        deinit { owned.forEach { $0.deallocate() }; base.deallocate() }
        func len(_ i: Int) -> ULong { base.load(fromByteOffset: 24 * i + 16, as: ULong.self) }
        func allocate(_ i: Int, _ size: Int) {
            let p = UnsafeMutableRawPointer.allocate(byteCount: max(1, size), alignment: 8)
            owned.append(p)
            base.storeBytes(of: p, toByteOffset: 24 * i + 8, as: UnsafeMutableRawPointer?.self)
            base.storeBytes(of: ULong(size), toByteOffset: 24 * i + 16, as: ULong.self)
        }
        func setLen(_ i: Int, _ n: ULong) { base.storeBytes(of: n, toByteOffset: 24 * i + 16, as: ULong.self) }
        func data(_ i: Int) -> Data {
            guard let p = base.load(fromByteOffset: 24 * i + 8, as: UnsafeMutableRawPointer?.self) else { return Data() }
            return Data(bytes: p, count: Int(len(i)))
        }
    }

    struct KeyObject {
        var label: String
        var id: Data
        var point: Data       // 65-byte x963 point, unwrapped from the CKA_EC_POINT OCTET STRING
        var params: Data
        var publicHandle: Handle
        var privateHandle: Handle?
    }

    private func mechanism(_ m: ULong) -> UnsafeMutableRawPointer {
        let p = UnsafeMutableRawPointer.allocate(byteCount: 24, alignment: 8)
        p.storeBytes(of: m, toByteOffset: 0, as: ULong.self)
        p.storeBytes(of: nil, toByteOffset: 8, as: UnsafeMutableRawPointer?.self)
        p.storeBytes(of: 0, toByteOffset: 16, as: ULong.self)
        return p
    }

    // MARK: flow

    func run() throws {
        try load()
        let initialize = fn(0, F_Initialize.self), finalize = fn(1, F_Finalize.self)
        try check(initialize(nil), "C_Initialize")
        defer { _ = finalize(nil) }
        try describeToken()
        let session = try openSession()
        defer { _ = fn(13, F_CloseSession.self)(session) }
        let keys = try enumerateKeys(session)
        guard !keys.isEmpty else { throw Failure("no enclave signing keys exposed by the token (create one with `safeski keygen NAME`)") }
        let chosen: KeyObject
        if let keyLabel {
            guard let k = keys.first(where: { $0.label == keyLabel }) else { throw Failure("no key labelled '\(keyLabel)' on the token") }
            chosen = k
        } else {
            chosen = keys[0]
        }
        guard let priv = chosen.privateHandle else { throw Failure("key '\(chosen.label)' has no private-key object") }
        let pub = try P256.Signing.PublicKey(x963Representation: chosen.point)
        try checkAttributeSemantics(session, priv)
        try signAndVerify(session, priv: priv, pubHandle: chosen.publicHandle, pub: pub, label: chosen.label)
    }

    private func load() throws {
        // The module statically embeds SafeskiCore, and so does this binary. Loading both makes
        // the Objective-C runtime print a "class implemented in both" line per Swift class. That
        // is specific to loading the module into safeski itself (third-party consumers do not
        // embed SafeskiCore) and harmless here because nothing crosses the C boundary as an
        // object, so silence stderr for the dlopen unless debugging.
        let quiet = ProcessInfo.processInfo.environment["SAFESKI_PKCS11_DEBUG"] != "1"
        let savedErr = quiet ? dup(STDERR_FILENO) : -1
        if quiet, let null = fopen("/dev/null", "w") { dup2(fileno(null), STDERR_FILENO); fclose(null) }
        let h = dlopen(modulePath, RTLD_NOW | RTLD_LOCAL)
        let err = h == nil ? String(cString: dlerror()) : ""
        if savedErr >= 0 { dup2(savedErr, STDERR_FILENO); close(savedErr) }
        guard let h else { throw Failure("dlopen \(modulePath): \(err)") }
        dl = h
        guard let sym = dlsym(h, "C_GetFunctionList") else { throw Failure("C_GetFunctionList not exported by \(modulePath)") }
        typealias F_GetFunctionList = @convention(c) (UnsafeMutablePointer<UnsafeRawPointer?>?) -> RV
        var p: UnsafeRawPointer?
        try check(unsafeBitCast(sym, to: F_GetFunctionList.self)(&p), "C_GetFunctionList")
        guard let p else { throw Failure("C_GetFunctionList returned NULL") }
        list = p
        let major = p.load(fromByteOffset: 0, as: UInt8.self), minor = p.load(fromByteOffset: 1, as: UInt8.self)
        log("module:   \(modulePath)")
        log("cryptoki: v\(major).\(minor)")
    }

    private func describeToken() throws {
        let info = UnsafeMutableRawPointer.allocate(byteCount: 88, alignment: 8); defer { info.deallocate() }
        info.initializeMemory(as: UInt8.self, repeating: 0, count: 88)
        try check(fn(2, F_GetInfo.self)(info), "C_GetInfo")
        log("library:  \(field(info, 48, 32)) (\(field(info, 2, 32)))")

        var count: ULong = 0
        try check(fn(4, F_GetSlotList.self)(1, nil, &count), "C_GetSlotList(size)")
        guard count >= 1 else { throw Failure("no slots") }
        var slots = [ULong](repeating: 0, count: Int(count))
        try check(fn(4, F_GetSlotList.self)(1, &slots, &count), "C_GetSlotList")
        log("slots:    \(slots)")

        let slot = UnsafeMutableRawPointer.allocate(byteCount: 112, alignment: 8); defer { slot.deallocate() }
        try check(fn(5, F_GetSlotInfo.self)(slots[0], slot), "C_GetSlotInfo")
        log("slot:     \(field(slot, 0, 64))")

        let tok = UnsafeMutableRawPointer.allocate(byteCount: 208, alignment: 8); defer { tok.deallocate() }
        try check(fn(6, F_GetTokenInfo.self)(slots[0], tok), "C_GetTokenInfo")
        let flags = tok.load(fromByteOffset: 96, as: ULong.self)
        log("token:    label=\"\(field(tok, 0, 32))\" manufacturer=\"\(field(tok, 32, 32))\" model=\"\(field(tok, 64, 16))\" serial=\(field(tok, 80, 16)) flags=0x\(String(flags, radix: 16))")

        var n: ULong = 0
        try check(fn(7, F_GetMechanismList.self)(slots[0], nil, &n), "C_GetMechanismList(size)")
        var mechs = [ULong](repeating: 0, count: Int(n))
        try check(fn(7, F_GetMechanismList.self)(slots[0], &mechs, &n), "C_GetMechanismList")
        let names = mechs.map { m -> String in
            switch m { case Self.CKM_ECDSA: return "CKM_ECDSA"; case Self.CKM_ECDSA_SHA256: return "CKM_ECDSA_SHA256"; default: return "0x" + String(m, radix: 16) }
        }
        log("mechs:    \(names.joined(separator: ", "))")
        guard mechs.contains(Self.CKM_ECDSA), mechs.contains(Self.CKM_ECDSA_SHA256) else { throw Failure("expected CKM_ECDSA and CKM_ECDSA_SHA256") }
    }

    private func openSession() throws -> Handle {
        var s: Handle = 0
        try check(fn(12, F_OpenSession.self)(0, Self.CKF_SERIAL_SESSION, nil, nil, &s), "C_OpenSession")
        return s
    }

    private func findAll(_ session: Handle, _ template: Template) throws -> [Handle] {
        try check(fn(26, F_FindObjectsInit.self)(session, template.base, ULong(template.count)), "C_FindObjectsInit")
        var out: [Handle] = []
        var batch = [Handle](repeating: 0, count: 8)
        while true {
            var n: ULong = 0
            try check(fn(27, F_FindObjects.self)(session, &batch, 8, &n), "C_FindObjects")
            if n == 0 { break }
            out.append(contentsOf: batch[0..<Int(n)])
        }
        try check(fn(28, F_FindObjectsFinal.self)(session), "C_FindObjectsFinal")
        return out
    }

    /// Two-step attribute read: size query, then fetch.
    private func attributes(_ session: Handle, _ obj: Handle, _ types: [ULong]) throws -> [Data] {
        let t = Template(types.map { ($0, nil) })
        try check(fn(24, F_GetAttributeValue.self)(session, obj, t.base, ULong(t.count)), "C_GetAttributeValue(size)")
        for i in 0..<t.count {
            let n = t.len(i)
            guard n != Self.CK_UNAVAILABLE_INFORMATION else { throw Failure("attribute 0x\(String(types[i], radix: 16)) unavailable on object \(obj)") }
            t.allocate(i, Int(n))
        }
        try check(fn(24, F_GetAttributeValue.self)(session, obj, t.base, ULong(t.count)), "C_GetAttributeValue")
        return (0..<t.count).map { t.data($0) }
    }

    private func enumerateKeys(_ session: Handle) throws -> [KeyObject] {
        func ulong(_ v: ULong) -> Data { withUnsafeBytes(of: v) { Data($0) } }
        let pubs = try findAll(session, Template([(Self.CKA_CLASS, ulong(Self.CKO_PUBLIC_KEY))]))
        var keys: [KeyObject] = []
        for h in pubs {
            let a = try attributes(session, h, [Self.CKA_LABEL, Self.CKA_ID, Self.CKA_EC_POINT, Self.CKA_EC_PARAMS, Self.CKA_KEY_TYPE])
            guard a[4].withUnsafeBytes({ $0.load(as: ULong.self) }) == Self.CKK_EC else { continue }
            guard a[2].count == 67, a[2][0] == 0x04, a[2][1] == 65 else { throw Failure("CKA_EC_POINT is not a DER OCTET STRING of a 65-byte point") }
            guard a[3] == Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) else { throw Failure("CKA_EC_PARAMS is not prime256v1") }
            let point = a[2].suffix(65)
            guard Data(SHA256.hash(data: point)).prefix(20) == a[1] else { throw Failure("CKA_ID is not SHA-256(point)[0..<20]") }
            keys.append(KeyObject(label: String(decoding: a[0], as: UTF8.self), id: a[1], point: Data(point), params: a[3], publicHandle: h))
        }
        // Pair each public key with the private key carrying the same CKA_ID.
        for i in keys.indices {
            let privs = try findAll(session, Template([(Self.CKA_CLASS, ulong(Self.CKO_PRIVATE_KEY)), (Self.CKA_ID, keys[i].id)]))
            keys[i].privateHandle = privs.first
            let pk = try P256.Signing.PublicKey(x963Representation: keys[i].point)
            log("object:   \(keys[i].label)  id=\(keys[i].id.map { String(format: "%02x", $0) }.joined())  pub=#\(keys[i].publicHandle) priv=\(privs.first.map { "#\($0)" } ?? "-")")
            log("          \(try pk.encoded(.ssh, comment: "safeski:\(keys[i].label)"))")
        }
        return keys
    }

    private func checkAttributeSemantics(_ session: Handle, _ priv: Handle) throws {
        let get = fn(24, F_GetAttributeValue.self)
        // CKA_VALUE on a private key is sensitive.
        let t1 = Template([(Self.CKA_VALUE, nil)])
        guard get(session, priv, t1.base, 1) == Self.CKR_ATTRIBUTE_SENSITIVE, t1.len(0) == Self.CK_UNAVAILABLE_INFORMATION else {
            throw Failure("CKA_VALUE on private key should be CKR_ATTRIBUTE_SENSITIVE")
        }
        // Too-small buffer reports CKR_BUFFER_TOO_SMALL.
        let t2 = Template([(Self.CKA_LABEL, Data(count: 1))])
        guard get(session, priv, t2.base, 1) == Self.CKR_BUFFER_TOO_SMALL else { throw Failure("1-byte CKA_LABEL buffer should be CKR_BUFFER_TOO_SMALL") }
        let t3 = Template([(Self.CKA_SIGN, nil), (Self.CKA_SENSITIVE, nil)])
        try check(get(session, priv, t3.base, 2), "C_GetAttributeValue(size)")
        t3.allocate(0, 1); t3.allocate(1, 1)
        try check(get(session, priv, t3.base, 2), "C_GetAttributeValue")
        guard t3.data(0) == Data([1]), t3.data(1) == Data([1]) else { throw Failure("private key must have CKA_SIGN and CKA_SENSITIVE true") }
        log("attrs:    sensitive/buffer-too-small/bool semantics ok")
    }

    private func signAndVerify(_ session: Handle, priv: Handle, pubHandle: Handle, pub: P256.Signing.PublicKey, label: String) throws {
        let message = Data("safeski pkcs11 test \(Date().timeIntervalSince1970)".utf8)
        let digest = Data(SHA256.hash(data: message))

        // CKM_ECDSA over the digest: size query, then sign.
        let m1 = mechanism(Self.CKM_ECDSA); defer { m1.deallocate() }
        try check(fn(42, F_SignInit.self)(session, m1, priv), "C_SignInit(ECDSA)")
        var input = [UInt8](digest)
        var sigLen: ULong = 0
        try check(fn(43, F_Sign.self)(session, &input, 32, nil, &sigLen), "C_Sign(size)")
        guard sigLen == 64 else { throw Failure("C_Sign size query returned \(sigLen), want 64") }
        var sig = [UInt8](repeating: 0, count: 64)
        var small: ULong = 10
        guard fn(43, F_Sign.self)(session, &input, 32, &sig, &small) == Self.CKR_BUFFER_TOO_SMALL, small == 64 else {
            throw Failure("C_Sign with a 10-byte buffer should be CKR_BUFFER_TOO_SMALL")
        }
        try check(fn(43, F_Sign.self)(session, &input, 32, &sig, &sigLen), "C_Sign(ECDSA)")
        let s1 = try P256.Signing.ECDSASignature(rawRepresentation: Data(sig))
        guard pub.isValidSignature(s1, for: try PrehashedSHA256Digest(digest)) else { throw Failure("CKM_ECDSA signature does not verify") }
        log("sign:     CKM_ECDSA over SHA-256 digest with '\(label)' -> 64-byte r||s, verified with CryptoKit")

        // CKM_ECDSA_SHA256 over the message using the multi-part API.
        let m2 = mechanism(Self.CKM_ECDSA_SHA256); defer { m2.deallocate() }
        try check(fn(42, F_SignInit.self)(session, m2, priv), "C_SignInit(ECDSA_SHA256)")
        var msg = [UInt8](message)
        let half = msg.count / 2
        try msg.withUnsafeMutableBufferPointer { b in
            try check(fn(44, F_SignUpdate.self)(session, b.baseAddress, ULong(half)), "C_SignUpdate")
            try check(fn(44, F_SignUpdate.self)(session, b.baseAddress! + half, ULong(b.count - half)), "C_SignUpdate")
        }
        var sig2 = [UInt8](repeating: 0, count: 64)
        var sigLen2: ULong = 64
        try check(fn(45, F_SignFinal.self)(session, &sig2, &sigLen2), "C_SignFinal")
        let s2 = try P256.Signing.ECDSASignature(rawRepresentation: Data(sig2))
        guard pub.isValidSignature(s2, for: SHA256.hash(data: message)) else { throw Failure("CKM_ECDSA_SHA256 signature does not verify") }
        log("sign:     CKM_ECDSA_SHA256 over message (SignUpdate x2 + SignFinal) -> verified with CryptoKit")

        // C_Verify through the module with the public-key object.
        try check(fn(48, F_VerifyInit.self)(session, m1, pubHandle), "C_VerifyInit")
        try check(fn(49, F_Verify.self)(session, &input, 32, &sig, 64), "C_Verify")
        try check(fn(48, F_VerifyInit.self)(session, m1, pubHandle), "C_VerifyInit")
        sig[5] ^= 0xFF
        guard fn(49, F_Verify.self)(session, &input, 32, &sig, 64) == Self.CKR_SIGNATURE_INVALID else { throw Failure("tampered signature should be CKR_SIGNATURE_INVALID") }
        log("verify:   C_Verify accepts the signature and rejects a tampered one")
    }
}
