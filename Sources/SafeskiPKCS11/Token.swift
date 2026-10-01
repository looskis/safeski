import CryptoKit
import Foundation
import SafeskiCore
import CPKCS11

/// A Cryptoki return value carried as a Swift error so the entry-point wrapper can
/// turn it back into a CK_RV at the C boundary.
struct CKError: Error {
    let rv: CK_RV
    init(_ rv: CK_RV) { self.rv = rv }
}

func mapError(_ error: Error) -> CK_RV {
    if let e = error as? CKError { return e.rv }
    guard let e = error as? SafeskiError else { return CKR_GENERAL_ERROR }
    switch e {
    case .denied, .policy: return CKR_FUNCTION_REJECTED
    case .approvalFailed: return CKR_FUNCTION_CANCELED
    case .rpc, .io: return CKR_DEVICE_REMOVED
    case .notFound: return CKR_KEY_HANDLE_INVALID
    case .invalidFormat: return CKR_DATA_INVALID
    case .enclaveUnavailable: return CKR_DEVICE_ERROR
    case .unsupported: return CKR_FUNCTION_NOT_SUPPORTED
    case .alreadyExists: return CKR_GENERAL_ERROR
    }
}

enum Debug {
    static let enabled: Bool = {
        guard let v = getenv("SAFESKI_PKCS11_DEBUG") else { return false }
        return String(cString: v) == "1"
    }()
    static func log(_ msg: @autoclosure () -> String) {
        guard enabled else { return }
        FileHandle.standardError.write(Data("[safeski-pkcs11] \(msg())\n".utf8))
    }
}

// MARK: - Attribute values

enum AttrValue {
    case ulong(CK_ULONG)
    case bool(Bool)
    case bytes(Data)
    case ulongs([CK_ULONG])

    var bytes: Data {
        switch self {
        case .ulong(let v): return withUnsafeBytes(of: v) { Data($0) }
        case .bool(let b): return Data([b ? CK_BYTE(CK_TRUE) : CK_BYTE(CK_FALSE)])
        case .bytes(let d): return d
        case .ulongs(let vs): return vs.withUnsafeBytes { Data($0) }
        }
    }
}

enum DER {
    /// id-ecPublicKey parameters for prime256v1: OBJECT IDENTIFIER 1.2.840.10045.3.1.7
    static let prime256v1Params = Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
    /// OCTET STRING wrapping an uncompressed (x963) EC point.
    static func octetString(_ d: Data) -> Data {
        precondition(d.count < 128)
        return Data([0x04, UInt8(d.count)]) + d
    }
}

// MARK: - Objects

final class P11Object {
    let handle: CK_OBJECT_HANDLE
    let cls: CK_OBJECT_CLASS
    let keyName: String
    /// x963 public point.
    let publicKey: Data
    let attrs: [CK_ATTRIBUTE_TYPE: AttrValue]
    /// Attribute types that exist but may never be read (CKR_ATTRIBUTE_SENSITIVE).
    let sensitive: Set<CK_ATTRIBUTE_TYPE>

    init(handle: CK_OBJECT_HANDLE, cls: CK_OBJECT_CLASS, key: KeySummary) {
        self.handle = handle
        self.cls = cls
        self.keyName = key.name
        self.publicKey = key.publicKey
        let id = Data(SHA256.hash(data: key.publicKey)).prefix(20)
        var a: [CK_ATTRIBUTE_TYPE: AttrValue] = [
            CKA_CLASS: .ulong(cls),
            CKA_TOKEN: .bool(true),
            CKA_PRIVATE: .bool(false),
            CKA_MODIFIABLE: .bool(false),
            CKA_COPYABLE: .bool(false),
            CKA_DESTROYABLE: .bool(false),
            CKA_LABEL: .bytes(Data(key.name.utf8)),
            CKA_ID: .bytes(id),
            CKA_KEY_TYPE: .ulong(CKK_EC),
            CKA_EC_PARAMS: .bytes(DER.prime256v1Params),
            CKA_EC_POINT: .bytes(DER.octetString(key.publicKey)),
            CKA_LOCAL: .bool(true),
            CKA_KEY_GEN_MECHANISM: .ulong(CKM_EC_KEY_PAIR_GEN),
            CKA_ALLOWED_MECHANISMS: .ulongs([CKM_ECDSA, CKM_ECDSA_SHA256]),
            CKA_SUBJECT: .bytes(Data()),
            CKA_START_DATE: .bytes(Data()),
            CKA_END_DATE: .bytes(Data()),
            CKA_DERIVE: .bool(false),
        ]
        if cls == CKO_PUBLIC_KEY {
            a[CKA_VERIFY] = .bool(true)
            a[CKA_VERIFY_RECOVER] = .bool(false)
            a[CKA_ENCRYPT] = .bool(false)
            a[CKA_WRAP] = .bool(false)
            a[CKA_TRUSTED] = .bool(false)
            sensitive = []
        } else {
            a[CKA_SIGN] = .bool(true)
            a[CKA_SIGN_RECOVER] = .bool(false)
            a[CKA_DECRYPT] = .bool(false)
            a[CKA_UNWRAP] = .bool(false)
            a[CKA_SENSITIVE] = .bool(true)
            a[CKA_EXTRACTABLE] = .bool(false)
            a[CKA_ALWAYS_SENSITIVE] = .bool(true)
            a[CKA_NEVER_EXTRACTABLE] = .bool(true)
            a[CKA_ALWAYS_AUTHENTICATE] = .bool(false)
            a[CKA_WRAP_WITH_TRUSTED] = .bool(false)
            sensitive = [CKA_VALUE]
        }
        attrs = a
    }

    func bool(_ type: CK_ATTRIBUTE_TYPE) -> Bool {
        if case .bool(let b)? = attrs[type] { return b }
        return false
    }

    /// Template matching for C_FindObjects: every template attribute must exist on the
    /// object and compare byte-for-byte equal.
    func matches(_ template: UnsafeMutablePointer<CK_ATTRIBUTE>?, _ count: CK_ULONG) -> Bool {
        guard let template, count > 0 else { return true }
        for i in 0..<Int(count) {
            let t = template[i]
            guard let v = attrs[t.type], !sensitive.contains(t.type) else { return false }
            let want: Data
            if let p = t.pValue, t.ulValueLen > 0 { want = Data(bytes: p, count: Int(t.ulValueLen)) } else { want = Data() }
            if v.bytes != want { return false }
        }
        return true
    }
}

// MARK: - Sessions

struct SignOp {
    let mechanism: CK_MECHANISM_TYPE
    let keyName: String
    var data = Data()
}

struct VerifyOp {
    let mechanism: CK_MECHANISM_TYPE
    let publicKey: Data
    var data = Data()
}

final class Session {
    let handle: CK_SESSION_HANDLE
    let flags: CK_FLAGS
    var find: (handles: [CK_OBJECT_HANDLE], index: Int)?
    var sign: SignOp?
    var verify: VerifyOp?
    init(handle: CK_SESSION_HANDLE, flags: CK_FLAGS) { self.handle = handle; self.flags = flags }
    var isReadWrite: Bool { flags & CKF_RW_SESSION != 0 }
}

// MARK: - Token state

/// All module state. Every Cryptoki entry point takes `lock` for its whole duration.
final class Token {
    static let shared = Token()
    let lock = NSLock()

    static let slotID: CK_SLOT_ID = 0
    static let mechanisms: [CK_MECHANISM_TYPE] = [CKM_ECDSA, CKM_ECDSA_SHA256]

    var initialized = false
    var backend: RemoteBackend?
    var deviceID = ""
    var loggedIn = false
    var sessions: [CK_SESSION_HANDLE: Session] = [:]
    var nextSession: CK_SESSION_HANDLE = 1
    var objects: [CK_OBJECT_HANDLE: P11Object] = [:]
    /// Key name -> (public handle, private handle). Kept across refreshes so handles stay stable.
    var handlesByKey: [String: (pub: CK_OBJECT_HANDLE, priv: CK_OBJECT_HANDLE)] = [:]
    var nextObject: CK_OBJECT_HANDLE = 1

    private init() {}

    // MARK: lifecycle

    static func socketPath() -> String {
        if let v = getenv("SAFESKI_SOCKET"), strlen(v) > 0 { return String(cString: v) }
        return SafeskiPaths.default.agentSocket.path
    }

    func initialize(args: UnsafeMutableRawPointer?) throws {
        if initialized { throw CKError(CKR_CRYPTOKI_ALREADY_INITIALIZED) }
        if let args {
            let a = args.assumingMemoryBound(to: CK_C_INITIALIZE_ARGS.self).pointee
            if a.pReserved != nil { throw CKError(CKR_ARGUMENTS_BAD) }
            // We always use our own OS lock; both "application supplies no mutexes" and
            // "OS locking OK" are satisfied by that. Partial mutex sets are an error per spec.
            let supplied = [a.CreateMutex != nil, a.DestroyMutex != nil, a.LockMutex != nil, a.UnlockMutex != nil]
            if supplied.contains(true) && supplied.contains(false) { throw CKError(CKR_ARGUMENTS_BAD) }
        }
        let token = getenv("SAFESKI_TOKEN").map { String(cString: $0) }
        let path = Token.socketPath()
        backend = RemoteBackend(socketPath: path, token: (token?.isEmpty ?? true) ? nil : token)
        initialized = true
        loggedIn = false
        sessions = [:]
        objects = [:]
        handlesByKey = [:]
        nextObject = 1
        nextSession = 1
        Debug.log("C_Initialize: agent socket \(path)")
        // Best effort: the token is "present" even if the agent is down; later calls report
        // CKR_DEVICE_REMOVED when they actually need it.
        do {
            deviceID = try backend!.status().deviceID
            try refresh()
        } catch {
            Debug.log("C_Initialize: agent unavailable: \(error)")
        }
    }

    func finalize() {
        sessions = [:]
        objects = [:]
        backend = nil
        loggedIn = false
        initialized = false
    }

    func requireInitialized() throws {
        if !initialized { throw CKError(CKR_CRYPTOKI_NOT_INITIALIZED) }
    }

    func requireBackend() throws -> RemoteBackend {
        try requireInitialized()
        guard let b = backend else { throw CKError(CKR_DEVICE_REMOVED) }
        return b
    }

    /// Re-read the agent's key list and rebuild the object table, keeping handles stable.
    func refresh() throws {
        let b = try requireBackend()
        let keys = try b.listKeys().filter { $0.kind == .enclaveSigning }
        var fresh: [CK_OBJECT_HANDLE: P11Object] = [:]
        for k in keys {
            let h: (pub: CK_OBJECT_HANDLE, priv: CK_OBJECT_HANDLE)
            if let existing = handlesByKey[k.name] {
                h = existing
            } else {
                h = (nextObject, nextObject + 1)
                nextObject += 2
                handlesByKey[k.name] = h
            }
            fresh[h.pub] = P11Object(handle: h.pub, cls: CKO_PUBLIC_KEY, key: k)
            fresh[h.priv] = P11Object(handle: h.priv, cls: CKO_PRIVATE_KEY, key: k)
        }
        objects = fresh
        Debug.log("refresh: \(keys.count) enclave signing key(s), \(objects.count) objects")
    }

    // MARK: sessions

    func session(_ h: CK_SESSION_HANDLE) throws -> Session {
        try requireInitialized()
        guard let s = sessions[h] else { throw CKError(CKR_SESSION_HANDLE_INVALID) }
        return s
    }

    func openSession(slot: CK_SLOT_ID, flags: CK_FLAGS) throws -> CK_SESSION_HANDLE {
        try requireInitialized()
        guard slot == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        guard flags & CKF_SERIAL_SESSION != 0 else { throw CKError(CKR_SESSION_PARALLEL_NOT_SUPPORTED) }
        let h = nextSession
        nextSession += 1
        sessions[h] = Session(handle: h, flags: flags)
        return h
    }

    func closeSession(_ h: CK_SESSION_HANDLE) throws {
        _ = try session(h)
        sessions[h] = nil
        if sessions.isEmpty { loggedIn = false }
    }

    func closeAllSessions(slot: CK_SLOT_ID) throws {
        try requireInitialized()
        guard slot == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        sessions = [:]
        loggedIn = false
    }

    func state(of s: Session) -> CK_STATE {
        switch (s.isReadWrite, loggedIn) {
        case (false, false): return CKS_RO_PUBLIC_SESSION
        case (false, true): return CKS_RO_USER_FUNCTIONS
        case (true, false): return CKS_RW_PUBLIC_SESSION
        case (true, true): return CKS_RW_USER_FUNCTIONS
        }
    }

    func login(_ h: CK_SESSION_HANDLE, userType: CK_USER_TYPE) throws {
        _ = try session(h)
        switch userType {
        case CKU_USER:
            if loggedIn { throw CKError(CKR_USER_ALREADY_LOGGED_IN) }
            loggedIn = true
        case CKU_CONTEXT_SPECIFIC:
            break // no per-operation authentication: the agent's policy decides
        case CKU_SO:
            throw CKError(CKR_USER_TYPE_INVALID)
        default:
            throw CKError(CKR_USER_TYPE_INVALID)
        }
    }

    func logout(_ h: CK_SESSION_HANDLE) throws {
        _ = try session(h)
        guard loggedIn else { throw CKError(CKR_USER_NOT_LOGGED_IN) }
        loggedIn = false
    }

    // MARK: objects

    func object(_ h: CK_OBJECT_HANDLE) throws -> P11Object {
        guard let o = objects[h] else { throw CKError(CKR_OBJECT_HANDLE_INVALID) }
        return o
    }

    func findInit(_ h: CK_SESSION_HANDLE, template: UnsafeMutablePointer<CK_ATTRIBUTE>?, count: CK_ULONG) throws {
        let s = try session(h)
        if s.find != nil { throw CKError(CKR_OPERATION_ACTIVE) }
        if count > 0 && template == nil { throw CKError(CKR_ARGUMENTS_BAD) }
        try refresh()
        let matches = objects.values.filter { $0.matches(template, count) }.map(\.handle).sorted()
        s.find = (matches, 0)
        Debug.log("C_FindObjectsInit: \(count) template attr(s) -> \(matches.count) match(es)")
    }

    func find(_ h: CK_SESSION_HANDLE, out: UnsafeMutablePointer<CK_OBJECT_HANDLE>?, max: CK_ULONG, count: UnsafeMutablePointer<CK_ULONG>?) throws {
        let s = try session(h)
        guard var f = s.find else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        guard let count else { throw CKError(CKR_ARGUMENTS_BAD) }
        if max > 0 && out == nil { throw CKError(CKR_ARGUMENTS_BAD) }
        var n = 0
        while n < Int(max), f.index < f.handles.count {
            out![n] = f.handles[f.index]
            n += 1; f.index += 1
        }
        s.find = f
        count.pointee = CK_ULONG(n)
    }

    func findFinal(_ h: CK_SESSION_HANDLE) throws {
        let s = try session(h)
        guard s.find != nil else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        s.find = nil
    }

    /// Standard C_GetAttributeValue semantics, applied per attribute; the first failure's code
    /// is returned after every attribute has been processed.
    func getAttributes(_ h: CK_SESSION_HANDLE, object oh: CK_OBJECT_HANDLE,
                       template: UnsafeMutablePointer<CK_ATTRIBUTE>?, count: CK_ULONG) throws {
        _ = try session(h)
        let o = try object(oh)
        if count == 0 { return }
        guard let template else { throw CKError(CKR_ARGUMENTS_BAD) }
        var rv = CKR_OK
        for i in 0..<Int(count) {
            let type = template[i].type
            if o.sensitive.contains(type) {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION
                if rv == CKR_OK { rv = CKR_ATTRIBUTE_SENSITIVE }
                continue
            }
            guard let v = o.attrs[type] else {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION
                if rv == CKR_OK { rv = CKR_ATTRIBUTE_TYPE_INVALID }
                continue
            }
            let bytes = v.bytes
            guard let p = template[i].pValue else {
                template[i].ulValueLen = CK_ULONG(bytes.count)
                continue
            }
            if template[i].ulValueLen < CK_ULONG(bytes.count) {
                template[i].ulValueLen = CK_UNAVAILABLE_INFORMATION
                if rv == CKR_OK { rv = CKR_BUFFER_TOO_SMALL }
                continue
            }
            bytes.withUnsafeBytes { src in
                if src.count > 0 { p.copyMemory(from: src.baseAddress!, byteCount: src.count) }
            }
            template[i].ulValueLen = CK_ULONG(bytes.count)
        }
        if rv != CKR_OK { throw CKError(rv) }
    }

    // MARK: sign

    private func checkMechanism(_ m: UnsafeMutablePointer<CK_MECHANISM>?) throws -> CK_MECHANISM_TYPE {
        guard let m else { throw CKError(CKR_ARGUMENTS_BAD) }
        let mech = m.pointee
        guard Token.mechanisms.contains(mech.mechanism) else { throw CKError(CKR_MECHANISM_INVALID) }
        if mech.ulParameterLen != 0 { throw CKError(CKR_MECHANISM_PARAM_INVALID) }
        return mech.mechanism
    }

    func signInit(_ h: CK_SESSION_HANDLE, mechanism: UnsafeMutablePointer<CK_MECHANISM>?, key: CK_OBJECT_HANDLE) throws {
        let s = try session(h)
        if s.sign != nil { throw CKError(CKR_OPERATION_ACTIVE) }
        let m = try checkMechanism(mechanism)
        guard let o = objects[key] else { throw CKError(CKR_KEY_HANDLE_INVALID) }
        guard o.cls == CKO_PRIVATE_KEY, o.bool(CKA_SIGN) else { throw CKError(CKR_KEY_FUNCTION_NOT_PERMITTED) }
        s.sign = SignOp(mechanism: m, keyName: o.keyName)
    }

    func signUpdate(_ h: CK_SESSION_HANDLE, data: UnsafeMutablePointer<CK_BYTE>?, len: CK_ULONG) throws {
        let s = try session(h)
        guard s.sign != nil else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        if len > 0 {
            guard let data else { throw CKError(CKR_ARGUMENTS_BAD) }
            s.sign!.data.append(data, count: Int(len))
        }
    }

    func signFinal(_ h: CK_SESSION_HANDLE, sig: UnsafeMutablePointer<CK_BYTE>?, sigLen: UnsafeMutablePointer<CK_ULONG>?) throws {
        let s = try session(h)
        guard let op = s.sign else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        guard let sigLen else { s.sign = nil; throw CKError(CKR_ARGUMENTS_BAD) }
        let outLen: CK_ULONG = 64
        // Size query and too-small buffer both leave the operation active (spec 5.2).
        guard let sig else { sigLen.pointee = outLen; return }
        if sigLen.pointee < outLen { sigLen.pointee = outLen; throw CKError(CKR_BUFFER_TOO_SMALL) }
        // From here on the operation is consumed whatever happens.
        s.sign = nil
        let digest: Data
        switch op.mechanism {
        case CKM_ECDSA:
            guard op.data.count == 32 else { throw CKError(CKR_DATA_LEN_RANGE) }
            digest = op.data
        case CKM_ECDSA_SHA256:
            digest = Data(SHA256.hash(data: op.data))
        default:
            throw CKError(CKR_MECHANISM_INVALID)
        }
        let b = try requireBackend()
        Debug.log("sign: key=\(op.keyName) mechanism=\(String(op.mechanism, radix: 16)) input=\(op.data.count) bytes")
        let raw = try b.sign(SignParams(key: op.keyName, data: digest, digest: true, purpose: "pkcs11"))
        guard raw.count == Int(outLen) else { throw CKError(CKR_DEVICE_ERROR) }
        raw.withUnsafeBytes { src in sig.update(from: src.bindMemory(to: UInt8.self).baseAddress!, count: src.count) }
        sigLen.pointee = outLen
    }

    // MARK: verify

    func verifyInit(_ h: CK_SESSION_HANDLE, mechanism: UnsafeMutablePointer<CK_MECHANISM>?, key: CK_OBJECT_HANDLE) throws {
        let s = try session(h)
        if s.verify != nil { throw CKError(CKR_OPERATION_ACTIVE) }
        let m = try checkMechanism(mechanism)
        guard let o = objects[key] else { throw CKError(CKR_KEY_HANDLE_INVALID) }
        guard o.cls == CKO_PUBLIC_KEY, o.bool(CKA_VERIFY) else { throw CKError(CKR_KEY_FUNCTION_NOT_PERMITTED) }
        s.verify = VerifyOp(mechanism: m, publicKey: o.publicKey)
    }

    func verifyUpdate(_ h: CK_SESSION_HANDLE, data: UnsafeMutablePointer<CK_BYTE>?, len: CK_ULONG) throws {
        let s = try session(h)
        guard s.verify != nil else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        if len > 0 {
            guard let data else { throw CKError(CKR_ARGUMENTS_BAD) }
            s.verify!.data.append(data, count: Int(len))
        }
    }

    func verifyFinal(_ h: CK_SESSION_HANDLE, sig: UnsafeMutablePointer<CK_BYTE>?, sigLen: CK_ULONG) throws {
        let s = try session(h)
        guard let op = s.verify else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        s.verify = nil
        guard let sig else { throw CKError(CKR_ARGUMENTS_BAD) }
        guard sigLen == 64 else { throw CKError(CKR_SIGNATURE_LEN_RANGE) }
        let signature: P256.Signing.ECDSASignature
        let pub: P256.Signing.PublicKey
        do {
            signature = try P256.Signing.ECDSASignature(rawRepresentation: Data(bytes: sig, count: 64))
            pub = try P256.Signing.PublicKey(x963Representation: op.publicKey)
        } catch {
            throw CKError(CKR_SIGNATURE_INVALID)
        }
        let ok: Bool
        switch op.mechanism {
        case CKM_ECDSA:
            guard op.data.count == 32 else { throw CKError(CKR_DATA_LEN_RANGE) }
            ok = pub.isValidSignature(signature, for: try PrehashedSHA256Digest(op.data))
        case CKM_ECDSA_SHA256:
            ok = pub.isValidSignature(signature, for: SHA256.hash(data: op.data))
        default:
            throw CKError(CKR_MECHANISM_INVALID)
        }
        if !ok { throw CKError(CKR_SIGNATURE_INVALID) }
    }
}

// MARK: - Fixed-width string fields

/// Fills a fixed-size CK_UTF8CHAR array (imported as a tuple) with `s`, space padded, no NUL.
func setPadded<T>(_ field: inout T, _ s: String) {
    withUnsafeMutableBytes(of: &field) { buf in
        let bytes = Array(s.utf8)
        for i in 0..<buf.count { buf[i] = i < bytes.count ? bytes[i] : 0x20 }
    }
}
