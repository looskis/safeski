import Foundation
import SafeskiCore
import CPKCS11

// libsafeski-pkcs11: a PKCS#11 v2.40 module that presents the safeski agent's Secure Enclave
// signing keys as a hardware token. The only exported symbol is C_GetFunctionList; every other
// entry point is reached through the function list it returns.
//
// All entry points run under one global lock and never let a Swift error escape to C.

typealias VoidPtr = UnsafeMutableRawPointer?
typealias BytePtr = UnsafeMutablePointer<CK_BYTE>?
typealias ULongPtr = UnsafeMutablePointer<CK_ULONG>?
typealias AttrPtr = UnsafeMutablePointer<CK_ATTRIBUTE>?
typealias MechPtr = UnsafeMutablePointer<CK_MECHANISM>?
typealias ObjPtr = UnsafeMutablePointer<CK_OBJECT_HANDLE>?

/// Runs `body` under the module lock and converts any thrown error into a CK_RV.
@inline(__always)
func entry(_ name: StaticString, _ body: () throws -> Void) -> CK_RV {
    Token.shared.lock.lock()
    defer { Token.shared.lock.unlock() }
    do {
        try body()
        return CKR_OK
    } catch {
        let rv = mapError(error)
        Debug.log("\(name) -> 0x\(String(rv, radix: 16)) (\(error))")
        return rv
    }
}

@inline(__always)
func unsupported(_ name: StaticString) -> CK_RV {
    Debug.log("\(name) -> CKR_FUNCTION_NOT_SUPPORTED")
    return CKR_FUNCTION_NOT_SUPPORTED
}

// MARK: - General purpose

func sk_Initialize(_ pInitArgs: VoidPtr) -> CK_RV {
    entry("C_Initialize") { try Token.shared.initialize(args: pInitArgs) }
}

func sk_Finalize(_ pReserved: VoidPtr) -> CK_RV {
    entry("C_Finalize") {
        try Token.shared.requireInitialized()
        if pReserved != nil { throw CKError(CKR_ARGUMENTS_BAD) }
        Token.shared.finalize()
    }
}

func sk_GetInfo(_ pInfo: UnsafeMutablePointer<CK_INFO>?) -> CK_RV {
    entry("C_GetInfo") {
        try Token.shared.requireInitialized()
        guard let pInfo else { throw CKError(CKR_ARGUMENTS_BAD) }
        var info = CK_INFO()
        info.cryptokiVersion = CK_VERSION(major: 2, minor: 40)
        setPadded(&info.manufacturerID, "safeski")
        info.flags = 0
        setPadded(&info.libraryDescription, "safeski Secure Enclave PKCS#11")
        info.libraryVersion = libraryVersion
        pInfo.pointee = info
    }
}

@_cdecl("C_GetFunctionList")
public func C_GetFunctionList(_ ppFunctionList: UnsafeMutablePointer<UnsafeMutablePointer<CK_FUNCTION_LIST>?>?) -> CK_RV {
    guard let ppFunctionList else { return CKR_ARGUMENTS_BAD }
    ppFunctionList.pointee = functionListPointer
    return CKR_OK
}

// MARK: - Slot and token

func sk_GetSlotList(_ tokenPresent: CK_BBOOL, _ pSlotList: UnsafeMutablePointer<CK_SLOT_ID>?, _ pulCount: ULongPtr) -> CK_RV {
    entry("C_GetSlotList") {
        try Token.shared.requireInitialized()
        guard let pulCount else { throw CKError(CKR_ARGUMENTS_BAD) }
        guard let pSlotList else { pulCount.pointee = 1; return }
        if pulCount.pointee < 1 { pulCount.pointee = 1; throw CKError(CKR_BUFFER_TOO_SMALL) }
        pSlotList[0] = Token.slotID
        pulCount.pointee = 1
    }
}

func sk_GetSlotInfo(_ slotID: CK_SLOT_ID, _ pInfo: UnsafeMutablePointer<CK_SLOT_INFO>?) -> CK_RV {
    entry("C_GetSlotInfo") {
        try Token.shared.requireInitialized()
        guard slotID == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        guard let pInfo else { throw CKError(CKR_ARGUMENTS_BAD) }
        var info = CK_SLOT_INFO()
        setPadded(&info.slotDescription, "safeski Secure Enclave")
        setPadded(&info.manufacturerID, "safeski")
        info.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT
        info.hardwareVersion = CK_VERSION(major: 1, minor: 0)
        info.firmwareVersion = libraryVersion
        pInfo.pointee = info
    }
}

func sk_GetTokenInfo(_ slotID: CK_SLOT_ID, _ pInfo: UnsafeMutablePointer<CK_TOKEN_INFO>?) -> CK_RV {
    entry("C_GetTokenInfo") {
        let t = Token.shared
        try t.requireInitialized()
        guard slotID == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        guard let pInfo else { throw CKError(CKR_ARGUMENTS_BAD) }
        var info = CK_TOKEN_INFO()
        setPadded(&info.label, "safeski")
        setPadded(&info.manufacturerID, "safeski")
        setPadded(&info.model, "Secure Enclave")
        setPadded(&info.serialNumber, String(t.deviceID.prefix(16)))
        // Keys are not CKA_PRIVATE, so no login is required; the agent's policy gates use.
        info.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_WRITE_PROTECTED
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE
        info.ulSessionCount = CK_ULONG(t.sessions.count)
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE
        info.ulRwSessionCount = CK_ULONG(t.sessions.values.filter(\.isReadWrite).count)
        info.ulMaxPinLen = 64
        info.ulMinPinLen = 0
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION
        info.hardwareVersion = CK_VERSION(major: 1, minor: 0)
        info.firmwareVersion = libraryVersion
        setPadded(&info.utcTime, "")
        pInfo.pointee = info
    }
}

func sk_GetMechanismList(_ slotID: CK_SLOT_ID, _ pMechanismList: UnsafeMutablePointer<CK_MECHANISM_TYPE>?, _ pulCount: ULongPtr) -> CK_RV {
    entry("C_GetMechanismList") {
        try Token.shared.requireInitialized()
        guard slotID == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        guard let pulCount else { throw CKError(CKR_ARGUMENTS_BAD) }
        let mechs = Token.mechanisms
        guard let pMechanismList else { pulCount.pointee = CK_ULONG(mechs.count); return }
        if pulCount.pointee < CK_ULONG(mechs.count) {
            pulCount.pointee = CK_ULONG(mechs.count)
            throw CKError(CKR_BUFFER_TOO_SMALL)
        }
        for (i, m) in mechs.enumerated() { pMechanismList[i] = m }
        pulCount.pointee = CK_ULONG(mechs.count)
    }
}

func sk_GetMechanismInfo(_ slotID: CK_SLOT_ID, _ type: CK_MECHANISM_TYPE, _ pInfo: UnsafeMutablePointer<CK_MECHANISM_INFO>?) -> CK_RV {
    entry("C_GetMechanismInfo") {
        try Token.shared.requireInitialized()
        guard slotID == Token.slotID else { throw CKError(CKR_SLOT_ID_INVALID) }
        guard let pInfo else { throw CKError(CKR_ARGUMENTS_BAD) }
        guard Token.mechanisms.contains(type) else { throw CKError(CKR_MECHANISM_INVALID) }
        pInfo.pointee = CK_MECHANISM_INFO(
            ulMinKeySize: 256, ulMaxKeySize: 256,
            flags: CKF_HW | CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS)
    }
}

func sk_InitToken(_ slotID: CK_SLOT_ID, _ pPin: UnsafeMutablePointer<CK_UTF8CHAR>?, _ ulPinLen: CK_ULONG, _ pLabel: UnsafeMutablePointer<CK_UTF8CHAR>?) -> CK_RV {
    unsupported("C_InitToken")
}
func sk_InitPIN(_ hSession: CK_SESSION_HANDLE, _ pPin: UnsafeMutablePointer<CK_UTF8CHAR>?, _ ulPinLen: CK_ULONG) -> CK_RV {
    unsupported("C_InitPIN")
}
func sk_SetPIN(_ hSession: CK_SESSION_HANDLE, _ pOldPin: UnsafeMutablePointer<CK_UTF8CHAR>?, _ ulOldLen: CK_ULONG,
               _ pNewPin: UnsafeMutablePointer<CK_UTF8CHAR>?, _ ulNewLen: CK_ULONG) -> CK_RV {
    unsupported("C_SetPIN")
}

// MARK: - Sessions

func sk_OpenSession(_ slotID: CK_SLOT_ID, _ flags: CK_FLAGS, _ pApplication: VoidPtr, _ notify: CK_NOTIFY?,
                    _ phSession: UnsafeMutablePointer<CK_SESSION_HANDLE>?) -> CK_RV {
    entry("C_OpenSession") {
        guard let phSession else { throw CKError(CKR_ARGUMENTS_BAD) }
        phSession.pointee = try Token.shared.openSession(slot: slotID, flags: flags)
    }
}

func sk_CloseSession(_ hSession: CK_SESSION_HANDLE) -> CK_RV {
    entry("C_CloseSession") { try Token.shared.closeSession(hSession) }
}

func sk_CloseAllSessions(_ slotID: CK_SLOT_ID) -> CK_RV {
    entry("C_CloseAllSessions") { try Token.shared.closeAllSessions(slot: slotID) }
}

func sk_GetSessionInfo(_ hSession: CK_SESSION_HANDLE, _ pInfo: UnsafeMutablePointer<CK_SESSION_INFO>?) -> CK_RV {
    entry("C_GetSessionInfo") {
        let s = try Token.shared.session(hSession)
        guard let pInfo else { throw CKError(CKR_ARGUMENTS_BAD) }
        pInfo.pointee = CK_SESSION_INFO(slotID: Token.slotID, state: Token.shared.state(of: s), flags: s.flags, ulDeviceError: 0)
    }
}

func sk_GetOperationState(_ hSession: CK_SESSION_HANDLE, _ pOperationState: BytePtr, _ pulOperationStateLen: ULongPtr) -> CK_RV {
    unsupported("C_GetOperationState")
}
func sk_SetOperationState(_ hSession: CK_SESSION_HANDLE, _ pOperationState: BytePtr, _ ulOperationStateLen: CK_ULONG,
                          _ hEncryptionKey: CK_OBJECT_HANDLE, _ hAuthenticationKey: CK_OBJECT_HANDLE) -> CK_RV {
    unsupported("C_SetOperationState")
}

func sk_Login(_ hSession: CK_SESSION_HANDLE, _ userType: CK_USER_TYPE, _ pPin: UnsafeMutablePointer<CK_UTF8CHAR>?, _ ulPinLen: CK_ULONG) -> CK_RV {
    // Any PIN is accepted: authentication and approval happen in the agent, per policy.
    entry("C_Login") { try Token.shared.login(hSession, userType: userType) }
}

func sk_Logout(_ hSession: CK_SESSION_HANDLE) -> CK_RV {
    entry("C_Logout") { try Token.shared.logout(hSession) }
}

// MARK: - Objects

func sk_CreateObject(_ hSession: CK_SESSION_HANDLE, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG, _ phObject: ObjPtr) -> CK_RV {
    unsupported("C_CreateObject")
}
func sk_CopyObject(_ hSession: CK_SESSION_HANDLE, _ hObject: CK_OBJECT_HANDLE, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG, _ phNewObject: ObjPtr) -> CK_RV {
    unsupported("C_CopyObject")
}
func sk_DestroyObject(_ hSession: CK_SESSION_HANDLE, _ hObject: CK_OBJECT_HANDLE) -> CK_RV {
    unsupported("C_DestroyObject")
}
func sk_GetObjectSize(_ hSession: CK_SESSION_HANDLE, _ hObject: CK_OBJECT_HANDLE, _ pulSize: ULongPtr) -> CK_RV {
    unsupported("C_GetObjectSize")
}

func sk_GetAttributeValue(_ hSession: CK_SESSION_HANDLE, _ hObject: CK_OBJECT_HANDLE, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG) -> CK_RV {
    entry("C_GetAttributeValue") {
        try Token.shared.getAttributes(hSession, object: hObject, template: pTemplate, count: ulCount)
    }
}

func sk_SetAttributeValue(_ hSession: CK_SESSION_HANDLE, _ hObject: CK_OBJECT_HANDLE, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG) -> CK_RV {
    unsupported("C_SetAttributeValue")
}

func sk_FindObjectsInit(_ hSession: CK_SESSION_HANDLE, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG) -> CK_RV {
    entry("C_FindObjectsInit") { try Token.shared.findInit(hSession, template: pTemplate, count: ulCount) }
}

func sk_FindObjects(_ hSession: CK_SESSION_HANDLE, _ phObject: ObjPtr, _ ulMaxObjectCount: CK_ULONG, _ pulObjectCount: ULongPtr) -> CK_RV {
    entry("C_FindObjects") { try Token.shared.find(hSession, out: phObject, max: ulMaxObjectCount, count: pulObjectCount) }
}

func sk_FindObjectsFinal(_ hSession: CK_SESSION_HANDLE) -> CK_RV {
    entry("C_FindObjectsFinal") { try Token.shared.findFinal(hSession) }
}

// MARK: - Encrypt / decrypt / digest (not supported)

func sk_EncryptInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV { unsupported("C_EncryptInit") }
func sk_Encrypt(_ hSession: CK_SESSION_HANDLE, _ pData: BytePtr, _ ulDataLen: CK_ULONG, _ pEncryptedData: BytePtr, _ pulEncryptedDataLen: ULongPtr) -> CK_RV { unsupported("C_Encrypt") }
func sk_EncryptUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG, _ pEncryptedPart: BytePtr, _ pulEncryptedPartLen: ULongPtr) -> CK_RV { unsupported("C_EncryptUpdate") }
func sk_EncryptFinal(_ hSession: CK_SESSION_HANDLE, _ pLastEncryptedPart: BytePtr, _ pulLastEncryptedPartLen: ULongPtr) -> CK_RV { unsupported("C_EncryptFinal") }
func sk_DecryptInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV { unsupported("C_DecryptInit") }
func sk_Decrypt(_ hSession: CK_SESSION_HANDLE, _ pEncryptedData: BytePtr, _ ulEncryptedDataLen: CK_ULONG, _ pData: BytePtr, _ pulDataLen: ULongPtr) -> CK_RV { unsupported("C_Decrypt") }
func sk_DecryptUpdate(_ hSession: CK_SESSION_HANDLE, _ pEncryptedPart: BytePtr, _ ulEncryptedPartLen: CK_ULONG, _ pPart: BytePtr, _ pulPartLen: ULongPtr) -> CK_RV { unsupported("C_DecryptUpdate") }
func sk_DecryptFinal(_ hSession: CK_SESSION_HANDLE, _ pLastPart: BytePtr, _ pulLastPartLen: ULongPtr) -> CK_RV { unsupported("C_DecryptFinal") }
func sk_DigestInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr) -> CK_RV { unsupported("C_DigestInit") }
func sk_Digest(_ hSession: CK_SESSION_HANDLE, _ pData: BytePtr, _ ulDataLen: CK_ULONG, _ pDigest: BytePtr, _ pulDigestLen: ULongPtr) -> CK_RV { unsupported("C_Digest") }
func sk_DigestUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG) -> CK_RV { unsupported("C_DigestUpdate") }
func sk_DigestKey(_ hSession: CK_SESSION_HANDLE, _ hKey: CK_OBJECT_HANDLE) -> CK_RV { unsupported("C_DigestKey") }
func sk_DigestFinal(_ hSession: CK_SESSION_HANDLE, _ pDigest: BytePtr, _ pulDigestLen: ULongPtr) -> CK_RV { unsupported("C_DigestFinal") }

// MARK: - Sign

func sk_SignInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV {
    entry("C_SignInit") { try Token.shared.signInit(hSession, mechanism: pMechanism, key: hKey) }
}

func sk_Sign(_ hSession: CK_SESSION_HANDLE, _ pData: BytePtr, _ ulDataLen: CK_ULONG, _ pSignature: BytePtr, _ pulSignatureLen: ULongPtr) -> CK_RV {
    entry("C_Sign") {
        let t = Token.shared
        // Single-part: the data replaces anything accumulated so a repeated size query is idempotent.
        let s = try t.session(hSession)
        guard s.sign != nil else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        s.sign!.data = Data()
        try t.signUpdate(hSession, data: pData, len: ulDataLen)
        try t.signFinal(hSession, sig: pSignature, sigLen: pulSignatureLen)
    }
}

func sk_SignUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG) -> CK_RV {
    entry("C_SignUpdate") { try Token.shared.signUpdate(hSession, data: pPart, len: ulPartLen) }
}

func sk_SignFinal(_ hSession: CK_SESSION_HANDLE, _ pSignature: BytePtr, _ pulSignatureLen: ULongPtr) -> CK_RV {
    entry("C_SignFinal") { try Token.shared.signFinal(hSession, sig: pSignature, sigLen: pulSignatureLen) }
}

func sk_SignRecoverInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV { unsupported("C_SignRecoverInit") }
func sk_SignRecover(_ hSession: CK_SESSION_HANDLE, _ pData: BytePtr, _ ulDataLen: CK_ULONG, _ pSignature: BytePtr, _ pulSignatureLen: ULongPtr) -> CK_RV { unsupported("C_SignRecover") }

// MARK: - Verify

func sk_VerifyInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV {
    entry("C_VerifyInit") { try Token.shared.verifyInit(hSession, mechanism: pMechanism, key: hKey) }
}

func sk_Verify(_ hSession: CK_SESSION_HANDLE, _ pData: BytePtr, _ ulDataLen: CK_ULONG, _ pSignature: BytePtr, _ ulSignatureLen: CK_ULONG) -> CK_RV {
    entry("C_Verify") {
        let t = Token.shared
        let s = try t.session(hSession)
        guard s.verify != nil else { throw CKError(CKR_OPERATION_NOT_INITIALIZED) }
        s.verify!.data = Data()
        try t.verifyUpdate(hSession, data: pData, len: ulDataLen)
        try t.verifyFinal(hSession, sig: pSignature, sigLen: ulSignatureLen)
    }
}

func sk_VerifyUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG) -> CK_RV {
    entry("C_VerifyUpdate") { try Token.shared.verifyUpdate(hSession, data: pPart, len: ulPartLen) }
}

func sk_VerifyFinal(_ hSession: CK_SESSION_HANDLE, _ pSignature: BytePtr, _ ulSignatureLen: CK_ULONG) -> CK_RV {
    entry("C_VerifyFinal") { try Token.shared.verifyFinal(hSession, sig: pSignature, sigLen: ulSignatureLen) }
}

func sk_VerifyRecoverInit(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hKey: CK_OBJECT_HANDLE) -> CK_RV { unsupported("C_VerifyRecoverInit") }
func sk_VerifyRecover(_ hSession: CK_SESSION_HANDLE, _ pSignature: BytePtr, _ ulSignatureLen: CK_ULONG, _ pData: BytePtr, _ pulDataLen: ULongPtr) -> CK_RV { unsupported("C_VerifyRecover") }

// MARK: - Dual-function, key management, random (not supported)

func sk_DigestEncryptUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG, _ pEncryptedPart: BytePtr, _ pulEncryptedPartLen: ULongPtr) -> CK_RV { unsupported("C_DigestEncryptUpdate") }
func sk_DecryptDigestUpdate(_ hSession: CK_SESSION_HANDLE, _ pEncryptedPart: BytePtr, _ ulEncryptedPartLen: CK_ULONG, _ pPart: BytePtr, _ pulPartLen: ULongPtr) -> CK_RV { unsupported("C_DecryptDigestUpdate") }
func sk_SignEncryptUpdate(_ hSession: CK_SESSION_HANDLE, _ pPart: BytePtr, _ ulPartLen: CK_ULONG, _ pEncryptedPart: BytePtr, _ pulEncryptedPartLen: ULongPtr) -> CK_RV { unsupported("C_SignEncryptUpdate") }
func sk_DecryptVerifyUpdate(_ hSession: CK_SESSION_HANDLE, _ pEncryptedPart: BytePtr, _ ulEncryptedPartLen: CK_ULONG, _ pPart: BytePtr, _ pulPartLen: ULongPtr) -> CK_RV { unsupported("C_DecryptVerifyUpdate") }
func sk_GenerateKey(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ pTemplate: AttrPtr, _ ulCount: CK_ULONG, _ phKey: ObjPtr) -> CK_RV { unsupported("C_GenerateKey") }
func sk_GenerateKeyPair(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ pPublicKeyTemplate: AttrPtr, _ ulPublicKeyAttributeCount: CK_ULONG,
                        _ pPrivateKeyTemplate: AttrPtr, _ ulPrivateKeyAttributeCount: CK_ULONG, _ phPublicKey: ObjPtr, _ phPrivateKey: ObjPtr) -> CK_RV { unsupported("C_GenerateKeyPair") }
func sk_WrapKey(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hWrappingKey: CK_OBJECT_HANDLE, _ hKey: CK_OBJECT_HANDLE, _ pWrappedKey: BytePtr, _ pulWrappedKeyLen: ULongPtr) -> CK_RV { unsupported("C_WrapKey") }
func sk_UnwrapKey(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hUnwrappingKey: CK_OBJECT_HANDLE, _ pWrappedKey: BytePtr, _ ulWrappedKeyLen: CK_ULONG,
                  _ pTemplate: AttrPtr, _ ulAttributeCount: CK_ULONG, _ phKey: ObjPtr) -> CK_RV { unsupported("C_UnwrapKey") }
func sk_DeriveKey(_ hSession: CK_SESSION_HANDLE, _ pMechanism: MechPtr, _ hBaseKey: CK_OBJECT_HANDLE, _ pTemplate: AttrPtr, _ ulAttributeCount: CK_ULONG, _ phKey: ObjPtr) -> CK_RV { unsupported("C_DeriveKey") }
func sk_SeedRandom(_ hSession: CK_SESSION_HANDLE, _ pSeed: BytePtr, _ ulSeedLen: CK_ULONG) -> CK_RV { unsupported("C_SeedRandom") }
func sk_GenerateRandom(_ hSession: CK_SESSION_HANDLE, _ pRandomData: BytePtr, _ ulRandomLen: CK_ULONG) -> CK_RV { unsupported("C_GenerateRandom") }

// MARK: - Legacy / events

func sk_GetFunctionStatus(_ hSession: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL }
func sk_CancelFunction(_ hSession: CK_SESSION_HANDLE) -> CK_RV { CKR_FUNCTION_NOT_PARALLEL }
func sk_WaitForSlotEvent(_ flags: CK_FLAGS, _ pSlot: UnsafeMutablePointer<CK_SLOT_ID>?, _ pReserved: VoidPtr) -> CK_RV {
    // No slot events ever occur; the token is always present.
    entry("C_WaitForSlotEvent") {
        try Token.shared.requireInitialized()
        throw CKError(CKR_NO_EVENT)
    }
}

// MARK: - Function list

let libraryVersion = CK_VERSION(major: 0, minor: 1)

/// Heap-allocated once and never freed: applications keep the pointer for the process lifetime.
let functionListPointer: UnsafeMutablePointer<CK_FUNCTION_LIST> = {
    let p = UnsafeMutablePointer<CK_FUNCTION_LIST>.allocate(capacity: 1)
    p.initialize(to: CK_FUNCTION_LIST(
        version: CK_VERSION(major: 2, minor: 40),
        C_Initialize: sk_Initialize,
        C_Finalize: sk_Finalize,
        C_GetInfo: sk_GetInfo,
        C_GetFunctionList: C_GetFunctionList,
        C_GetSlotList: sk_GetSlotList,
        C_GetSlotInfo: sk_GetSlotInfo,
        C_GetTokenInfo: sk_GetTokenInfo,
        C_GetMechanismList: sk_GetMechanismList,
        C_GetMechanismInfo: sk_GetMechanismInfo,
        C_InitToken: sk_InitToken,
        C_InitPIN: sk_InitPIN,
        C_SetPIN: sk_SetPIN,
        C_OpenSession: sk_OpenSession,
        C_CloseSession: sk_CloseSession,
        C_CloseAllSessions: sk_CloseAllSessions,
        C_GetSessionInfo: sk_GetSessionInfo,
        C_GetOperationState: sk_GetOperationState,
        C_SetOperationState: sk_SetOperationState,
        C_Login: sk_Login,
        C_Logout: sk_Logout,
        C_CreateObject: sk_CreateObject,
        C_CopyObject: sk_CopyObject,
        C_DestroyObject: sk_DestroyObject,
        C_GetObjectSize: sk_GetObjectSize,
        C_GetAttributeValue: sk_GetAttributeValue,
        C_SetAttributeValue: sk_SetAttributeValue,
        C_FindObjectsInit: sk_FindObjectsInit,
        C_FindObjects: sk_FindObjects,
        C_FindObjectsFinal: sk_FindObjectsFinal,
        C_EncryptInit: sk_EncryptInit,
        C_Encrypt: sk_Encrypt,
        C_EncryptUpdate: sk_EncryptUpdate,
        C_EncryptFinal: sk_EncryptFinal,
        C_DecryptInit: sk_DecryptInit,
        C_Decrypt: sk_Decrypt,
        C_DecryptUpdate: sk_DecryptUpdate,
        C_DecryptFinal: sk_DecryptFinal,
        C_DigestInit: sk_DigestInit,
        C_Digest: sk_Digest,
        C_DigestUpdate: sk_DigestUpdate,
        C_DigestKey: sk_DigestKey,
        C_DigestFinal: sk_DigestFinal,
        C_SignInit: sk_SignInit,
        C_Sign: sk_Sign,
        C_SignUpdate: sk_SignUpdate,
        C_SignFinal: sk_SignFinal,
        C_SignRecoverInit: sk_SignRecoverInit,
        C_SignRecover: sk_SignRecover,
        C_VerifyInit: sk_VerifyInit,
        C_Verify: sk_Verify,
        C_VerifyUpdate: sk_VerifyUpdate,
        C_VerifyFinal: sk_VerifyFinal,
        C_VerifyRecoverInit: sk_VerifyRecoverInit,
        C_VerifyRecover: sk_VerifyRecover,
        C_DigestEncryptUpdate: sk_DigestEncryptUpdate,
        C_DecryptDigestUpdate: sk_DecryptDigestUpdate,
        C_SignEncryptUpdate: sk_SignEncryptUpdate,
        C_DecryptVerifyUpdate: sk_DecryptVerifyUpdate,
        C_GenerateKey: sk_GenerateKey,
        C_GenerateKeyPair: sk_GenerateKeyPair,
        C_WrapKey: sk_WrapKey,
        C_UnwrapKey: sk_UnwrapKey,
        C_DeriveKey: sk_DeriveKey,
        C_SeedRandom: sk_SeedRandom,
        C_GenerateRandom: sk_GenerateRandom,
        C_GetFunctionStatus: sk_GetFunctionStatus,
        C_CancelFunction: sk_CancelFunction,
        C_WaitForSlotEvent: sk_WaitForSlotEvent))
    return p
}()
