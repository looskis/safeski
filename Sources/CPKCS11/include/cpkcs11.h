/*
 * Minimal PKCS#11 v2.40 definitions used by the safeski module.
 *
 * Hand-written subset of the Cryptoki interface: only the types, constants and the
 * CK_FUNCTION_LIST layout that libsafeski-pkcs11 needs. On macOS (and every other
 * non-Windows platform) the standard uses natural struct alignment, so no packing
 * pragmas are applied here.
 */
#ifndef CPKCS11_H
#define CPKCS11_H

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Base types ------------------------------------------------------------ */

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef long CK_LONG;
typedef CK_ULONG CK_FLAGS;

typedef CK_BYTE *CK_BYTE_PTR;
typedef CK_CHAR *CK_CHAR_PTR;
typedef CK_UTF8CHAR *CK_UTF8CHAR_PTR;
typedef CK_ULONG *CK_ULONG_PTR;
typedef void *CK_VOID_PTR;
typedef CK_VOID_PTR *CK_VOID_PTR_PTR;

#define CK_TRUE 1
#define CK_FALSE 0

#define CK_UNAVAILABLE_INFORMATION 0xFFFFFFFFFFFFFFFFUL
#define CK_EFFECTIVELY_INFINITE 0UL
#define CK_INVALID_HANDLE 0UL

typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_SESSION_HANDLE *CK_SESSION_HANDLE_PTR;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_OBJECT_CLASS *CK_OBJECT_CLASS_PTR;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_MECHANISM_TYPE *CK_MECHANISM_TYPE_PTR;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_NOTIFICATION;

/* ---- Structures ------------------------------------------------------------ */

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;
typedef CK_VERSION *CK_VERSION_PTR;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;
typedef CK_INFO *CK_INFO_PTR;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;
typedef CK_SLOT_INFO *CK_SLOT_INFO_PTR;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;
typedef CK_SESSION_INFO *CK_SESSION_INFO_PTR;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM *CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;
typedef CK_MECHANISM_INFO *CK_MECHANISM_INFO_PTR;

typedef CK_RV (*CK_CREATEMUTEX)(CK_VOID_PTR_PTR ppMutex);
typedef CK_RV (*CK_DESTROYMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_LOCKMUTEX)(CK_VOID_PTR pMutex);
typedef CK_RV (*CK_UNLOCKMUTEX)(CK_VOID_PTR pMutex);

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX LockMutex;
    CK_UNLOCKMUTEX UnlockMutex;
    CK_FLAGS flags;
    CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;
typedef CK_C_INITIALIZE_ARGS *CK_C_INITIALIZE_ARGS_PTR;

typedef CK_RV (*CK_NOTIFY)(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event, CK_VOID_PTR pApplication);

/* ---- Constants ------------------------------------------------------------- */

/* CK_INFO / CK_C_INITIALIZE_ARGS flags */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK 0x00000002UL

/* Slot flags */
#define CKF_TOKEN_PRESENT 0x00000001UL
#define CKF_REMOVABLE_DEVICE 0x00000002UL
#define CKF_HW_SLOT 0x00000004UL

/* Token flags */
#define CKF_RNG 0x00000001UL
#define CKF_WRITE_PROTECTED 0x00000002UL
#define CKF_LOGIN_REQUIRED 0x00000004UL
#define CKF_USER_PIN_INITIALIZED 0x00000008UL
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL
#define CKF_TOKEN_INITIALIZED 0x00000400UL

/* Session flags */
#define CKF_RW_SESSION 0x00000002UL
#define CKF_SERIAL_SESSION 0x00000004UL

/* Session states */
#define CKS_RO_PUBLIC_SESSION 0UL
#define CKS_RO_USER_FUNCTIONS 1UL
#define CKS_RW_PUBLIC_SESSION 2UL
#define CKS_RW_USER_FUNCTIONS 3UL
#define CKS_RW_SO_FUNCTIONS 4UL

/* User types */
#define CKU_SO 0UL
#define CKU_USER 1UL
#define CKU_CONTEXT_SPECIFIC 2UL

/* Object classes */
#define CKO_DATA 0x00000000UL
#define CKO_CERTIFICATE 0x00000001UL
#define CKO_PUBLIC_KEY 0x00000002UL
#define CKO_PRIVATE_KEY 0x00000003UL
#define CKO_SECRET_KEY 0x00000004UL

/* Key types */
#define CKK_RSA 0x00000000UL
#define CKK_EC 0x00000003UL
#define CKK_ECDSA 0x00000003UL

/* Attribute types */
#define CKF_ARRAY_ATTRIBUTE 0x40000000UL
#define CKA_CLASS 0x00000000UL
#define CKA_TOKEN 0x00000001UL
#define CKA_PRIVATE 0x00000002UL
#define CKA_LABEL 0x00000003UL
#define CKA_APPLICATION 0x00000010UL
#define CKA_VALUE 0x00000011UL
#define CKA_CERTIFICATE_TYPE 0x00000080UL
#define CKA_ISSUER 0x00000081UL
#define CKA_SERIAL_NUMBER 0x00000082UL
#define CKA_TRUSTED 0x00000086UL
#define CKA_KEY_TYPE 0x00000100UL
#define CKA_SUBJECT 0x00000101UL
#define CKA_ID 0x00000102UL
#define CKA_SENSITIVE 0x00000103UL
#define CKA_ENCRYPT 0x00000104UL
#define CKA_DECRYPT 0x00000105UL
#define CKA_WRAP 0x00000106UL
#define CKA_UNWRAP 0x00000107UL
#define CKA_SIGN 0x00000108UL
#define CKA_SIGN_RECOVER 0x00000109UL
#define CKA_VERIFY 0x0000010AUL
#define CKA_VERIFY_RECOVER 0x0000010BUL
#define CKA_DERIVE 0x0000010CUL
#define CKA_START_DATE 0x00000110UL
#define CKA_END_DATE 0x00000111UL
#define CKA_MODULUS 0x00000120UL
#define CKA_MODULUS_BITS 0x00000121UL
#define CKA_PUBLIC_EXPONENT 0x00000122UL
#define CKA_VALUE_LEN 0x00000161UL
#define CKA_EXTRACTABLE 0x00000162UL
#define CKA_LOCAL 0x00000163UL
#define CKA_NEVER_EXTRACTABLE 0x00000164UL
#define CKA_ALWAYS_SENSITIVE 0x00000165UL
#define CKA_KEY_GEN_MECHANISM 0x00000166UL
#define CKA_MODIFIABLE 0x00000170UL
#define CKA_COPYABLE 0x00000171UL
#define CKA_DESTROYABLE 0x00000172UL
#define CKA_EC_PARAMS 0x00000180UL
#define CKA_ECDSA_PARAMS 0x00000180UL
#define CKA_EC_POINT 0x00000181UL
#define CKA_ALWAYS_AUTHENTICATE 0x00000202UL
#define CKA_WRAP_WITH_TRUSTED 0x00000210UL
#define CKA_ALLOWED_MECHANISMS 0x40000600UL
#define CKA_VENDOR_DEFINED 0x80000000UL

/* Mechanisms */
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_SHA256 0x00000250UL
#define CKM_EC_KEY_PAIR_GEN 0x00001040UL
#define CKM_ECDSA_KEY_PAIR_GEN 0x00001040UL
#define CKM_ECDSA 0x00001041UL
#define CKM_ECDSA_SHA1 0x00001042UL
#define CKM_ECDSA_SHA224 0x00001043UL
#define CKM_ECDSA_SHA256 0x00001044UL
#define CKM_ECDSA_SHA384 0x00001045UL
#define CKM_ECDSA_SHA512 0x00001046UL
#define CKM_VENDOR_DEFINED 0x80000000UL

/* Mechanism flags */
#define CKF_HW 0x00000001UL
#define CKF_ENCRYPT 0x00000100UL
#define CKF_DECRYPT 0x00000200UL
#define CKF_DIGEST 0x00000400UL
#define CKF_SIGN 0x00000800UL
#define CKF_SIGN_RECOVER 0x00001000UL
#define CKF_VERIFY 0x00002000UL
#define CKF_VERIFY_RECOVER 0x00004000UL
#define CKF_GENERATE 0x00008000UL
#define CKF_GENERATE_KEY_PAIR 0x00010000UL
#define CKF_WRAP 0x00020000UL
#define CKF_UNWRAP 0x00040000UL
#define CKF_DERIVE 0x00080000UL
#define CKF_EC_F_P 0x00100000UL
#define CKF_EC_F_2M 0x00200000UL
#define CKF_EC_ECPARAMETERS 0x00400000UL
#define CKF_EC_NAMEDCURVE 0x00800000UL
#define CKF_EC_UNCOMPRESS 0x01000000UL
#define CKF_EC_COMPRESS 0x02000000UL

/* Return values */
#define CKR_OK 0x00000000UL
#define CKR_CANCEL 0x00000001UL
#define CKR_HOST_MEMORY 0x00000002UL
#define CKR_SLOT_ID_INVALID 0x00000003UL
#define CKR_GENERAL_ERROR 0x00000005UL
#define CKR_FUNCTION_FAILED 0x00000006UL
#define CKR_ARGUMENTS_BAD 0x00000007UL
#define CKR_NO_EVENT 0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS 0x00000009UL
#define CKR_CANT_LOCK 0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY 0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE 0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID 0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID 0x00000013UL
#define CKR_ACTION_PROHIBITED 0x0000001BUL
#define CKR_DATA_INVALID 0x00000020UL
#define CKR_DATA_LEN_RANGE 0x00000021UL
#define CKR_DEVICE_ERROR 0x00000030UL
#define CKR_DEVICE_MEMORY 0x00000031UL
#define CKR_DEVICE_REMOVED 0x00000032UL
#define CKR_FUNCTION_CANCELED 0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL 0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED 0x00000054UL
#define CKR_KEY_HANDLE_INVALID 0x00000060UL
#define CKR_KEY_SIZE_RANGE 0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT 0x00000063UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED 0x00000068UL
#define CKR_MECHANISM_INVALID 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID 0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID 0x00000082UL
#define CKR_OPERATION_ACTIVE 0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED 0x00000091UL
#define CKR_PIN_INCORRECT 0x000000A0UL
#define CKR_PIN_INVALID 0x000000A1UL
#define CKR_PIN_LEN_RANGE 0x000000A2UL
#define CKR_SESSION_CLOSED 0x000000B0UL
#define CKR_SESSION_COUNT 0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID 0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY 0x000000B5UL
#define CKR_SESSION_EXISTS 0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS 0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS 0x000000B8UL
#define CKR_SIGNATURE_INVALID 0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE 0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE 0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT 0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT 0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED 0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED 0x000000E2UL
#define CKR_USER_ALREADY_LOGGED_IN 0x00000100UL
#define CKR_USER_NOT_LOGGED_IN 0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED 0x00000102UL
#define CKR_USER_TYPE_INVALID 0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL
#define CKR_USER_TOO_MANY_TYPES 0x00000105UL
#define CKR_BUFFER_TOO_SMALL 0x00000150UL
#define CKR_SAVED_STATE_INVALID 0x00000160UL
#define CKR_INFORMATION_SENSITIVE 0x00000170UL
#define CKR_STATE_UNSAVEABLE 0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_MUTEX_BAD 0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED 0x000001A1UL
#define CKR_FUNCTION_REJECTED 0x00000200UL
#define CKR_VENDOR_DEFINED 0x80000000UL

/* ---- Function list --------------------------------------------------------- */

struct CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (*CK_C_Initialize)(CK_VOID_PTR pInitArgs);
typedef CK_RV (*CK_C_Finalize)(CK_VOID_PTR pReserved);
typedef CK_RV (*CK_C_GetInfo)(CK_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*CK_C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (*CK_C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV (*CK_C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
typedef CK_RV (*CK_C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*CK_C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*CK_C_CloseSession)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CloseAllSessions)(CK_SLOT_ID slotID);
typedef CK_RV (*CK_C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*CK_C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV (*CK_C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*CK_C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*CK_C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*CK_C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*CK_C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (*CK_C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*CK_C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*CK_C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*CK_C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*CK_C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
typedef CK_RV (*CK_C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*CK_C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*CK_C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*CK_C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*CK_C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*CK_C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*CK_C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*CK_C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*CK_C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*CK_C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*CK_C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*CK_C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (*CK_C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);
typedef CK_RV (*CK_C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_CancelFunction)(CK_SESSION_HANDLE hSession);
typedef CK_RV (*CK_C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

/* The 68 entry points, in the order mandated by the standard. */
struct CK_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

#ifdef __cplusplus
}
#endif

#endif /* CPKCS11_H */
