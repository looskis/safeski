import Foundation

public enum SafeskiError: Error, LocalizedError, Equatable {
    case enclaveUnavailable
    case notFound(String)
    case alreadyExists(String)
    case invalidFormat(String)
    case denied(String)
    case approvalFailed(String)
    case io(String)
    case rpc(String)
    case policy(String)
    case unsupported(String)

    public var errorDescription: String? {
        switch self {
        case .enclaveUnavailable: return "Secure Enclave is not available on this machine"
        case .notFound(let s): return "not found: \(s)"
        case .alreadyExists(let s): return "already exists: \(s)"
        case .invalidFormat(let s): return "invalid format: \(s)"
        case .denied(let s): return "denied: \(s)"
        case .approvalFailed(let s): return "approval failed: \(s)"
        case .io(let s): return "io: \(s)"
        case .rpc(let s): return "rpc: \(s)"
        case .policy(let s): return "policy: \(s)"
        case .unsupported(let s): return "unsupported: \(s)"
        }
    }

    /// The bare message without the category prefix.
    public var message: String {
        switch self {
        case .enclaveUnavailable: return errorDescription ?? ""
        case .notFound(let s), .alreadyExists(let s), .invalidFormat(let s), .denied(let s), .approvalFailed(let s),
             .io(let s), .rpc(let s), .policy(let s), .unsupported(let s): return s
        }
    }

    /// Stable machine-readable code for the RPC layer.
    public var code: String {
        switch self {
        case .enclaveUnavailable: return "enclave_unavailable"
        case .notFound: return "not_found"
        case .alreadyExists: return "already_exists"
        case .invalidFormat: return "invalid_format"
        case .denied: return "denied"
        case .approvalFailed: return "approval_failed"
        case .io: return "io"
        case .rpc: return "rpc"
        case .policy: return "policy"
        case .unsupported: return "unsupported"
        }
    }

    public static func fromCode(_ code: String, message: String) -> SafeskiError {
        switch code {
        case "enclave_unavailable": return .enclaveUnavailable
        case "not_found": return .notFound(message)
        case "already_exists": return .alreadyExists(message)
        case "invalid_format": return .invalidFormat(message)
        case "denied": return .denied(message)
        case "approval_failed": return .approvalFailed(message)
        case "io": return .io(message)
        case "policy": return .policy(message)
        case "unsupported": return .unsupported(message)
        default: return .rpc(message)
        }
    }
}
