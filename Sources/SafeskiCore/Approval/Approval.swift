import Foundation
import LocalAuthentication

/// Decides whether a request proceeds, prompting the user when policy says so, and caching
/// approvals per (caller, resource). Prompts use LocalAuthentication so they work from a
/// LaunchAgent in the GUI session; in a headless context prompts fail closed.
public final class ApprovalBroker {
    public struct CacheKey: Hashable {
        let callerKey: String
        let resource: String
    }
    private var cache: [CacheKey: Date] = [:]
    private let lock = NSLock()
    /// Shared LAContext so biometric approvals on enclave keys can be reused within the window.
    public private(set) var context: LAContext
    public var interactive: Bool
    public var prompter: ((String) -> Bool)?

    public init(interactive: Bool) {
        self.interactive = interactive
        self.context = Enclave.makeContext(reason: "safeski", reuseSeconds: 300)
    }

    public static func callerKey(_ c: CallerIdentity) -> String {
        if let t = c.tokenName { return "token:\(t)" }
        // Stable across pids: path + team + uid, plus script for interpreters.
        var parts = [c.path ?? "?", c.teamID ?? "-", c.signingID ?? "-", c.uid.map(String.init) ?? "-"]
        if let cmd = c.commandLine, cmd.count > 1, let first = cmd.first,
           ["node", "python", "python3", "ruby", "bun", "deno"].contains((first as NSString).lastPathComponent) {
            parts.append(cmd[1])
        }
        return parts.joined(separator: "|")
    }

    /// Returns normally if allowed; throws `.denied` / `.approvalFailed` otherwise.
    public func authorize(decision: Decision, caller: CallerIdentity, kind: String, resource: String, purpose: String?) throws -> String {
        switch decision.verdict {
        case .allow: return "allow"
        case .deny(let why): throw SafeskiError.denied(why)
        case .approve(let mode):
            let key = CacheKey(callerKey: ApprovalBroker.callerKey(caller), resource: "\(kind):\(resource)")
            if mode == .once {
                lock.lock()
                if let until = cache[key], until > Date() { lock.unlock(); return "cached" }
                lock.unlock()
            }
            let reason = "\(caller.displayName) wants to use \(kind) \"\(resource)\"" + (purpose.map { " (\($0))" } ?? "")
            try prompt(reason: reason, biometric: mode == .touchid)
            if mode == .once {
                lock.lock(); cache[key] = Date().addingTimeInterval(decision.ttl); lock.unlock()
            }
            return "approved"
        }
    }

    func prompt(reason: String, biometric: Bool) throws {
        if let p = prompter {
            guard p(reason) else { throw SafeskiError.approvalFailed("user declined: \(reason)") }
            return
        }
        guard interactive else { throw SafeskiError.approvalFailed("approval required but agent is not interactive: \(reason)") }
        let policy: LAPolicy = biometric ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
        let ctx = LAContext()
        ctx.localizedReason = reason
        var err: NSError?
        guard ctx.canEvaluatePolicy(policy, error: &err) else {
            throw SafeskiError.approvalFailed("cannot prompt: \(err?.localizedDescription ?? "unknown")")
        }
        let sem = DispatchSemaphore(value: 0)
        var ok = false
        var failure: Error?
        ctx.evaluatePolicy(policy, localizedReason: reason) { success, error in
            ok = success; failure = error; sem.signal()
        }
        _ = sem.wait(timeout: .now() + 120)
        guard ok else { throw SafeskiError.approvalFailed(failure?.localizedDescription ?? "timed out") }
    }

    public func clear() { lock.lock(); cache.removeAll(); lock.unlock() }

    public func cachedCount() -> Int { lock.lock(); defer { lock.unlock() }; return cache.filter { $0.value > Date() }.count }
}
