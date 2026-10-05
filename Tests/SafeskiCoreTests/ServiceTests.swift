import Foundation
import Testing
@testable import SafeskiCore

/// Records every prompt the broker makes and answers with a scripted result.
private final class PromptRecorder {
    private let lock = NSLock()
    private(set) var reasons: [String] = []
    var answer = true
    var count: Int { lock.lock(); defer { lock.unlock() }; return reasons.count }
    func handler() -> (String) -> Bool {
        { [self] reason in
            lock.lock(); reasons.append(reason); let a = answer; lock.unlock()
            return a
        }
    }
}

@Suite("Service approval flow", .requiresEnclave, .enclaveSerialized)
struct ServiceTests {
    private static let policy = """
    [defaults]
    approve = "never"
    ttl = 300

    [secrets.once]
    rules = [ { uid = \(getuid()), approve = "once", ttl = 120 } ]
    [secrets.always]
    rules = [ { uid = \(getuid()), approve = "always" } ]
    [secrets.touch]
    rules = [ { uid = \(getuid()), approve = "touchid" } ]
    [secrets.denied]
    rules = [ { uid = \(getuid()), approve = "deny" } ]
    [secrets.open]
    rules = [ { uid = \(getuid()), approve = "never" } ]
    """

    private func makeService(_ prefix: String) throws -> (TempHome, Service, PromptRecorder) {
        let home = try TempHome(prefix)
        let store = Store(paths: home.paths)
        try store.initialize(name: "svc")
        try home.writePolicy(Self.policy)
        let service = try Service(store: store, interactive: false)
        let rec = PromptRecorder()
        service.approvals.prompter = rec.handler()
        let owner = CallerIdentity.local()
        for name in ["once", "always", "touch", "denied", "open"] {
            _ = try service.setSecret(SetSecretParams(name: name, value: Data(name.utf8), contentType: "text"), caller: owner)
        }
        return (home, service, rec)
    }

    private func lastAudit(_ s: Service) throws -> AuditEvent? { try s.audit.tail(1).first }

    @Test func oncePromptsThenCaches() throws {
        let (home, svc, rec) = try makeService("svc-once")
        defer { home.cleanup() }
        let caller = CallerIdentity.testUnix(path: "/usr/bin/tool")

        #expect(try svc.getSecret("once", purpose: "deploy", caller: caller).value == Data("once".utf8))
        #expect(rec.count == 1)
        #expect(rec.reasons[0].contains("secret \"once\""))
        #expect(rec.reasons[0].contains("tool"))
        #expect(rec.reasons[0].contains("(deploy)"))
        var ev = try #require(try lastAudit(svc))
        #expect(ev.action == "secret.get" && ev.outcome == "approved")
        #expect(ev.detail?["via"] == .string("approved"))
        #expect(ev.detail?["purpose"] == .string("deploy"))
        #expect(ev.caller?.path == "/usr/bin/tool")
        #expect(svc.approvals.cachedCount() == 1)

        #expect(try svc.getSecret("once", purpose: nil, caller: caller).value == Data("once".utf8))
        #expect(rec.count == 1)   // cached, no second prompt
        ev = try #require(try lastAudit(svc))
        #expect(ev.outcome == "allow")
        #expect(ev.detail?["via"] == .string("cached"))

        // the cache is per (caller, resource): a different caller path prompts again
        _ = try svc.getSecret("once", purpose: nil, caller: .testUnix(path: "/usr/bin/other"))
        #expect(rec.count == 2)
        // but the same caller with a different pid is still cached
        _ = try svc.getSecret("once", purpose: nil, caller: .testUnix(path: "/usr/bin/tool", pid: 9999))
        #expect(rec.count == 2)
        #expect(svc.approvals.cachedCount() == 2)
    }

    @Test func alwaysPromptsEveryTime() throws {
        let (home, svc, rec) = try makeService("svc-always")
        defer { home.cleanup() }
        let caller = CallerIdentity.testUnix()
        for i in 1...3 {
            #expect(try svc.getSecret("always", purpose: nil, caller: caller).value == Data("always".utf8))
            #expect(rec.count == i)
            #expect(try lastAudit(svc)?.outcome == "approved")
        }
        #expect(svc.approvals.cachedCount() == 0)
    }

    @Test func declinedPromptFailsAndIsAudited() throws {
        let (home, svc, rec) = try makeService("svc-decline")
        defer { home.cleanup() }
        rec.answer = false
        let caller = CallerIdentity.testUnix()
        let e = safeskiError { _ = try svc.getSecret("once", purpose: "x", caller: caller) }
        #expect(e?.code == "approval_failed")
        #expect(e?.message.contains("user declined") == true)
        #expect(rec.count == 1)
        let ev = try #require(try lastAudit(svc))
        #expect(ev.action == "secret.get" && ev.resource == "once" && ev.outcome == "deny")
        #expect(ev.detail?["error"]?.stringValue?.contains("approval failed") == true)
        #expect(ev.caller?.uid == getuid())
        // nothing was cached by the failed attempt
        #expect(svc.approvals.cachedCount() == 0)
        rec.answer = true
        _ = try svc.getSecret("once", purpose: nil, caller: caller)
        #expect(rec.count == 2)
    }

    @Test func touchidUsesPrompter() throws {
        let (home, svc, rec) = try makeService("svc-touch")
        defer { home.cleanup() }
        let caller = CallerIdentity.testUnix()
        #expect(try svc.getSecret("touch", purpose: nil, caller: caller).value == Data("touch".utf8))
        #expect(rec.count == 1)
        #expect(try lastAudit(svc)?.outcome == "approved")
        // touchid is never cached
        _ = try svc.getSecret("touch", purpose: nil, caller: caller)
        #expect(rec.count == 2)
        #expect(svc.approvals.cachedCount() == 0)
        rec.answer = false
        #expect(safeskiError { _ = try svc.getSecret("touch", purpose: nil, caller: caller) }?.code == "approval_failed")
    }

    @Test func clearResetsCache() throws {
        let (home, svc, rec) = try makeService("svc-clear")
        defer { home.cleanup() }
        let caller = CallerIdentity.testUnix()
        _ = try svc.getSecret("once", purpose: nil, caller: caller)
        _ = try svc.getSecret("once", purpose: nil, caller: caller)
        #expect(rec.count == 1)
        #expect(svc.approvals.cachedCount() == 1)
        svc.approvals.clear()
        #expect(svc.approvals.cachedCount() == 0)
        _ = try svc.getSecret("once", purpose: nil, caller: caller)
        #expect(rec.count == 2)
    }

    @Test func denyRuleDoesNotPromptAndIsAudited() throws {
        let (home, svc, rec) = try makeService("svc-deny")
        defer { home.cleanup() }
        let e = safeskiError { _ = try svc.getSecret("denied", purpose: nil, caller: .testUnix()) }
        #expect(e?.code == "denied")
        #expect(rec.count == 0)
        let ev = try #require(try lastAudit(svc))
        #expect(ev.outcome == "deny" && ev.resource == "denied")
        #expect(ev.detail?["error"]?.stringValue?.contains("denied") == true)

        // allow without prompting
        #expect(try svc.getSecret("open", purpose: nil, caller: .testUnix()).value == Data("open".utf8))
        #expect(rec.count == 0)
        let ok = try #require(try lastAudit(svc))
        #expect(ok.outcome == "allow" && ok.detail?["via"] == .string("allow"))
    }

    @Test func headlessWithoutPrompterFailsClosed() throws {
        let (home, svc, _) = try makeService("svc-headless")
        defer { home.cleanup() }
        svc.approvals.prompter = nil
        #expect(!svc.approvals.interactive)
        let e = safeskiError { _ = try svc.getSecret("once", purpose: nil, caller: .testUnix()) }
        #expect(e?.code == "approval_failed")
        #expect(e?.message.contains("not interactive") == true)
        #expect(try lastAudit(svc)?.outcome == "deny")
    }

    @Test func policyReloadPicksUpChanges() throws {
        let (home, svc, rec) = try makeService("svc-reload")
        defer { home.cleanup() }
        let caller = CallerIdentity.testUnix()
        _ = try svc.getSecret("open", purpose: nil, caller: caller)
        #expect(rec.count == 0)
        try home.writePolicy("""
        [defaults]
        approve = "never"
        [secrets.open]
        rules = [ { uid = \(getuid()), approve = "always" } ]
        """)
        try svc.reloadPolicy()
        #expect(svc.policy.secrets["open"]?.rules.first?.approve == .always)
        _ = try svc.getSecret("open", purpose: nil, caller: caller)
        #expect(rec.count == 1)
    }

    @Test func brokerAuthorizeDirectly() throws {
        let broker = ApprovalBroker(interactive: false)
        let rec = PromptRecorder()
        broker.prompter = rec.handler()
        let caller = CallerIdentity.testUnix()
        #expect(try broker.authorize(decision: Decision(verdict: .allow, rule: nil, ttl: 0), caller: caller, kind: "key", resource: "k", purpose: nil) == "allow")
        #expect(safeskiError { _ = try broker.authorize(decision: Decision(verdict: .deny("no"), rule: nil, ttl: 0), caller: caller, kind: "key", resource: "k", purpose: nil) }?.code == "denied")
        #expect(try broker.authorize(decision: Decision(verdict: .approve(.once), rule: nil, ttl: 60), caller: caller, kind: "key", resource: "k", purpose: nil) == "approved")
        #expect(try broker.authorize(decision: Decision(verdict: .approve(.once), rule: nil, ttl: 60), caller: caller, kind: "key", resource: "k", purpose: nil) == "cached")
        // an expired cache entry prompts again
        #expect(try broker.authorize(decision: Decision(verdict: .approve(.once), rule: nil, ttl: -1), caller: caller, kind: "key", resource: "k2", purpose: nil) == "approved")
        #expect(try broker.authorize(decision: Decision(verdict: .approve(.once), rule: nil, ttl: -1), caller: caller, kind: "key", resource: "k2", purpose: nil) == "approved")
        #expect(rec.count == 3)
        #expect(broker.cachedCount() == 1)

        // token callers are keyed by token name
        var t = CallerIdentity(transport: "token"); t.tokenName = "ci"
        #expect(ApprovalBroker.callerKey(t) == "token:ci")
        var node = CallerIdentity.testUnix(path: "/usr/local/bin/node")
        node.commandLine = ["/usr/local/bin/node", "/x/claude.js"]
        #expect(ApprovalBroker.callerKey(node).hasSuffix("|/x/claude.js"))
    }
}
