import Foundation
import Security

/// A proxy session: a random URL token bound to the caller identity that created it. Every request
/// made through the session is evaluated against policy as that caller.
public final class ProxySession {
    public let id: String
    public let token: String
    public let label: String?
    public let caller: CallerIdentity
    /// Routes this session may use; nil means every configured route.
    public let routes: [String]?
    public let created: Date
    public let expires: Date
    public private(set) var requests = 0
    public private(set) var lastUsed: Date?
    /// Resolved secret values, cached for the session's lifetime. Never serialized.
    var secretCache: [String: String] = [:]
    /// Sliding-window request timestamps per route (budget accounting).
    var windows: [String: [Date]] = [:]

    init(id: String, token: String, label: String?, caller: CallerIdentity, routes: [String]?, created: Date, expires: Date) {
        self.id = id; self.token = token; self.label = label; self.caller = caller; self.routes = routes
        self.created = created; self.expires = expires
    }

    public func isExpired(at now: Date = Date()) -> Bool { now >= expires }

    public func allows(route: String) -> Bool { routes?.contains(route) ?? true }

    func touch(_ now: Date = Date()) { requests += 1; lastUsed = now }

    public var summary: ProxySessionSummary {
        ProxySessionSummary(id: id, label: label, routes: routes, created: created, expires: expires, requests: requests,
                            lastUsed: lastUsed, caller: caller.displayName, callerTransport: caller.transport)
    }
}

public struct ProxySessionSummary: Codable, Equatable {
    public var id: String
    public var label: String?
    public var routes: [String]?
    public var created: Date
    public var expires: Date
    public var requests: Int
    public var lastUsed: Date?
    public var caller: String
    public var callerTransport: String
}

/// In-memory session table. Thread-safe.
public final class ProxySessionStore {
    private var byToken: [String: ProxySession] = [:]
    private let lock = NSLock()
    public var defaultTTL: TimeInterval = 8 * 3600
    public var maxTTL: TimeInterval = 30 * 86400

    public init() {}

    public static func randomToken(bytes: Int = 24) -> String {
        var b = [UInt8](repeating: 0, count: bytes)
        if SecRandomCopyBytes(kSecRandomDefault, b.count, &b) != errSecSuccess {
            for i in 0..<b.count { b[i] = UInt8.random(in: 0...255) }
        }
        return Base64URL.encode(Data(b))
    }

    @discardableResult
    public func create(caller: CallerIdentity, routes: [String]?, ttl: TimeInterval?, label: String?, now: Date = Date()) -> ProxySession {
        let t = min(max(ttl ?? defaultTTL, 1), maxTTL)
        let s = ProxySession(id: "ps_" + ProxySessionStore.randomToken(bytes: 6), token: ProxySessionStore.randomToken(),
                             label: label, caller: caller, routes: routes, created: now, expires: now.addingTimeInterval(t))
        lock.lock(); defer { lock.unlock() }
        purgeLocked(now)
        byToken[s.token] = s
        return s
    }

    /// Look up a live session by URL token. Expired sessions are purged and return nil.
    public func lookup(token: String, now: Date = Date()) -> ProxySession? {
        lock.lock(); defer { lock.unlock() }
        guard let s = byToken[token] else { return nil }
        if s.isExpired(at: now) { byToken[token] = nil; return nil }
        return s
    }

    public func find(id: String) -> ProxySession? {
        lock.lock(); defer { lock.unlock() }
        return byToken.values.first { $0.id == id }
    }

    @discardableResult
    public func revoke(id: String) -> ProxySession? {
        lock.lock(); defer { lock.unlock() }
        guard let s = byToken.values.first(where: { $0.id == id }) else { return nil }
        byToken[s.token] = nil
        return s
    }

    public func list(now: Date = Date()) -> [ProxySession] {
        lock.lock(); defer { lock.unlock() }
        purgeLocked(now)
        return byToken.values.sorted { $0.created < $1.created }
    }

    public func count(now: Date = Date()) -> Int { list(now: now).count }

    public func removeAll() { lock.lock(); byToken.removeAll(); lock.unlock() }

    private func purgeLocked(_ now: Date) {
        for (k, s) in byToken where s.isExpired(at: now) { byToken[k] = nil }
    }

    // MARK: per-session state (serialized through the store lock)

    /// Record a request against the budget window. Returns the seconds until a slot frees when over budget.
    public func consumeBudget(_ s: ProxySession, route: String, budget: ProxyBudget?, now: Date = Date()) -> TimeInterval? {
        lock.lock(); defer { lock.unlock() }
        s.touch(now)
        guard let b = budget else { return nil }
        var w = s.windows[route] ?? []
        let cutoff = now.addingTimeInterval(-b.per)
        w.removeAll { $0 <= cutoff }
        if w.count >= b.requests {
            s.windows[route] = w
            return max(1, (w[0].addingTimeInterval(b.per)).timeIntervalSince(now))
        }
        w.append(now)
        s.windows[route] = w
        return nil
    }

    public func cachedSecret(_ s: ProxySession, _ name: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return s.secretCache[name]
    }

    public func cacheSecret(_ s: ProxySession, _ name: String, _ value: String) {
        lock.lock(); s.secretCache[name] = value; lock.unlock()
    }

    /// Drop cached secrets everywhere (e.g. after a policy reload).
    public func clearSecretCaches() {
        lock.lock(); defer { lock.unlock() }
        for s in byToken.values { s.secretCache.removeAll() }
    }
}
