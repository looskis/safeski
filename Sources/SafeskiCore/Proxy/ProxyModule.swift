import Foundation

/// The secretless proxy module: reads `[proxy]` from policy, runs the HTTP listener, and registers
/// the `proxy.*` RPC methods on the agent's `Service`.
public final class ProxyModule {
    public let service: Service
    public let sessions = ProxySessionStore()
    public var log: (String) -> Void = { _ in }
    private var server: ProxyServer?
    private var config: ProxyConfig
    private var configLoaded: Date?
    private var configError: String?
    private let lock = NSLock()
    public private(set) var running = false

    public enum Method {
        public static let status = "proxy.status"
        public static let routes = "proxy.routes"
        public static let sessionCreate = "proxy.session.create"
        public static let sessionList = "proxy.session.list"
        public static let sessionRevoke = "proxy.session.revoke"
    }

    /// Identity used for unsessioned `/r/<route>/...` requests when `allow_unsessioned = true`.
    public let anonymousSession: ProxySession = {
        var c = CallerIdentity(transport: "proxy")
        c.path = "proxy-anonymous"
        return ProxySession(id: "ps_anonymous", token: "", label: "anonymous", caller: c, routes: nil, created: Date(), expires: .distantFuture)
    }()

    public init(service: Service) {
        self.service = service
        self.config = ProxyConfig()
        self.configLoaded = nil
        reloadConfig()
        registerMethods()
        let prev = service.statusExtras
        service.statusExtras = { [weak self] in
            var d = prev()
            guard let self else { return d }
            let cfg = self.currentConfig()
            d["proxy.listen"] = .string(self.running ? cfg.listen : "(disabled)")
            d["proxy.routes"] = .number(Double(cfg.routes.count))
            d["proxy.sessions"] = .number(Double(self.sessions.count()))
            return d
        }
    }

    // MARK: lifecycle

    public func start() throws {
        let cfg = currentConfig()
        guard cfg.enabled else { log("proxy disabled by policy ([proxy] enabled = false)"); return }
        let s = ProxyServer(module: self)
        try s.start(host: cfg.listenHost, port: cfg.listenPort)
        server = s
        running = true
        log("proxy listening on http://\(cfg.listen) (\(cfg.routes.count) route(s))")
        _ = try? service.audit.append(action: "proxy.start", outcome: "allow", caller: nil,
                                  detail: ["listen": .string(cfg.listen), "routes": .number(Double(cfg.routes.count))])
    }

    public func stop() {
        guard running else { return }
        server?.stop(); server = nil
        running = false
        sessions.removeAll()
        _ = try? service.audit.append(action: "proxy.stop", outcome: "allow", caller: nil)
    }

    /// The port the listener bound (0 if not running).
    public var boundPort: UInt16 { server?.boundPort ?? 0 }

    // MARK: configuration

    /// Current config; re-parsed from the policy document whenever the policy was reloaded.
    public func currentConfig() -> ProxyConfig {
        service.reloadPolicyIfChanged()
        lock.lock(); defer { lock.unlock() }
        if service.policyLoaded != configLoaded { reloadConfigLocked() }
        return config
    }

    private func reloadConfig() { lock.lock(); reloadConfigLocked(); lock.unlock() }

    private func reloadConfigLocked() {
        configLoaded = service.policyLoaded
        do {
            let fresh = try ProxyConfig.parse(service.policy.raw["proxy"])
            if fresh != config { log("proxy: configuration reloaded (\(fresh.routes.count) route(s))") }
            config = fresh
            configError = nil
            sessions.clearSecretCaches()
        } catch {
            let msg = (error as? SafeskiError)?.message ?? error.localizedDescription
            configError = msg
            log("proxy: policy error, keeping previous configuration: \(msg)")
        }
    }

    // MARK: URLs

    public func baseURL(for session: ProxySession, route: String, config cfg: ProxyConfig? = nil) -> String {
        let c = cfg ?? currentConfig()
        return "\(c.baseURL)/s/\(session.token)/\(route)"
    }

    // MARK: RPC

    private func isOwner(_ c: CallerIdentity) -> Bool { c.uid == getuid() && c.tokenName == nil }

    private func registerMethods() {
        service.extraMethods[Method.status] = { [unowned self] _, _ in try self.statusJSON() }
        service.extraMethods[Method.routes] = { [unowned self] _, _ in self.routesJSON() }
        service.extraMethods[Method.sessionCreate] = { [unowned self] p, caller in try self.createSession(p, caller: caller) }
        service.extraMethods[Method.sessionList] = { [unowned self] _, caller in try self.listSessions(caller: caller) }
        service.extraMethods[Method.sessionRevoke] = { [unowned self] p, caller in try self.revokeSession(p, caller: caller) }
    }

    func statusJSON() throws -> JSONValue {
        let cfg = currentConfig()
        var d: [String: JSONValue] = [
            "enabled": .bool(cfg.enabled), "running": .bool(running), "listen": .string(cfg.listen), "baseURL": .string(cfg.baseURL),
            "allowUnsessioned": .bool(cfg.allowUnsessioned), "routes": .number(Double(cfg.routes.count)),
            "sessions": .number(Double(sessions.count())),
        ]
        if let e = configError { d["configError"] = .string(e) }
        return .object(d)
    }

    func routesJSON() -> JSONValue {
        let cfg = currentConfig()
        return .array(cfg.routes.keys.sorted().map { ProxyModule.describe(cfg.routes[$0]!) })
    }

    public static func describe(_ r: ProxyRoute) -> JSONValue {
        var d: [String: JSONValue] = ["name": .string(r.name), "upstream": .string(r.upstream)]
        if let e = r.env { d["env"] = .string(e) }
        d["headers"] = .object(Dictionary(uniqueKeysWithValues: r.headers.map { h in
            let refs = ProxyRoute.secretRefs(in: h.value)
            return (h.name, JSONValue.string(refs.isEmpty ? "(literal)" : refs.map { "secret:\($0)" }.joined(separator: ",")))
        }))
        d["strip"] = .array(r.strip.map { .string($0) })
        d["rules"] = .array(r.rules.map { rule in
            var o: [String: JSONValue] = ["path": .string(rule.path), "approve": .string(rule.approve.rawValue)]
            o["methods"] = .array(rule.methods.map { .string($0) })
            if let t = rule.ttl { o["ttl"] = .number(t) }
            return .object(o)
        })
        if let b = r.budget { d["budget"] = .object(["requests": .number(Double(b.requests)), "per": .number(b.per)]) }
        return .object(d)
    }

    func createSession(_ p: JSONValue, caller: CallerIdentity) throws -> JSONValue {
        let cfg = currentConfig()
        guard running else { throw SafeskiError.unsupported("proxy is not running") }
        var routes: [String]? = nil
        if let r = p["routes"], !r.isNull {
            guard let names = r.stringArray else { throw SafeskiError.invalidFormat("routes must be an array of strings") }
            if !names.isEmpty {
                for n in names where cfg.routes[n] == nil { throw SafeskiError.notFound("route '\(n)'") }
                routes = names
            }
        }
        if cfg.routes.isEmpty { throw SafeskiError.policy("no proxy routes configured; add [proxy.routes.<name>] to policy.toml") }
        var ttl: TimeInterval? = nil
        if let t = p["ttl"]?.doubleValue { ttl = t }
        else if let t = p["ttl"]?.stringValue {
            guard let secs = ProxyConfig.parseDuration(t), secs > 0 else { throw SafeskiError.invalidFormat("bad ttl '\(t)'") }
            ttl = secs
        }
        let label = p["label"]?.stringValue
        let s = sessions.create(caller: caller, routes: routes, ttl: ttl, label: label)
        let names = routes ?? cfg.routes.keys.sorted()
        var urls: [String: JSONValue] = [:]
        var env: [String: JSONValue] = [:]
        for n in names {
            let u = baseURL(for: s, route: n, config: cfg)
            urls[n] = .string(u)
            if let e = cfg.routes[n]?.env { env[e] = .string(u) }
        }
        _ = try? service.audit.append(action: "proxy.session.create", resource: s.id, outcome: "allow", caller: caller,
                                  detail: ["routes": .array(names.map { .string($0) }), "ttl": .number(s.expires.timeIntervalSince(s.created)),
                                           "label": label.map { .string($0) } ?? .null])
        log("proxy: session \(s.id) created for \(caller.displayName) routes=\(names.joined(separator: ","))")
        return .object([
            "id": .string(s.id), "token": .string(s.token), "label": label.map { .string($0) } ?? .null,
            "routes": .array(names.map { .string($0) }), "expires": .string(ISO8601DateFormatter().string(from: s.expires)),
            "baseURL": .string("\(cfg.baseURL)/s/\(s.token)"), "urls": .object(urls), "env": .object(env),
        ])
    }

    func listSessions(caller: CallerIdentity) throws -> JSONValue {
        let mine = ApprovalBroker.callerKey(caller)
        let all = sessions.list().filter { isOwner(caller) || ApprovalBroker.callerKey($0.caller) == mine }
        // ISO-8601 dates (the plain JSONValue initializer would encode them as numbers).
        let data = try JSONEncoder.safeskiCompact.encode(all.map(\.summary))
        return try JSONDecoder().decode(JSONValue.self, from: data)
    }

    func revokeSession(_ p: JSONValue, caller: CallerIdentity) throws -> JSONValue {
        guard let id = p["id"]?.stringValue, !id.isEmpty else { throw SafeskiError.invalidFormat("missing id") }
        guard let s = sessions.find(id: id) else { throw SafeskiError.notFound("session '\(id)'") }
        guard isOwner(caller) || ApprovalBroker.callerKey(s.caller) == ApprovalBroker.callerKey(caller) else {
            throw SafeskiError.denied("only the owner or the session's creator may revoke it")
        }
        sessions.revoke(id: id)
        _ = try? service.audit.append(action: "proxy.session.revoke", resource: id, outcome: "allow", caller: caller,
                                  detail: ["label": s.label.map { .string($0) } ?? .null])
        log("proxy: session \(id) revoked by \(caller.displayName)")
        return .bool(true)
    }
}
