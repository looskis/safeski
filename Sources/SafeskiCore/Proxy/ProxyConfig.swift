import Foundation

/// Configuration for the secretless HTTP proxy, read from the `[proxy]` section of policy.toml.
///
/// ```toml
/// [proxy]
/// listen = "127.0.0.1:7865"
/// allow_unsessioned = false
///
/// [proxy.routes.anthropic]
/// upstream = "https://api.anthropic.com"
/// env = "ANTHROPIC_BASE_URL"
/// headers = { "x-api-key" = "secret:ANTHROPIC_API_KEY" }
/// strip = ["authorization"]
/// rules = [ { methods = ["POST"], path = "/v1/messages", approve = "never" } ]
/// budget = { requests = 1000, per = "1h" }
/// ```
public struct ProxyConfig: Equatable {
    public static let defaultListen = "127.0.0.1:7865"

    public var enabled: Bool = true
    public var listenHost: String = "127.0.0.1"
    public var listenPort: UInt16 = 7865
    public var allowUnsessioned: Bool = false
    public var routes: [String: ProxyRoute] = [:]

    public init() {}

    public var listen: String { "\(listenHost):\(listenPort)" }

    /// Host clients should use to reach the listener (wildcard binds map to loopback).
    public var advertisedHost: String {
        if listenHost == "0.0.0.0" || listenHost == "::" || listenHost == "*" { return "127.0.0.1" }
        return listenHost
    }

    public var baseURL: String { "http://\(advertisedHost):\(listenPort)" }

    /// Parse the `[proxy]` section. A `nil` section yields the defaults (enabled, loopback, no routes).
    public static func parse(_ node: JSONValue?) throws -> ProxyConfig {
        var cfg = ProxyConfig()
        guard let node, let obj = node.objectValue else { return cfg }
        if let e = obj["enabled"]?.boolValue { cfg.enabled = e }
        if let l = obj["listen"]?.stringValue {
            let (h, p) = try parseListen(l)
            cfg.listenHost = h; cfg.listenPort = p
        }
        if let a = obj["allow_unsessioned"]?.boolValue { cfg.allowUnsessioned = a }
        if let routes = obj["routes"]?.objectValue {
            for (name, v) in routes {
                guard isValidRouteName(name) else { throw SafeskiError.policy("proxy.routes.\(name): invalid route name") }
                cfg.routes[name] = try ProxyRoute.parse(name: name, v)
            }
        }
        return cfg
    }

    public static func parseListen(_ s: String) throws -> (String, UInt16) {
        let t = s.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { throw SafeskiError.policy("proxy.listen: empty") }
        // "[::1]:7865", "127.0.0.1:7865", "7865"
        if t.hasPrefix("[") {
            guard let close = t.firstIndex(of: "]") else { throw SafeskiError.policy("proxy.listen: bad address '\(s)'") }
            let host = String(t[t.index(after: t.startIndex)..<close])
            let rest = t[t.index(after: close)...]
            guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()) else { throw SafeskiError.policy("proxy.listen: bad port in '\(s)'") }
            return (host, p)
        }
        if let colon = t.lastIndex(of: ":") {
            let host = String(t[..<colon]); let port = t[t.index(after: colon)...]
            guard let p = UInt16(port), p > 0 else { throw SafeskiError.policy("proxy.listen: bad port in '\(s)'") }
            return (host.isEmpty ? "127.0.0.1" : host, p)
        }
        guard let p = UInt16(t), p > 0 else { throw SafeskiError.policy("proxy.listen: bad port in '\(s)'") }
        return ("127.0.0.1", p)
    }

    static func isValidRouteName(_ n: String) -> Bool {
        guard !n.isEmpty, n.count <= 64 else { return false }
        return n.unicodeScalars.allSatisfy { c in
            (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "_" || c == "-" || c == "."
        }
    }

    /// Parse a duration like "30s", "15m", "1h", "1d" into seconds.
    public static func parseDuration(_ s: String) -> TimeInterval? {
        guard let unit = s.last, let n = Double(s.dropLast()), n >= 0 else { return Double(s) }
        switch unit {
        case "s": return n
        case "m": return n * 60
        case "h": return n * 3600
        case "d": return n * 86400
        default: return nil
        }
    }
}

public struct ProxyRoute: Equatable {
    public var name: String
    /// Upstream base URL (scheme + host [+ port] [+ path prefix]), no trailing slash.
    public var upstream: String
    /// Environment variable `safeski proxy run` sets to this route's base URL.
    public var env: String?
    /// Headers injected into every forwarded request. Values may embed `secret:NAME`.
    public var headers: [(name: String, value: String)] = []
    /// Request header names removed before forwarding (lower-case).
    public var strip: [String] = []
    public var rules: [ProxyRule] = []
    public var budget: ProxyBudget?
    public var comment: String?

    public static func == (a: ProxyRoute, b: ProxyRoute) -> Bool {
        a.name == b.name && a.upstream == b.upstream && a.env == b.env && a.strip == b.strip && a.rules == b.rules
            && a.budget == b.budget && a.headers.map { "\($0.name)=\($0.value)" } == b.headers.map { "\($0.name)=\($0.value)" }
    }

    public init(name: String, upstream: String) { self.name = name; self.upstream = upstream }

    /// Secret names referenced by the injected headers.
    public var secretNames: [String] {
        var out: [String] = []
        for h in headers { for s in ProxyRoute.secretRefs(in: h.value) where !out.contains(s) { out.append(s) } }
        return out
    }

    /// Find every `secret:NAME` reference in a header value.
    public static func secretRefs(in value: String) -> [String] {
        var out: [String] = []
        var rest = Substring(value)
        while let r = rest.range(of: "secret:") {
            let after = rest[r.upperBound...]
            let name = after.prefix { c in c.isLetter || c.isNumber || c == "_" || c == "-" || c == "." }
            if !name.isEmpty { out.append(String(name)) }
            rest = after.dropFirst(name.count)
        }
        return out
    }

    /// Replace each `secret:NAME` reference with its resolved value.
    public static func substitute(_ value: String, resolve: (String) throws -> String) throws -> String {
        var out = ""
        var rest = Substring(value)
        while let r = rest.range(of: "secret:") {
            out += rest[..<r.lowerBound]
            let after = rest[r.upperBound...]
            let name = after.prefix { c in c.isLetter || c.isNumber || c == "_" || c == "-" || c == "." }
            if name.isEmpty { out += "secret:"; rest = after; continue }
            out += try resolve(String(name))
            rest = after.dropFirst(name.count)
        }
        out += rest
        return out
    }

    static func parse(name: String, _ v: JSONValue) throws -> ProxyRoute {
        let where_ = "proxy.routes.\(name)"
        guard let up = v["upstream"]?.stringValue, !up.isEmpty else { throw SafeskiError.policy("\(where_): missing upstream") }
        guard let u = URL(string: up), let scheme = u.scheme?.lowercased(), ["http", "https"].contains(scheme), u.host != nil else {
            throw SafeskiError.policy("\(where_).upstream: must be an http(s) URL")
        }
        var upstream = up
        while upstream.hasSuffix("/") { upstream.removeLast() }
        var r = ProxyRoute(name: name, upstream: upstream)
        r.env = v["env"]?.stringValue
        r.comment = v["comment"]?.stringValue
        if let h = v["headers"]?.objectValue {
            for (k, hv) in h.sorted(by: { $0.key < $1.key }) {
                guard let s = hv.stringValue else { throw SafeskiError.policy("\(where_).headers.\(k): must be a string") }
                guard HTTPRequest.isValidHeaderName(k) else { throw SafeskiError.policy("\(where_).headers: bad header name '\(k)'") }
                r.headers.append((k, s))
            }
        }
        if let s = v["strip"] {
            guard let arr = s.stringArray else { throw SafeskiError.policy("\(where_).strip: must be an array of strings") }
            r.strip = arr.map { $0.lowercased() }
        }
        if let rules = v["rules"] {
            guard let arr = rules.arrayValue else { throw SafeskiError.policy("\(where_).rules: must be an array") }
            for (i, rv) in arr.enumerated() {
                do { r.rules.append(try ProxyRule.parse(rv)) }
                catch let e as SafeskiError { throw SafeskiError.policy("\(where_).rules[\(i)]: \(e.message)") }
            }
        }
        if let b = v["budget"] {
            guard let n = b["requests"]?.intValue, n > 0 else { throw SafeskiError.policy("\(where_).budget: requests must be > 0") }
            var per: TimeInterval = 3600
            if let p = b["per"]?.stringValue {
                guard let secs = ProxyConfig.parseDuration(p), secs > 0 else { throw SafeskiError.policy("\(where_).budget.per: bad duration '\(p)'") }
                per = secs
            } else if let p = b["per"]?.doubleValue, p > 0 { per = p }
            r.budget = ProxyBudget(requests: n, per: per)
        }
        return r
    }

    /// First matching rule for a request, or nil.
    public func rule(for method: String, path: String, caller: CallerIdentity) -> ProxyRule? {
        rules.first { $0.matches(method: method, path: path, caller: caller) }
    }
}

public struct ProxyBudget: Equatable {
    public var requests: Int
    public var per: TimeInterval
    public init(requests: Int, per: TimeInterval) { self.requests = requests; self.per = per }
}

/// A route rule: first match wins, no match denies.
public struct ProxyRule: Equatable {
    /// Upper-case HTTP methods; empty means any.
    public var methods: [String] = []
    /// Glob over the request path (see `Glob`).
    public var path: String = "/**"
    public var approve: ApprovalMode = .never
    public var ttl: Double?
    /// Optional caller matchers (parent, team_id, signing_id, uid, token), same semantics as secret rules.
    public var caller: Rule?
    public var comment: String?

    public init(methods: [String] = [], path: String = "/**", approve: ApprovalMode = .never, ttl: Double? = nil, caller: Rule? = nil) {
        self.methods = methods.map { $0.uppercased() }; self.path = path; self.approve = approve; self.ttl = ttl; self.caller = caller
    }

    static func parse(_ v: JSONValue) throws -> ProxyRule {
        guard v.objectValue != nil else { throw SafeskiError.policy("rule must be a table") }
        var r = ProxyRule()
        if let m = v["methods"] {
            guard let arr = m.stringArray else { throw SafeskiError.policy("methods must be an array of strings") }
            r.methods = arr.map { $0.uppercased() }
        } else if let m = v["method"]?.stringValue {
            r.methods = [m.uppercased()]
        }
        if let p = v["path"]?.stringValue { r.path = p }
        if let a = v["approve"]?.stringValue {
            guard let mode = ApprovalMode(rawValue: a) else { throw SafeskiError.policy("unknown approve mode '\(a)'") }
            r.approve = mode
        }
        r.ttl = v["ttl"]?.doubleValue
        r.comment = v["comment"]?.stringValue
        var c = Rule()
        c.parent = v["parent"]?.stringValue
        c.teamID = v["team_id"]?.stringValue
        c.signingID = v["signing_id"]?.stringValue
        c.uid = v["uid"]?.intValue
        c.token = v["token"]?.stringValue
        if let exe = v["exe"]?.stringValue { c.path = exe }
        if !c.isEmpty { r.caller = c }
        return r
    }

    public func matches(method: String, path: String, caller: CallerIdentity) -> Bool {
        if !methods.isEmpty, !methods.contains(method.uppercased()) { return false }
        guard Glob.match(self.path, path) else { return false }
        if let c = self.caller, !c.matches(caller) { return false }
        return true
    }
}
