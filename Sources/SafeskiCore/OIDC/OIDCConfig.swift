import Foundation

/// The `[oidc]` section of policy.toml.
///
/// ```toml
/// [oidc]
/// issuer = "https://oidc.example.com/my-mac"   # public HTTPS URL (AWS requires it)
/// key = "oidc"                                        # enclave-signing key name
/// default_ttl = 3600
/// listen = "127.0.0.1:7866"                           # optional local discovery/JWKS server
/// [oidc.subjects]
/// default = "device:{device_id}"
/// ```
public struct OIDCConfig: Equatable {
    public static let defaultKeyName = "oidc"
    public static let defaultTTL: TimeInterval = 3600
    public static let maxTTL: TimeInterval = 86400

    /// Normalized issuer (no trailing slash). nil when the section is absent or has no issuer.
    public var issuer: String?
    public var key: String = OIDCConfig.defaultKeyName
    public var defaultTTL: TimeInterval = OIDCConfig.defaultTTL
    /// "host:port" for the local HTTP discovery server; nil disables it.
    public var listen: String?
    /// Named subject templates. Placeholders: {device_id} {device_name} {key} {user} {host}.
    public var subjects: [String: String] = [:]
    /// Whether a `[oidc]` table was present at all.
    public var isConfigured: Bool = false

    public init() {}

    public init(policy: PolicyDocument) throws {
        try self.init(raw: policy.raw)
    }

    public init(raw: JSONValue) throws {
        guard let o = raw["oidc"]?.objectValue else { return }
        isConfigured = true
        if let iss = o["issuer"]?.stringValue {
            issuer = try OIDCConfig.normalizeIssuer(iss)
        }
        if let k = o["key"]?.stringValue {
            try Names.validate(k)
            key = k
        }
        if let t = o["default_ttl"]?.doubleValue {
            guard t > 0, t <= OIDCConfig.maxTTL else { throw SafeskiError.policy("oidc.default_ttl must be 1...\(Int(OIDCConfig.maxTTL)) seconds") }
            defaultTTL = t
        }
        if let l = o["listen"]?.stringValue, !l.isEmpty {
            _ = try OIDCConfig.parseListen(l)
            listen = l
        }
        if let subs = o["subjects"]?.objectValue {
            for (name, v) in subs {
                guard let s = v.stringValue else { throw SafeskiError.policy("oidc.subjects.\(name) must be a string") }
                subjects[name] = s
            }
        }
    }

    public func requireIssuer() throws -> String {
        guard let iss = issuer else {
            throw SafeskiError.policy("oidc.issuer is not set; add an [oidc] section to policy.toml (see `safeski oidc setup`)")
        }
        return iss
    }

    /// Validate and normalize an issuer URL: http(s), has a host, no query/fragment, no trailing slash.
    public static func normalizeIssuer(_ s: String) throws -> String {
        var str = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while str.hasSuffix("/") { str.removeLast() }
        guard let url = URL(string: str), let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let host = url.host, !host.isEmpty else {
            throw SafeskiError.policy("oidc.issuer must be an http(s) URL with a host, got '\(s)'")
        }
        guard url.query == nil, url.fragment == nil else {
            throw SafeskiError.policy("oidc.issuer must not contain a query or fragment")
        }
        return str
    }

    /// The issuer without its scheme ("oidc.example.com/path"), which is how AWS names the
    /// IAM OIDC provider and its condition keys.
    public static func providerPath(issuer: String) -> String {
        if let r = issuer.range(of: "://") { return String(issuer[r.upperBound...]) }
        return issuer
    }

    /// Parse "host:port", ":port" or "port" into an IPv4 host and port.
    public static func parseListen(_ s: String) throws -> (host: String, port: UInt16) {
        var host = "127.0.0.1"
        var portStr = s
        if let colon = s.lastIndex(of: ":") {
            let h = String(s[..<colon])
            if !h.isEmpty { host = h }
            portStr = String(s[s.index(after: colon)...])
        }
        if host == "localhost" { host = "127.0.0.1" }
        guard let port = UInt16(portStr), port > 0 else { throw SafeskiError.policy("oidc.listen: bad port in '\(s)'") }
        return (host, port)
    }

    /// Expand a subject template or return the literal.
    public func subject(_ requested: String?, deviceID: String, deviceName: String, key: String) -> String {
        let template: String
        if let r = requested {
            template = subjects[r] ?? r
        } else {
            template = subjects["default"] ?? "device:{device_id}"
        }
        return OIDCConfig.expand(template, deviceID: deviceID, deviceName: deviceName, key: key)
    }

    static func expand(_ template: String, deviceID: String, deviceName: String, key: String) -> String {
        var s = template
        let user = ProcessInfo.processInfo.environment["USER"] ?? NSUserName()
        let host = Host.current().localizedName ?? deviceName
        let vars: [(String, String)] = [
            ("{device_id}", deviceID), ("{device_name}", deviceName), ("{key}", key), ("{user}", user), ("{host}", host),
        ]
        for (k, v) in vars { s = s.replacingOccurrences(of: k, with: v) }
        return s
    }

    /// The policy.toml block to add for a given issuer.
    public static func sampleTOML(issuer: String, key: String = OIDCConfig.defaultKeyName, listen: String? = "127.0.0.1:7866") -> String {
        var s = """
        [oidc]
        issuer = "\(issuer)"
        key = "\(key)"
        default_ttl = 3600

        """
        if let l = listen { s += "listen = \"\(l)\"     # local discovery + JWKS for consumers on this Mac; remove to disable\n" }
        s += """

        [oidc.subjects]
        default = "device:{device_id}"

        # Who may mint tokens with the key. Container/remote callers use a session token:
        # [keys.\(key)]
        # rules = [
        #   { token = "ci-runner", approve = "never" },
        # ]
        """
        return s
    }
}
