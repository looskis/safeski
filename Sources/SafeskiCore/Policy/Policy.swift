import Foundation

/// Policy document model. Loaded from policy.toml; the raw tree is kept so other modules
/// (proxy, oidc) can read their own sections without the core needing to know them.
public struct PolicyDocument: Equatable {
    public var defaults: Defaults
    public var keys: [String: ResourcePolicy]
    public var secrets: [String: ResourcePolicy]
    public var tokens: [String: TokenPolicy]
    public var raw: JSONValue

    public struct Defaults: Codable, Equatable {
        /// Default approval mode when a rule does not specify one.
        public var approve: ApprovalMode = .once
        /// Approval cache TTL in seconds.
        public var ttl: Double = 300
        /// Reject callers whose code signature failed validation.
        public var requireValidSignature: Bool = false
        /// Deny anything that no rule matches (true) or just require approval (false).
        public var denyUnmatched: Bool = false
        public init() {}
    }

    public init(defaults: Defaults = .init(), keys: [String: ResourcePolicy] = [:], secrets: [String: ResourcePolicy] = [:],
                tokens: [String: TokenPolicy] = [:], raw: JSONValue = .object([:])) {
        self.defaults = defaults; self.keys = keys; self.secrets = secrets; self.tokens = tokens; self.raw = raw
    }

    public static let defaultTOML = """
    # safeski policy. Reloaded by the agent when it changes.
    #
    # Who may use what. A caller matches a rule when every listed attribute matches.
    #   path       = "/usr/bin/ssh"            exact executable path (globs ok: "/opt/homebrew/**")
    #   parent     = "**/claude"               executable path of the caller's parent process
    #   team_id    = "ABCDE12345"              Apple Team ID from the code signature
    #   signing_id = "com.apple.ssh"           code-signing identifier
    #   uid        = 501
    #   token      = "ci-runner"               a safeski session token (containers, remote)
    #   approve    = "never" | "once" | "always" | "touchid"   (default: [defaults].approve)
    #   ttl        = 600                       approval cache seconds for this rule
    #
    # A resource with no rules falls back to the defaults below.

    [defaults]
    approve = "once"      # ask once per caller per TTL window
    ttl = 300
    deny_unmatched = false

    # [keys.github-ssh]
    # access = "biometry-any"
    # rules = [
    #   { path = "/usr/bin/ssh", approve = "never" },
    #   { path = "/usr/bin/git", approve = "never" },
    # ]

    # [secrets.ANTHROPIC_API_KEY]
    # rules = [
    #   { parent = "**/claude", approve = "once", ttl = 3600 },
    #   { token = "docker-dev", approve = "never" },
    # ]
    """
}

public enum ApprovalMode: String, Codable, Equatable {
    /// Allow silently.
    case never
    /// Ask once per (caller, resource) and cache for ttl.
    case once
    /// Ask on every use.
    case always
    /// Require biometric/passcode authentication on every use (LocalAuthentication).
    case touchid
    /// Deny.
    case deny
}

public struct Rule: Codable, Equatable {
    public var path: String?
    public var parent: String?
    public var teamID: String?
    public var signingID: String?
    public var uid: Int?
    public var token: String?
    public var approve: ApprovalMode?
    public var ttl: Double?
    public var comment: String?

    enum CodingKeys: String, CodingKey {
        case path, parent, uid, token, approve, ttl, comment
        case teamID = "team_id", signingID = "signing_id"
    }

    public init(path: String? = nil, parent: String? = nil, teamID: String? = nil, signingID: String? = nil, uid: Int? = nil,
                token: String? = nil, approve: ApprovalMode? = nil, ttl: Double? = nil, comment: String? = nil) {
        self.path = path; self.parent = parent; self.teamID = teamID; self.signingID = signingID; self.uid = uid
        self.token = token; self.approve = approve; self.ttl = ttl; self.comment = comment
    }

    public var isEmpty: Bool { path == nil && parent == nil && teamID == nil && signingID == nil && uid == nil && token == nil }

    public func matches(_ c: CallerIdentity) -> Bool {
        if isEmpty { return true }
        if let p = path { guard let cp = c.path, Glob.match(p, cp) else { return false } }
        if let p = parent {
            // parent may match the parent executable or, for interpreters, the script in argv[1]
            let candidates = [c.parentPath, c.commandLine?.dropFirst().first].compactMap { $0 }
            guard candidates.contains(where: { Glob.match(p, $0) }) else { return false }
        }
        if let t = teamID { guard c.teamID == t else { return false } }
        if let s = signingID { guard c.signingID == s else { return false } }
        if let u = uid { guard let cu = c.uid, Int(cu) == u else { return false } }
        if let t = token { guard c.tokenName == t else { return false } }
        return true
    }
}

public struct ResourcePolicy: Codable, Equatable {
    public var access: AccessPolicy?
    public var rules: [Rule]
    public var comment: String?
    public init(access: AccessPolicy? = nil, rules: [Rule] = [], comment: String? = nil) {
        self.access = access; self.rules = rules; self.comment = comment
    }
}

/// Session tokens for callers that cannot be identified by peer credentials (containers, remote).
public struct TokenPolicy: Codable, Equatable {
    /// SHA-256 hex of the bearer token (the token itself is shown once at creation).
    public var hash: String
    public var expires: Date?
    public var comment: String?
}

public struct Decision: Equatable {
    public enum Verdict: Equatable { case allow, deny(String), approve(ApprovalMode) }
    public var verdict: Verdict
    public var rule: Rule?
    public var ttl: Double
}

public enum Policy {
    public static func load(from url: URL) throws -> PolicyDocument {
        guard FileIO.exists(url) else { return PolicyDocument() }
        let text = String(decoding: try FileIO.read(url), as: UTF8.self)
        return try parse(text)
    }

    public static func parse(_ text: String) throws -> PolicyDocument {
        let tree: JSONValue
        do { tree = try TOMLParser.parse(text) }
        catch { throw SafeskiError.policy(error.localizedDescription) }
        var doc = PolicyDocument(raw: tree)
        if let d = tree["defaults"] {
            if let a = d["approve"]?.stringValue {
                guard let m = ApprovalMode(rawValue: a) else { throw SafeskiError.policy("defaults.approve: unknown mode '\(a)'") }
                doc.defaults.approve = m
            }
            if let t = d["ttl"]?.doubleValue { doc.defaults.ttl = t }
            if let b = d["require_valid_signature"]?.boolValue { doc.defaults.requireValidSignature = b }
            if let b = d["deny_unmatched"]?.boolValue { doc.defaults.denyUnmatched = b }
        }
        doc.keys = try parseResources(tree["keys"], section: "keys")
        doc.secrets = try parseResources(tree["secrets"], section: "secrets")
        if let toks = tree["tokens"]?.objectValue {
            for (name, v) in toks {
                guard let h = v["hash"]?.stringValue else { throw SafeskiError.policy("tokens.\(name): missing hash") }
                var tp = TokenPolicy(hash: h, expires: nil, comment: v["comment"]?.stringValue)
                if let e = v["expires"]?.stringValue { tp.expires = ISO8601DateFormatter().date(from: e) }
                doc.tokens[name] = tp
            }
        }
        return doc
    }

    static func parseResources(_ node: JSONValue?, section: String) throws -> [String: ResourcePolicy] {
        guard let obj = node?.objectValue else { return [:] }
        var out: [String: ResourcePolicy] = [:]
        for (name, v) in obj {
            var rp = ResourcePolicy()
            if let a = v["access"]?.stringValue {
                guard let ap = AccessPolicy(rawValue: a) else { throw SafeskiError.policy("\(section).\(name).access: unknown '\(a)'") }
                rp.access = ap
            }
            rp.comment = v["comment"]?.stringValue
            if let rules = v["rules"]?.arrayValue {
                for (i, r) in rules.enumerated() {
                    do { rp.rules.append(try r.decode(Rule.self)) }
                    catch { throw SafeskiError.policy("\(section).\(name).rules[\(i)]: \(error.localizedDescription)") }
                }
            }
            out[name] = rp
        }
        return out
    }

    /// Evaluate a caller against a resource. `kind` is "key" or "secret".
    public static func evaluate(_ doc: PolicyDocument, kind: String, resource: String, caller: CallerIdentity) -> Decision {
        if doc.defaults.requireValidSignature, caller.transport == "unix" || caller.transport == "broker", caller.signatureValid != true {
            return Decision(verdict: .deny("caller code signature is invalid or unverifiable"), rule: nil, ttl: 0)
        }
        let table = kind == "key" ? doc.keys : doc.secrets
        let rp = table[resource] ?? table["*"]
        let rules = rp?.rules ?? []
        if let rule = rules.first(where: { $0.matches(caller) }) {
            let mode = rule.approve ?? doc.defaults.approve
            let ttl = rule.ttl ?? doc.defaults.ttl
            switch mode {
            case .deny: return Decision(verdict: .deny("rule denies \(caller.displayName)"), rule: rule, ttl: ttl)
            case .never: return Decision(verdict: .allow, rule: rule, ttl: ttl)
            default: return Decision(verdict: .approve(mode), rule: rule, ttl: ttl)
            }
        }
        if !rules.isEmpty || doc.defaults.denyUnmatched {
            return Decision(verdict: .deny("no rule for \(caller.displayName) on \(kind) '\(resource)'"), rule: nil, ttl: 0)
        }
        // Local in-process CLI calls by the owning user are implicitly trusted at the policy layer;
        // the enclave access policy on the key still applies.
        if caller.transport == "local" { return Decision(verdict: .allow, rule: nil, ttl: 0) }
        let mode = doc.defaults.approve
        if mode == .never { return Decision(verdict: .allow, rule: nil, ttl: doc.defaults.ttl) }
        if mode == .deny { return Decision(verdict: .deny("default policy denies"), rule: nil, ttl: 0) }
        return Decision(verdict: .approve(mode), rule: nil, ttl: doc.defaults.ttl)
    }
}

/// Shell-style glob matching with `*` (no slash), `**` (any), `?`.
public enum Glob {
    public static func match(_ pattern: String, _ s: String) -> Bool {
        let expanded = (pattern as NSString).expandingTildeInPath
        return match(Array(expanded), 0, Array(s), 0)
    }
    private static func match(_ p: [Character], _ pi: Int, _ s: [Character], _ si: Int) -> Bool {
        var pi = pi, si = si
        while pi < p.count {
            let c = p[pi]
            if c == "*" {
                if pi + 1 < p.count, p[pi + 1] == "*" {
                    var np = pi + 2
                    if np < p.count, p[np] == "/" { np += 1 }
                    if np >= p.count { return true }
                    var k = si
                    while k <= s.count {
                        if match(p, np, s, k) { return true }
                        k += 1
                    }
                    return false
                }
                var k = si
                while k <= s.count {
                    if match(p, pi + 1, s, k) { return true }
                    if k < s.count, s[k] == "/" { return false }
                    k += 1
                }
                return false
            }
            guard si < s.count else { return false }
            if c == "?" { pi += 1; si += 1; continue }
            if c != s[si] { return false }
            pi += 1; si += 1
        }
        return si == s.count
    }
}
