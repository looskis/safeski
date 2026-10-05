import Foundation
import Testing
@testable import SafeskiCore

private func isDeny(_ d: Decision) -> Bool { if case .deny = d.verdict { return true }; return false }
private func denyMessage(_ d: Decision) -> String { if case .deny(let m) = d.verdict { return m }; return "" }

@Suite("Policy parsing")
struct PolicyParseTests {
    @Test func fullDocument() throws {
        let doc = try Policy.parse("""
        [defaults]
        approve = "always"
        ttl = 60
        require_valid_signature = true
        deny_unmatched = true

        [keys.github-ssh]
        access = "biometry-any"
        comment = "ssh key"
        rules = [
          { path = "/usr/bin/ssh", approve = "never", comment = "ssh itself" },
          { parent = "**/claude", approve = "once", ttl = 3600 },
        ]

        [secrets.API_KEY]
        rules = [
          { token = "ci", approve = "never" },
          { uid = 501, team_id = "ABCDE12345", signing_id = "com.example.app", approve = "touchid" },
        ]

        [tokens.ci]
        hash = "0123abcd"
        expires = "2030-01-01T00:00:00Z"
        comment = "ci runner"

        [tokens.forever]
        hash = "ffff"
        """)
        #expect(doc.defaults.approve == .always)
        #expect(doc.defaults.ttl == 60)
        #expect(doc.defaults.requireValidSignature)
        #expect(doc.defaults.denyUnmatched)

        let key = try #require(doc.keys["github-ssh"])
        #expect(key.access == .biometryAny)
        #expect(key.comment == "ssh key")
        #expect(key.rules.count == 2)
        #expect(key.rules[0] == Rule(path: "/usr/bin/ssh", approve: .never, comment: "ssh itself"))
        #expect(key.rules[1] == Rule(parent: "**/claude", approve: .once, ttl: 3600))

        let sec = try #require(doc.secrets["API_KEY"])
        #expect(sec.access == nil)
        #expect(sec.rules[0] == Rule(token: "ci", approve: .never))
        #expect(sec.rules[1] == Rule(teamID: "ABCDE12345", signingID: "com.example.app", uid: 501, approve: .touchid))

        let ci = try #require(doc.tokens["ci"])
        #expect(ci.hash == "0123abcd")
        #expect(ci.comment == "ci runner")
        #expect(ci.expires == ISO8601DateFormatter().date(from: "2030-01-01T00:00:00Z"))
        #expect(doc.tokens["forever"]?.expires == nil)

        // raw tree is preserved for other modules
        #expect(doc.raw["tokens"]?["ci"]?["hash"]?.stringValue == "0123abcd")
    }

    @Test func emptyAndDefaultDocuments() throws {
        let empty = try Policy.parse("")
        #expect(empty == PolicyDocument())
        let def = try Policy.parse(PolicyDocument.defaultTOML)
        #expect(def.defaults.approve == .once)
        #expect(def.defaults.ttl == 300)
        #expect(def.keys.isEmpty && def.secrets.isEmpty && def.tokens.isEmpty)
    }

    @Test func loadMissingFileGivesDefaults() throws {
        let home = try TempHome("pol")
        defer { home.cleanup() }
        #expect(try Policy.load(from: home.paths.policy) == PolicyDocument())
        try home.writePolicy("[defaults]\napprove = \"deny\"")
        #expect(try Policy.load(from: home.paths.policy).defaults.approve == .deny)
    }

    @Test func parseErrors() {
        #expect(safeskiError { _ = try Policy.parse("[defaults]\napprove = \"maybe\"") }?.code == "policy")
        #expect(safeskiError { _ = try Policy.parse("[keys.k]\naccess = \"nope\"") }?.message.contains("keys.k.access") == true)
        #expect(safeskiError { _ = try Policy.parse("[secrets.s]\nrules = [ { approve = \"maybe\" } ]") }?.message.contains("secrets.s.rules[0]") == true)
        #expect(safeskiError { _ = try Policy.parse("[tokens.t]\ncomment = \"no hash\"") }?.message.contains("missing hash") == true)
        // TOML syntax errors surface as policy errors too
        #expect(safeskiError { _ = try Policy.parse("a = ") }?.code == "policy")
    }
}

@Suite("Policy evaluation")
struct PolicyEvaluateTests {
    private func doc(_ toml: String) throws -> PolicyDocument { try Policy.parse(toml) }

    @Test func firstMatchWins() throws {
        let d = try doc("""
        [keys.k]
        rules = [
          { path = "/usr/bin/ssh", approve = "deny" },
          { path = "/usr/bin/*", approve = "never" },
          { path = "/usr/bin/ssh", approve = "never" },
        ]
        """)
        let ssh = Policy.evaluate(d, kind: "key", resource: "k", caller: .testUnix(path: "/usr/bin/ssh"))
        #expect(isDeny(ssh))
        #expect(ssh.rule?.path == "/usr/bin/ssh")
        let git = Policy.evaluate(d, kind: "key", resource: "k", caller: .testUnix(path: "/usr/bin/git"))
        #expect(git.verdict == .allow)
        #expect(git.rule?.path == "/usr/bin/*")
    }

    @Test func approveModes() throws {
        let d = try doc("""
        [defaults]
        approve = "always"
        ttl = 77
        [secrets.never]
        rules = [ { uid = \(getuid()), approve = "never" } ]
        [secrets.deny]
        rules = [ { uid = \(getuid()), approve = "deny" } ]
        [secrets.once]
        rules = [ { uid = \(getuid()), approve = "once", ttl = 5 } ]
        [secrets.always]
        rules = [ { uid = \(getuid()), approve = "always" } ]
        [secrets.touch]
        rules = [ { uid = \(getuid()), approve = "touchid" } ]
        [secrets.inherit]
        rules = [ { uid = \(getuid()) } ]
        """)
        let c = CallerIdentity.testUnix()
        let never = Policy.evaluate(d, kind: "secret", resource: "never", caller: c)
        #expect(never.verdict == .allow)
        #expect(never.rule != nil)

        let deny = Policy.evaluate(d, kind: "secret", resource: "deny", caller: c)
        #expect(isDeny(deny))
        #expect(denyMessage(deny).contains("rule denies"))

        let once = Policy.evaluate(d, kind: "secret", resource: "once", caller: c)
        #expect(once.verdict == .approve(.once))
        #expect(once.ttl == 5)

        let always = Policy.evaluate(d, kind: "secret", resource: "always", caller: c)
        #expect(always.verdict == .approve(.always))
        #expect(always.ttl == 77)

        #expect(Policy.evaluate(d, kind: "secret", resource: "touch", caller: c).verdict == .approve(.touchid))

        // no approve on the rule -> defaults.approve, defaults.ttl
        let inherit = Policy.evaluate(d, kind: "secret", resource: "inherit", caller: c)
        #expect(inherit.verdict == .approve(.always))
        #expect(inherit.ttl == 77)
    }

    @Test func noRulesLocalAllows() throws {
        let d = try doc("[defaults]\napprove = \"once\"")
        let r = Policy.evaluate(d, kind: "key", resource: "anything", caller: .local())
        #expect(r.verdict == .allow)
        #expect(r.rule == nil)
    }

    @Test func noRulesUnixUsesDefaults() throws {
        let once = Policy.evaluate(try doc("[defaults]\napprove = \"once\"\nttl = 42"), kind: "key", resource: "k", caller: .testUnix())
        #expect(once.verdict == .approve(.once))
        #expect(once.ttl == 42)
        #expect(once.rule == nil)

        let never = Policy.evaluate(try doc("[defaults]\napprove = \"never\""), kind: "key", resource: "k", caller: .testUnix())
        #expect(never.verdict == .allow)

        let deny = Policy.evaluate(try doc("[defaults]\napprove = \"deny\""), kind: "key", resource: "k", caller: .testUnix())
        #expect(isDeny(deny))
        #expect(denyMessage(deny).contains("default policy denies"))

        let touch = Policy.evaluate(try doc("[defaults]\napprove = \"touchid\""), kind: "secret", resource: "s", caller: .testUnix())
        #expect(touch.verdict == .approve(.touchid))
    }

    @Test func denyUnmatched() throws {
        let d = try doc("[defaults]\napprove = \"never\"\ndeny_unmatched = true")
        let unix = Policy.evaluate(d, kind: "secret", resource: "s", caller: .testUnix())
        #expect(isDeny(unix))
        #expect(denyMessage(unix).contains("no rule for"))
        // deny_unmatched applies to local callers as well
        #expect(isDeny(Policy.evaluate(d, kind: "secret", resource: "s", caller: .local())))
    }

    @Test func rulesPresentButNoneMatchDenies() throws {
        let d = try doc("""
        [defaults]
        approve = "never"
        [keys.k]
        rules = [ { path = "/usr/bin/ssh" } ]
        """)
        let r = Policy.evaluate(d, kind: "key", resource: "k", caller: .testUnix(path: "/usr/bin/git"))
        #expect(isDeny(r))
        #expect(denyMessage(r).contains("no rule for"))
        #expect(r.rule == nil)
        // even for the local CLI: once rules exist for a resource they are authoritative
        #expect(isDeny(Policy.evaluate(d, kind: "key", resource: "k", caller: .local())))
        // other resources are unaffected
        #expect(Policy.evaluate(d, kind: "key", resource: "other", caller: .testUnix(path: "/usr/bin/git")).verdict == .allow)
    }

    @Test func wildcardResourceFallback() throws {
        let d = try doc("""
        [secrets."*"]
        rules = [ { uid = \(getuid()), approve = "never" } ]
        [secrets.special]
        rules = [ { uid = \(getuid()), approve = "deny" } ]
        """)
        #expect(Policy.evaluate(d, kind: "secret", resource: "random", caller: .testUnix()).verdict == .allow)
        #expect(isDeny(Policy.evaluate(d, kind: "secret", resource: "special", caller: .testUnix())))
        // keys table is separate from secrets
        #expect(Policy.evaluate(d, kind: "key", resource: "random", caller: .testUnix()).verdict == .approve(.once))
    }

    @Test func requireValidSignature() throws {
        let d = try doc("""
        [defaults]
        require_valid_signature = true
        [keys.k]
        rules = [ { uid = \(getuid()), approve = "never" } ]
        """)
        var c = CallerIdentity.testUnix()
        let unknown = Policy.evaluate(d, kind: "key", resource: "k", caller: c)
        #expect(isDeny(unknown))
        #expect(denyMessage(unknown).contains("signature"))
        #expect(unknown.rule == nil)

        c.signatureValid = false
        #expect(isDeny(Policy.evaluate(d, kind: "key", resource: "k", caller: c)))

        c.signatureValid = true
        #expect(Policy.evaluate(d, kind: "key", resource: "k", caller: c).verdict == .allow)

        // only unix peers are subject to the signature check
        var local = CallerIdentity.local(); local.signatureValid = nil
        #expect(Policy.evaluate(d, kind: "key", resource: "other", caller: local).verdict == .allow)
        var tok = CallerIdentity(transport: "token"); tok.tokenName = "t"
        #expect(Policy.evaluate(d, kind: "key", resource: "other", caller: tok).verdict == .approve(.once))
    }
}

@Suite("Rule matching")
struct RuleMatchTests {
    @Test func emptyRuleMatchesEverything() {
        #expect(Rule().isEmpty)
        #expect(Rule().matches(.testUnix()))
        #expect(Rule().matches(CallerIdentity(transport: "token")))
        #expect(Rule(approve: .never, ttl: 5).isEmpty)   // approve/ttl alone keep the rule "empty"
    }

    @Test func pathGlobs() {
        let ssh = CallerIdentity.testUnix(path: "/opt/homebrew/bin/ssh")
        #expect(Rule(path: "/opt/homebrew/bin/ssh").matches(ssh))
        #expect(Rule(path: "/opt/homebrew/**").matches(ssh))
        #expect(Rule(path: "**/ssh").matches(ssh))
        #expect(Rule(path: "/opt/homebrew/bin/*").matches(ssh))
        #expect(!Rule(path: "/opt/*/ssh").matches(ssh))
        #expect(!Rule(path: "/usr/bin/ssh").matches(ssh))
        #expect(!Rule(path: "/opt/homebrew/bin/ssh").matches(.testUnix(path: nil)))
    }

    @Test func parentMatchesParentPathOrScript() {
        var c = CallerIdentity.testUnix(path: "/usr/local/bin/node")
        c.parentPath = "/bin/zsh"
        c.commandLine = ["/usr/local/bin/node", "/Users/me/.npm/bin/claude", "--flag"]
        #expect(Rule(parent: "/bin/zsh").matches(c))
        #expect(Rule(parent: "**/claude").matches(c))
        #expect(!Rule(parent: "**/codex").matches(c))
        // argv[2] is never considered
        #expect(!Rule(parent: "--flag").matches(c))

        var bare = CallerIdentity.testUnix(path: "/usr/bin/ssh")
        bare.commandLine = ["ssh"]
        #expect(!Rule(parent: "**/claude").matches(bare))
    }

    @Test func teamSigningUidToken() {
        var c = CallerIdentity.testUnix(path: "/Applications/X.app/Contents/MacOS/X", uid: 501)
        c.teamID = "ABCDE12345"; c.signingID = "com.example.x"
        #expect(Rule(teamID: "ABCDE12345").matches(c))
        #expect(!Rule(teamID: "ZZZZZ99999").matches(c))
        #expect(Rule(signingID: "com.example.x").matches(c))
        #expect(!Rule(signingID: "com.example.y").matches(c))
        #expect(Rule(uid: 501).matches(c))
        #expect(!Rule(uid: 502).matches(c))
        #expect(!Rule(uid: 501).matches(CallerIdentity(transport: "unix")))
        // all listed attributes must match
        #expect(Rule(path: "**/X", teamID: "ABCDE12345", uid: 501).matches(c))
        #expect(!Rule(teamID: "ABCDE12345", uid: 502).matches(c))

        var t = CallerIdentity(transport: "token"); t.tokenName = "ci"
        #expect(Rule(token: "ci").matches(t))
        #expect(!Rule(token: "other").matches(t))
        #expect(!Rule(token: "ci").matches(c))
    }

    @Test(.requiresEnclave, .enclaveSerialized) func tokenCallersDoNotMatchPathRules() throws {
        var t = CallerIdentity(transport: "token"); t.tokenName = "ci"
        #expect(t.path == nil)
        #expect(!Rule(path: "**").matches(t))
        #expect(!Rule(path: "/usr/bin/ssh", token: "ci").matches(t))
        #expect(!Rule(uid: Int(getuid())).matches(t))
        #expect(Rule(token: "ci").matches(t))
        // a resolved token caller carries no peer attributes at all
        var base = CallerIdentity.testUnix(path: "/usr/bin/relay")
        base.commandLine = ["/usr/bin/relay", "/x/claude"]; base.parentPath = "/x/claude"; base.teamID = "T"
        let home = try TempHome("tokres")
        defer { home.cleanup() }
        let store = Store(paths: home.paths)
        try store.initialize()
        try home.writePolicy("[tokens.ci]\nhash = \"\(sha256Hex("tok"))\"")
        let svc = try Service(store: store, interactive: false)
        let resolved = try #require(svc.resolveToken("tok", base: base))
        #expect(resolved.tokenName == "ci" && resolved.transport == "token")
        #expect(resolved.uid == nil && resolved.gid == nil && resolved.path == nil && resolved.parentPath == nil)
        #expect(resolved.commandLine == nil && resolved.teamID == nil && resolved.signingID == nil)
        #expect(!Rule(uid: Int(getuid())).matches(resolved))
        #expect(!Rule(parent: "**/claude").matches(resolved))
        #expect(Rule(token: "ci").matches(resolved))
        #expect(svc.resolveToken("other", base: base) == nil)
    }
}

@Suite("Glob")
struct GlobTests {
    @Test func doubleStarCrossesSlashes() {
        #expect(Glob.match("**", "/any/thing/at/all"))
        #expect(Glob.match("**", ""))
        #expect(Glob.match("/usr/**", "/usr/local/bin/ssh"))
        #expect(Glob.match("/usr/**/ssh", "/usr/local/bin/ssh"))
        #expect(Glob.match("/usr/**/ssh", "/usr/ssh"))
        #expect(Glob.match("**/claude", "claude"))
        #expect(Glob.match("**/claude", "/a/b/claude"))
        #expect(!Glob.match("**/claude", "/a/b/claude2"))
    }

    @Test func singleStarStopsAtSlash() {
        #expect(Glob.match("/usr/*", "/usr/bin"))
        #expect(!Glob.match("/usr/*", "/usr/bin/ssh"))
        #expect(Glob.match("/usr/*/ssh", "/usr/bin/ssh"))
        #expect(!Glob.match("/usr/*/ssh", "/usr/local/bin/ssh"))
        #expect(Glob.match("*.py", "script.py"))
        #expect(!Glob.match("*.py", "dir/script.py"))
        #expect(Glob.match("/a/*", "/a/"))
    }

    @Test func questionMark() {
        #expect(Glob.match("/bin/sh?", "/bin/shx"))
        #expect(!Glob.match("/bin/sh?", "/bin/sh"))
        #expect(!Glob.match("/bin/sh?", "/bin/shxx"))
        #expect(Glob.match("python?", "python3"))
    }

    @Test func literalAndEdgeCases() {
        #expect(Glob.match("", ""))
        #expect(!Glob.match("", "x"))
        #expect(!Glob.match("x", ""))
        #expect(Glob.match("/exact/path", "/exact/path"))
        #expect(!Glob.match("/exact/path", "/exact/path/"))
        #expect(Glob.match("a*b*c", "aXXbYYc"))
        #expect(!Glob.match("a*b*c", "aXXbYY"))
    }

    @Test func tildeExpansion() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        #expect(Glob.match("~/bin/tool", home + "/bin/tool"))
        #expect(Glob.match("~/**", home + "/anything/deep"))
        #expect(!Glob.match("~/bin/tool", "/other/bin/tool"))
    }
}
