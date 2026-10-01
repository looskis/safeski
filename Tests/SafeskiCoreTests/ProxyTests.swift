import Foundation
import Testing
@testable import SafeskiCore

private let sampleTOML = """
[proxy]
listen = "127.0.0.1:7865"
allow_unsessioned = false

[proxy.routes.anthropic]
upstream = "https://api.anthropic.com/"
env = "ANTHROPIC_BASE_URL"
headers = { "x-api-key" = "secret:ANTHROPIC_API_KEY" }
strip = ["Authorization"]
rules = [
  { methods = ["POST"], path = "/v1/messages", approve = "never" },
  { methods = ["GET"],  path = "/**",          approve = "never" },
]
budget = { requests = 1000, per = "1h" }

[proxy.routes.github]
upstream = "https://api.github.com"
env = "GITHUB_API_URL"
headers = { authorization = "Bearer secret:GH_TOKEN", accept = "application/vnd.github+json" }
rules = [
  { methods = ["GET"], path = "/**", approve = "never" },
  { methods = ["DELETE"], path = "/repos/**", approve = "deny" },
  { methods = ["POST","PATCH","PUT","DELETE"], path = "/**", approve = "once", ttl = 600 },
]
"""

@Test func proxyConfigParsing() throws {
    let doc = try Policy.parse(sampleTOML)
    let cfg = try ProxyConfig.parse(doc.raw["proxy"])
    #expect(cfg.enabled)
    #expect(cfg.listenHost == "127.0.0.1")
    #expect(cfg.listenPort == 7865)
    #expect(!cfg.allowUnsessioned)
    #expect(cfg.routes.count == 2)
    let a = try #require(cfg.routes["anthropic"])
    #expect(a.upstream == "https://api.anthropic.com") // trailing slash trimmed
    #expect(a.env == "ANTHROPIC_BASE_URL")
    #expect(a.headers.count == 1 && a.headers[0].name == "x-api-key" && a.headers[0].value == "secret:ANTHROPIC_API_KEY")
    #expect(a.strip == ["authorization"]) // lower-cased
    #expect(a.rules.count == 2)
    #expect(a.budget == ProxyBudget(requests: 1000, per: 3600))
    #expect(a.secretNames == ["ANTHROPIC_API_KEY"])
    let g = try #require(cfg.routes["github"])
    #expect(g.secretNames == ["GH_TOKEN"])
    #expect(g.rules[2].approve == .once && g.rules[2].ttl == 600)
    #expect(g.rules[2].methods == ["POST", "PATCH", "PUT", "DELETE"])
}

@Test func proxyConfigDefaultsAndErrors() throws {
    let cfg = try ProxyConfig.parse(nil)
    #expect(cfg.listen == "127.0.0.1:7865")
    #expect(cfg.routes.isEmpty && cfg.enabled)
    #expect(try ProxyConfig.parseListen("9000") == ("127.0.0.1", 9000))
    #expect(try ProxyConfig.parseListen("[::1]:9000") == ("::1", 9000))
    #expect(ProxyConfig.parseDuration("90s") == 90)
    #expect(ProxyConfig.parseDuration("2m") == 120)
    #expect(ProxyConfig.parseDuration("1d") == 86400)
    #expect(ProxyConfig.parseDuration("x") == nil)
    #expect(throws: SafeskiError.self) { try ProxyConfig.parse(try Policy.parse("[proxy.routes.x]\nupstream = \"ftp://x\"").raw["proxy"]) }
    #expect(throws: SafeskiError.self) { try ProxyConfig.parse(try Policy.parse("[proxy.routes.x]\nupstream = \"https://x\"\nrules = [{ approve = \"maybe\" }]").raw["proxy"]) }
    #expect(throws: SafeskiError.self) { try ProxyConfig.parse(try Policy.parse("[proxy]\nlisten = \"nope:xx\"").raw["proxy"]) }
    #expect(throws: SafeskiError.self) { try ProxyConfig.parse(try Policy.parse("[proxy.routes.x]\nupstream = \"https://x\"\nbudget = { requests = 0 }").raw["proxy"]) }
}

@Test func secretSubstitution() throws {
    let out = try ProxyRoute.substitute("Bearer secret:GH_TOKEN; other=secret:B.c-d end") { name in "<\(name)>" }
    #expect(out == "Bearer <GH_TOKEN>; other=<B.c-d> end")
    #expect(ProxyRoute.secretRefs(in: "plain") == [])
    #expect(try ProxyRoute.substitute("secret:", resolve: { _ in "x" }) == "secret:")
}

@Test func ruleMatchingIsFirstMatch() throws {
    let cfg = try ProxyConfig.parse(try Policy.parse(sampleTOML).raw["proxy"])
    let g = try #require(cfg.routes["github"])
    let c = CallerIdentity(transport: "unix")
    #expect(g.rule(for: "get", path: "/repos/a/b", caller: c)?.approve == .never)
    #expect(g.rule(for: "DELETE", path: "/repos/a/b", caller: c)?.approve == .deny)
    #expect(g.rule(for: "DELETE", path: "/gists/1", caller: c)?.approve == .once)
    #expect(g.rule(for: "PATCH", path: "/repos/a/b", caller: c)?.approve == .once)
    #expect(g.rule(for: "OPTIONS", path: "/", caller: c) == nil) // no match -> deny
    let a = try #require(cfg.routes["anthropic"])
    #expect(a.rule(for: "POST", path: "/v1/messages", caller: c) != nil)
    #expect(a.rule(for: "POST", path: "/v1/messages/batch", caller: c) == nil)
    #expect(a.rule(for: "GET", path: "/v1/models", caller: c) != nil)
}

@Test func ruleCallerMatchers() throws {
    let toml = """
    [proxy.routes.x]
    upstream = "https://x"
    rules = [
      { parent = "**/claude", approve = "never" },
      { approve = "deny" },
    ]
    """
    let cfg = try ProxyConfig.parse(try Policy.parse(toml).raw["proxy"])
    let x = try #require(cfg.routes["x"])
    var claude = CallerIdentity(transport: "unix"); claude.parentPath = "/opt/homebrew/bin/claude"
    var other = CallerIdentity(transport: "unix"); other.parentPath = "/bin/zsh"
    #expect(x.rule(for: "GET", path: "/", caller: claude)?.approve == .never)
    #expect(x.rule(for: "GET", path: "/", caller: other)?.approve == .deny)
}

@Test func httpRequestParsing() throws {
    let raw = "POST /s/tok/route/v1/messages?x=1&y=2 HTTP/1.1\r\nHost: 127.0.0.1:7865\r\nContent-Type: application/json\r\nAuthorization: Bearer bogus\r\nContent-Length: 13\r\n\r\n{\"a\":\"hello\"}"
    let req = try HTTPRequestReader.parse(Data(raw.utf8))
    #expect(req.method == "POST")
    #expect(req.target == "/s/tok/route/v1/messages?x=1&y=2")
    #expect(req.path == "/s/tok/route/v1/messages")
    #expect(req.query == "x=1&y=2")
    #expect(req.version == "HTTP/1.1")
    #expect(req.header("authorization") == "Bearer bogus")
    #expect(req.header("CONTENT-TYPE") == "application/json")
    #expect(String(decoding: req.body, as: UTF8.self) == "{\"a\":\"hello\"}")
}

@Test func httpRequestParsingChunked() throws {
    let raw = "PUT /r/x/upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
    let req = try HTTPRequestReader.parse(Data(raw.utf8))
    #expect(req.method == "PUT")
    #expect(String(decoding: req.body, as: UTF8.self) == "hello world")
}

@Test func httpRequestParsingIncremental() throws {
    // Deliver the request one byte at a time to exercise buffering across reads.
    let raw = Array("GET /s/t/r/ HTTP/1.1\r\nHost: x\r\nX-Multi: a\r\n b\r\n\r\n".utf8)
    var i = 0
    let reader = HTTPRequestReader {
        guard i < raw.count else { return Data() }
        defer { i += 1 }
        return Data([raw[i]])
    }
    let req = try #require(try reader.readRequest())
    #expect(req.method == "GET" && req.target == "/s/t/r/")
    #expect(req.header("x-multi") == "a b")
    #expect(req.body.isEmpty)
    #expect(try reader.readRequest() == nil) // EOF
}

@Test func httpRequestParsingRejectsGarbage() {
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GARBAGE\r\n\r\n".utf8)) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GET http://evil/ HTTP/1.1\r\n\r\n".utf8)) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GET / HTTP/1.1\r\nBad Header\r\n\r\n".utf8)) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort".utf8)) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n".utf8)) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data("GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\n0123456789".utf8), maxBody: 4) }
    #expect(throws: HTTPError.self) { try HTTPRequestReader.parse(Data(repeating: 0x41, count: 70_000)) }
}

@Test func httpResponseFraming() {
    let head = String(decoding: HTTPResponseWriter.head(status: 429, headers: [("Retry-After", "7"), ("X", "a\r\nInjected: y")]), as: UTF8.self)
    #expect(head.hasPrefix("HTTP/1.1 429 Too Many Requests\r\n"))
    #expect(head.contains("Retry-After: 7\r\n"))
    #expect(!head.contains("\r\nInjected")) // CRLF in values is sanitized
    #expect(String(decoding: HTTPResponseWriter.chunk(Data("hello".utf8)), as: UTF8.self) == "5\r\nhello\r\n")
    let j = String(decoding: HTTPResponseWriter.json(status: 403, ["error": .string("x")]), as: UTF8.self)
    #expect(j.contains("Content-Length: 13\r\n") && j.hasSuffix("{\"error\":\"x\"}"))
}

@Test func sessionLifecycleAndExpiry() {
    let store = ProxySessionStore()
    var c = CallerIdentity(transport: "unix"); c.path = "/usr/bin/curl"
    let t0 = Date()
    let s = store.create(caller: c, routes: ["a"], ttl: 60, label: "test", now: t0)
    #expect(s.token.count >= 32)
    #expect(s.allows(route: "a") && !s.allows(route: "b"))
    #expect(store.lookup(token: s.token, now: t0.addingTimeInterval(59)) === s)
    #expect(store.lookup(token: "nope", now: t0) == nil)
    #expect(store.lookup(token: s.token, now: t0.addingTimeInterval(60)) == nil) // expired and purged
    #expect(store.list(now: t0).isEmpty)
    let s2 = store.create(caller: c, routes: nil, ttl: nil, label: nil, now: t0)
    #expect(s2.allows(route: "anything"))
    #expect(store.find(id: s2.id) === s2)
    #expect(store.revoke(id: s2.id) === s2)
    #expect(store.lookup(token: s2.token, now: t0) == nil)
    #expect(store.revoke(id: s2.id) == nil)
}

@Test func budgetSlidingWindow() {
    let store = ProxySessionStore()
    let s = store.create(caller: CallerIdentity(transport: "unix"), routes: nil, ttl: 3600, label: nil)
    let b = ProxyBudget(requests: 3, per: 60)
    let t0 = Date()
    #expect(store.consumeBudget(s, route: "r", budget: b, now: t0) == nil)
    #expect(store.consumeBudget(s, route: "r", budget: b, now: t0.addingTimeInterval(1)) == nil)
    #expect(store.consumeBudget(s, route: "r", budget: b, now: t0.addingTimeInterval(2)) == nil)
    let wait = store.consumeBudget(s, route: "r", budget: b, now: t0.addingTimeInterval(3))
    #expect(wait != nil && wait! > 56 && wait! <= 58)
    #expect(store.consumeBudget(s, route: "other", budget: b, now: t0.addingTimeInterval(3)) == nil) // per route
    #expect(store.consumeBudget(s, route: "r", budget: b, now: t0.addingTimeInterval(61)) == nil) // window slid
    #expect(store.consumeBudget(s, route: "r", budget: nil, now: t0) == nil) // no budget
    #expect(s.requests == 7)
}

@Test func secretCacheIsPerSession() {
    let store = ProxySessionStore()
    let a = store.create(caller: CallerIdentity(transport: "unix"), routes: nil, ttl: 60, label: nil)
    let b = store.create(caller: CallerIdentity(transport: "unix"), routes: nil, ttl: 60, label: nil)
    store.cacheSecret(a, "K", "v")
    #expect(store.cachedSecret(a, "K") == "v")
    #expect(store.cachedSecret(b, "K") == nil)
    store.clearSecretCaches()
    #expect(store.cachedSecret(a, "K") == nil)
}
