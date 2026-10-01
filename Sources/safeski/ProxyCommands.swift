import ArgumentParser
import Foundation
import SafeskiCore

// Owned by the Proxy module.
struct ProxyCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "proxy",
        abstract: "Secretless HTTP proxy: point agents at a local URL; safeski injects the credential under policy.",
        discussion: """
        Configure routes in policy.toml:

          [proxy.routes.anthropic]
          upstream = "https://api.anthropic.com"
          env = "ANTHROPIC_BASE_URL"
          headers = { "x-api-key" = "secret:ANTHROPIC_API_KEY" }
          strip = ["authorization"]
          rules = [ { methods = ["POST"], path = "/v1/messages", approve = "never" } ]
          budget = { requests = 1000, per = "1h" }

        Then: safeski proxy run --route anthropic -- claude
        """,
        subcommands: [ProxyStatus.self, ProxyRoutes.self, ProxySessionCmd.self, ProxyRun.self])

    /// The proxy lives in the agent; the in-process backend has no listener.
    static func remote(_ g: GlobalOptions) throws -> Backend {
        let b = try g.backend()
        guard b.isRemote else { Output.fail("the proxy runs inside the agent, which is not running (start it with `safeski agent start` or `safeski agent install`)") }
        return b
    }

    struct ProxyStatus: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "status", abstract: "Show the proxy listener, route count and active sessions.")
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let s = try ProxyCmd.remote(g).call(ProxyModule.Method.status, params: .object([:]))
            if g.json { print(s.description); return }
            let running = s["running"]?.boolValue ?? false
            print("proxy:    \(running ? "listening on http://\(s["listen"]?.stringValue ?? "?")" : (s["enabled"]?.boolValue == false ? "disabled by policy" : "not running"))")
            print("routes:   \(s["routes"]?.intValue ?? 0)")
            print("sessions: \(s["sessions"]?.intValue ?? 0)")
            print("unsessioned /r/ routes: \(s["allowUnsessioned"]?.boolValue == true ? "allowed" : "disabled")")
            if let e = s["configError"]?.stringValue { print("config error: \(e)") }
        }
    }

    struct ProxyRoutes: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "routes", abstract: "List configured routes.")
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let routes: JSONValue
            let b = try g.backend()
            if b.isRemote {
                routes = try b.call(ProxyModule.Method.routes, params: .object([:]))
            } else {
                // No agent: show what policy.toml says.
                let cfg = try ProxyConfig.parse(try Policy.load(from: SafeskiPaths.default.policy).raw["proxy"])
                routes = .array(cfg.routes.keys.sorted().map { ProxyModule.describe(cfg.routes[$0]!) })
            }
            if g.json { print(routes.description); return }
            guard let list = routes.arrayValue, !list.isEmpty else { print("no routes. add [proxy.routes.<name>] to \(SafeskiPaths.default.policy.path)"); return }
            for r in list {
                print("\(r["name"]?.stringValue ?? "?")  ->  \(r["upstream"]?.stringValue ?? "?")" + (r["env"]?.stringValue.map { "   env: \($0)" } ?? ""))
                if let h = r["headers"]?.objectValue, !h.isEmpty {
                    print("    inject: " + h.keys.sorted().map { "\($0)=\(h[$0]?.stringValue ?? "")" }.joined(separator: ", "))
                }
                if let s = r["strip"]?.stringArray, !s.isEmpty { print("    strip:  \(s.joined(separator: ", "))") }
                for rule in r["rules"]?.arrayValue ?? [] {
                    let m = rule["methods"]?.stringArray ?? []
                    let ttl = rule["ttl"]?.doubleValue.map { " ttl=\(Int($0))s" } ?? ""
                    print("    rule:   \(m.isEmpty ? "*" : m.joined(separator: ","))  \(rule["path"]?.stringValue ?? "/**")  -> \(rule["approve"]?.stringValue ?? "?")\(ttl)")
                }
                if let b = r["budget"] { print("    budget: \(b["requests"]?.intValue ?? 0) requests per \(Int(b["per"]?.doubleValue ?? 0))s") }
            }
        }
    }

    struct ProxySessionCmd: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "session", abstract: "Create, list or revoke proxy sessions.",
                                                        subcommands: [Create.self, Ls.self, Revoke.self])

        struct Create: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Create a session and print its base URL(s).")
            @Option(name: .long, parsing: .upToNextOption, help: "Route(s) the session may use. Default: all.") var route: [String] = []
            @Option(help: "Lifetime, e.g. 30m, 8h, 7d. Default: 8h.") var ttl: String = "8h"
            @Option(help: "Label shown in approval prompts and the audit log.") var label: String?
            @Flag(help: "Print `export VAR=url` lines for each route's env var (for eval).") var env = false
            @OptionGroup var g: GlobalOptions
            func run() throws {
                let r = try ProxyCmd.createSession(g, routes: route, ttl: ttl, label: label)
                if g.json { print(r.description); return }
                if env {
                    for (k, v) in (r["env"]?.objectValue ?? [:]).sorted(by: { $0.key < $1.key }) { print("export \(k)=\"\(v.stringValue ?? "")\"") }
                    print("export SAFESKI_PROXY_SESSION=\"\(r["id"]?.stringValue ?? "")\"")
                    return
                }
                print("session \(r["id"]?.stringValue ?? "?") expires \(r["expires"]?.stringValue ?? "?")")
                for (k, v) in (r["urls"]?.objectValue ?? [:]).sorted(by: { $0.key < $1.key }) { print("  \(k.padding(toLength: 16, withPad: " ", startingAt: 0)) \(v.stringValue ?? "")") }
            }
        }

        struct Ls: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "List active sessions (tokens are never shown).")
            @OptionGroup var g: GlobalOptions
            func run() throws {
                let r = try ProxyCmd.remote(g).call(ProxyModule.Method.sessionList, params: .object([:]))
                if g.json { print(r.description); return }
                let list = r.arrayValue ?? []
                if list.isEmpty { print("no active sessions"); return }
                for s in list {
                    let routes = s["routes"]?.stringArray?.joined(separator: ",") ?? "*"
                    print("\(s["id"]?.stringValue ?? "?")  \((s["label"]?.stringValue ?? "-").padding(toLength: 16, withPad: " ", startingAt: 0)) routes=\(routes)  requests=\(s["requests"]?.intValue ?? 0)  expires=\(s["expires"]?.stringValue ?? "?")  caller=\(s["caller"]?.stringValue ?? "?")")
                }
            }
        }

        struct Revoke: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "Revoke a session by id.")
            @Argument var id: String
            @OptionGroup var g: GlobalOptions
            func run() throws {
                _ = try ProxyCmd.remote(g).call(ProxyModule.Method.sessionRevoke, params: .object(["id": .string(id)]))
                print("revoked \(id)")
            }
        }
    }

    struct ProxyRun: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "run",
                                                        abstract: "Create a session and exec a command with each route's env var pointed at it.")
        @Option(name: .long, parsing: .upToNextOption, help: "Route(s) to expose. Default: all.") var route: [String] = []
        @Option(help: "Session lifetime, e.g. 8h.") var ttl: String = "8h"
        @Option(help: "Session label (default: the command name).") var label: String?
        @Argument(parsing: .captureForPassthrough, help: "Command and arguments.") var command: [String]
        @OptionGroup var g: GlobalOptions
        func run() throws {
            var cmd = command
            if cmd.first == "--" { cmd.removeFirst() }
            guard !cmd.isEmpty else { Output.fail("usage: safeski proxy run [--route r ...] -- cmd args") }
            let r = try ProxyCmd.createSession(g, routes: route, ttl: ttl, label: label ?? (cmd[0] as NSString).lastPathComponent)
            var env = ProcessInfo.processInfo.environment
            for (k, v) in r["env"]?.objectValue ?? [:] { if let s = v.stringValue { env[k] = s } }
            env["SAFESKI_PROXY_SESSION"] = r["id"]?.stringValue
            env["SAFESKI_PROXY_URL"] = r["baseURL"]?.stringValue
            let paths = SafeskiPaths.default
            if UnixSocketClient.isListening(path: paths.agentSocket.path), env["SAFESKI_SOCKET"] == nil { env["SAFESKI_SOCKET"] = paths.agentSocket.path }
            execvpWithEnv(cmd, env: env)
        }
    }

    static func createSession(_ g: GlobalOptions, routes: [String], ttl: String, label: String?) throws -> JSONValue {
        guard let secs = parseDuration(ttl), secs > 0 else { Output.fail("bad ttl '\(ttl)' (use e.g. 30m, 8h, 7d)") }
        var p: [String: JSONValue] = ["ttl": .number(secs)]
        if !routes.isEmpty { p["routes"] = .array(routes.map { .string($0) }) }
        if let l = label { p["label"] = .string(l) }
        return try remote(g).call(ProxyModule.Method.sessionCreate, params: .object(p))
    }
}
