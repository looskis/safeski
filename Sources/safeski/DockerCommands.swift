import ArgumentParser
import Foundation
import SafeskiCore

/// `safeski docker`: hand the agent socket to a container. Docker Desktop, OrbStack, colima and
/// Apple's `container` all run Linux VMs; unix sockets bind-mounted from the Mac are forwarded,
/// but peer credentials do not survive the VM boundary, so the container authenticates with a
/// safeski token (`safeski token create NAME --export`).
struct DockerCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "docker",
        abstract: "Expose the agent to containers (Docker Desktop, OrbStack, colima, Apple container).",
        subcommands: [Env.self, RunCmd.self, ComposeSnippet.self, SSHEnv.self])

    static let containerSocket = "/run/safeski/agent.sock"

    /// Options shared by `env` and `run`.
    struct TokenOptions: ParsableArguments {
        @Option(help: "Token name from policy.toml (used to sanity-check that the token exists and has rules).") var token: String?
        @Option(help: "The token value. Default: $SAFESKI_TOKEN. safeski stores only the hash, so the value must come from you.") var tokenValue: String?
        @Option(help: "Agent socket on the host. Default: $SAFESKI_SOCKET or the agent's runtime socket.") var socket: String?
        @Option(help: "Where the socket appears inside the container.") var containerSocket: String = DockerCmd.containerSocket

        func hostSocket() -> String {
            if let s = socket, !s.isEmpty { return s }
            if let s = ProcessInfo.processInfo.environment["SAFESKI_SOCKET"], !s.isEmpty { return s }
            return SafeskiPaths.default.agentSocket.path
        }

        func resolvedTokenValue() -> String {
            if let v = tokenValue, !v.isEmpty { return v }
            if let v = ProcessInfo.processInfo.environment["SAFESKI_TOKEN"], !v.isEmpty { return v }
            Output.fail("no token value: pass --token-value, or run  eval \"$(safeski token create \(token ?? "docker-dev") --export)\"  first")
        }

        /// Warn when the named token is unknown or has no policy rules (the container would be denied everything).
        func checkPolicy() {
            guard let name = token else { return }
            guard let doc = try? Policy.load(from: SafeskiPaths.default.policy) else { return }
            if doc.tokens[name] == nil {
                warn("token '\(name)' is not in \(SafeskiPaths.default.policy.path); create it with: safeski token create \(name) --export")
                return
            }
            let used = doc.secrets.values.contains { $0.rules.contains { $0.token == name } } || doc.keys.values.contains { $0.rules.contains { $0.token == name } }
            if !used { warn("token '\(name)' has no rules yet; grant access with e.g. [secrets.NAME] rules = [{ token = \"\(name)\", approve = \"never\" }]") }
        }

        func flags() -> [String] {
            ["-v", "\(hostSocket()):\(containerSocket)", "-e", "SAFESKI_SOCKET=\(containerSocket)", "-e", "SAFESKI_TOKEN=\(resolvedTokenValue())"]
        }

        private func warn(_ s: String) { FileHandle.standardError.write(Data("safeski: warning: \(s)\n".utf8)) }
    }

    struct Env: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the `docker run` flags that mount the agent socket and pass the token.")
        @OptionGroup var t: TokenOptions
        func run() throws {
            t.checkPolicy()
            if !UnixSocketClient.isListening(path: t.hostSocket()) {
                FileHandle.standardError.write(Data("safeski: warning: no agent listening at \(t.hostSocket())\n".utf8))
            }
            print(t.flags().map(shellQuote).joined(separator: " "))
        }
    }

    struct RunCmd: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "run", abstract: "Run `docker run` with the safeski flags injected. Usage: safeski docker run --token NAME -- docker run [args]")
        @OptionGroup var t: TokenOptions
        @Argument(parsing: .captureForPassthrough, help: "`docker run ...` (or just the image and args).") var command: [String]
        func run() throws {
            t.checkPolicy()
            var args = command
            if args.first == "--" { args.removeFirst() }
            guard !args.isEmpty else { Output.fail("usage: safeski docker run --token NAME -- docker run [docker args] IMAGE [cmd]") }
            let flags = t.flags()
            var argv: [String]
            if args.count >= 2, (args[0] as NSString).lastPathComponent == "docker", args[1] == "run" {
                argv = [args[0], "run"] + flags + Array(args.dropFirst(2))
            } else if args.count >= 2, args[1] == "run" {
                // some other CLI with a run verb (e.g. `container run`, `podman run`)
                argv = [args[0], "run"] + flags + Array(args.dropFirst(2))
            } else {
                argv = ["docker", "run"] + flags + args
            }
            var env = ProcessInfo.processInfo.environment
            env["SAFESKI_TOKEN"] = t.resolvedTokenValue()
            execvpWithEnv(argv, env: env)
        }
    }

    struct ComposeSnippet: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "compose-snippet", abstract: "Print a docker-compose service snippet (volumes + environment).")
        @OptionGroup var t: TokenOptions
        func run() throws {
            let host = t.hostSocket()
            print("""
            # Add to the service in docker-compose.yml. SAFESKI_TOKEN is read from your shell
            # environment at `docker compose up` time: eval "$(safeski token create \(t.token ?? "compose") --export)"
            services:
              app:
                volumes:
                  - \(host):\(t.containerSocket)
                environment:
                  SAFESKI_SOCKET: \(t.containerSocket)
                  SAFESKI_TOKEN: ${SAFESKI_TOKEN:?run eval "$(safeski token create NAME --export)"}
            """)
        }
    }

    struct SSHEnv: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "ssh-env", abstract: "Print the Docker Desktop SSH-agent forwarding flags (host SSH_AUTH_SOCK must be safeski's ssh socket).")
        func run() throws {
            let p = SafeskiPaths.default
            let host = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] ?? ""
            if host != p.sshAgentSocket.path {
                FileHandle.standardError.write(Data("""
                safeski: warning: SSH_AUTH_SOCK is \(host.isEmpty ? "unset" : host), not safeski's \(p.sshAgentSocket.path).
                        Docker Desktop forwards whatever SSH_AUTH_SOCK points to on the host; run: eval "$(safeski agent env)"

                """.utf8))
            }
            print("# Docker Desktop (and OrbStack) forward the host's SSH_AUTH_SOCK to this magic path:")
            print("-v /run/host-services/ssh-auth.sock:/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent")
            print("# Other runtimes (colima, Apple container): mount the socket directly:")
            print("# -v \(p.sshAgentSocket.path):/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent")
        }
    }
}

func shellQuote(_ s: String) -> String {
    if s.range(of: "^[A-Za-z0-9_./:=@%+-]+$", options: .regularExpression) != nil { return s }
    return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}
