import ArgumentParser
import CryptoKit
import Foundation
import SafeskiCore

struct Safeski: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "safeski",
        abstract: "Secure Enclave-backed keys and secrets for your shell, agents, containers, and apps.",
        version: Version.string,
        subcommands: [
            Init.self, Keygen.self, Keys.self, Pubkey.self, Sign.self, Verify.self,
            Secret.self, Run.self, Agent.self, PolicyCmd.self, Audit.self, Status.self, Whoami.self,
            Token.self, Device.self,
        ] + ExtraCommands.all
    )
}

struct GlobalOptions: ParsableArguments {
    @Flag(name: .long, help: "Bypass the agent and operate on the store in-process.")
    var local = false
    @Flag(name: .long, help: "Emit machine-readable JSON.")
    var json = false

    func backend() throws -> Backend { try BackendFactory.make(forceLocal: local) }
}

enum Output {
    static func json<T: Encodable>(_ v: T) {
        if let d = try? JSONEncoder.safeski.encode(v) { print(String(decoding: d, as: UTF8.self)) }
    }
    static func fail(_ msg: String) -> Never {
        FileHandle.standardError.write(Data("safeski: \(msg)\n".utf8))
        Foundation.exit(1)
    }
    static func readAllStdin() -> Data { FileHandle.standardInput.readDataToEndOfFile() }
    static func readInput(_ file: String?) throws -> Data {
        if let f = file, f != "-" { return try Data(contentsOf: URL(fileURLWithPath: f)) }
        return readAllStdin()
    }
}

// MARK: - init

struct Init: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Create this device's enclave identity and the ~/.safeski layout.")
    @Option(help: "Device name (defaults to hostname).") var name: String?
    @Option(help: "Access policy for the vault key that unlocks secrets: none, user-presence, biometry-any, biometry-current-set, device-passcode.")
    var vaultAccess: AccessPolicy = .none
    @OptionGroup var g: GlobalOptions

    func run() throws {
        let store = Store()
        let dev = try store.initialize(name: name, vaultAccess: vaultAccess)
        if g.json { Output.json(dev.publicRecord); return }
        print("initialized \(store.paths.root.path)")
        print("device id:   \(dev.deviceID)")
        print("device name: \(dev.name)")
        print("policy:      \(store.paths.policy.path)")
    }
}

// MARK: - keys

extension AccessPolicy: ExpressibleByArgument {}
extension KeyKind: ExpressibleByArgument {}
extension PublicKeyFormat: ExpressibleByArgument {}

struct Keygen: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Create a key.")
    @Argument(help: "Key name.") var name: String
    @Option(help: "enclave-signing, enclave-agreement, software-ed25519, software-x25519") var kind: KeyKind = .enclaveSigning
    @Option(help: "none, user-presence, biometry-any, biometry-current-set, device-passcode") var access: AccessPolicy = .none
    @Option(help: "Comment (used in SSH public key output).") var comment: String?
    @Option(name: .long, parsing: .upToNextOption, help: "Label as key=value (e.g. ssh=false hides the key from the SSH agent). Repeatable.") var label: [String] = []
    @OptionGroup var g: GlobalOptions

    func run() throws {
        let b = try g.backend()
        var labels: [String: String] = [:]
        for l in label {
            let parts = l.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { Output.fail("label must be key=value: \(l)") }
            labels[parts[0]] = parts[1]
        }
        let k = try b.createKey(CreateKeyParams(name: name, kind: kind, access: access, comment: comment, labels: labels.isEmpty ? nil : labels))
        if g.json { Output.json(k); return }
        print("created \(k.kind.rawValue) key '\(k.name)' (access: \(k.access.rawValue))")
        if k.kind == .enclaveSigning, let pk = try? P256.Signing.PublicKey(x963Representation: k.publicKey) {
            print(pk.sshAuthorizedKey(comment: k.comment ?? "safeski:\(k.name)"))
        }
    }
}

struct Keys: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List keys.")
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let keys = try g.backend().listKeys()
        if g.json { Output.json(keys); return }
        if keys.isEmpty { print("no keys. create one with: safeski keygen <name>"); return }
        for k in keys {
            var fp = ""
            if k.kind == .enclaveSigning, let pk = try? P256.Signing.PublicKey(x963Representation: k.publicKey) { fp = pk.sshFingerprint }
            print("\(k.name.padding(toLength: 24, withPad: " ", startingAt: 0)) \(k.kind.rawValue.padding(toLength: 20, withPad: " ", startingAt: 0)) \(k.access.rawValue.padding(toLength: 22, withPad: " ", startingAt: 0)) \(fp)")
        }
    }
}

struct Pubkey: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Print a key's public key.")
    @Argument var name: String
    @Option(help: "ssh, pem, jwk, raw, hex, der") var format: PublicKeyFormat = .ssh
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let k = try g.backend().getKey(name)
        switch k.kind {
        case .enclaveSigning:
            let pk = try P256.Signing.PublicKey(x963Representation: k.publicKey)
            print(try pk.encoded(format, comment: k.comment ?? "safeski:\(k.name)"))
        case .enclaveAgreement:
            let pk = try P256.KeyAgreement.PublicKey(x963Representation: k.publicKey)
            switch format {
            case .pem: print(pk.pemRepresentation)
            case .hex: print(pk.rawRepresentation.hexString)
            default: print(pk.x963Representation.base64EncodedString())
            }
        case .softwareEd25519:
            switch format {
            case .ssh:
                var w = SSHWire(); w.writeString("ssh-ed25519"); w.writeString(k.publicKey)
                print("ssh-ed25519 \(w.data.base64EncodedString()) \(k.comment ?? "safeski:\(k.name)")")
            case .hex: print(k.publicKey.hexString)
            case .jwk: print("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"\(Base64URL.encode(k.publicKey))\"}")
            default: print(k.publicKey.base64EncodedString())
            }
        case .softwareX25519:
            print(format == .hex ? k.publicKey.hexString : k.publicKey.base64EncodedString())
        }
    }
}

struct Sign: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Sign a file or stdin with a key.")
    @Argument var name: String
    @Argument(help: "File to sign, or - for stdin.") var file: String = "-"
    @Flag(help: "Input is already a 32-byte SHA-256 digest.") var digest = false
    @Option(help: "Output format: raw (r||s base64), der (base64), ssh (base64 blob), hex") var format: String = "raw"
    @Option(help: "Shown in approval prompts and the audit log.") var purpose: String?
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let input = try Output.readInput(file)
        let sig = try g.backend().sign(SignParams(key: name, data: input, digest: digest, purpose: purpose))
        switch format {
        case "raw": print(sig.base64EncodedString())
        case "der": print(try ECDSAFormat.rawToDER(sig).base64EncodedString())
        case "ssh": print(try ECDSAFormat.rawToSSH(sig).base64EncodedString())
        case "hex": print(sig.hexString)
        default: Output.fail("unknown format \(format)")
        }
    }
}

struct Verify: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Verify a raw (r||s) signature made by a key.")
    @Argument var name: String
    @Argument var file: String = "-"
    @Option(help: "Base64 raw signature.") var signature: String
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let k = try g.backend().getKey(name)
        let input = try Output.readInput(file)
        guard let sig = Data(base64Encoded: signature) else { Output.fail("bad base64 signature") }
        let ok: Bool
        switch k.kind {
        case .enclaveSigning:
            let pk = try P256.Signing.PublicKey(x963Representation: k.publicKey)
            ok = (try? P256.Signing.ECDSASignature(rawRepresentation: sig)).map { pk.isValidSignature($0, for: input) } ?? false
        case .softwareEd25519:
            let pk = try Curve25519.Signing.PublicKey(rawRepresentation: k.publicKey)
            ok = pk.isValidSignature(sig, for: input)
        default: Output.fail("key cannot verify")
        }
        print(ok ? "valid" : "INVALID")
        if !ok { throw ExitCode(1) }
    }
}

// MARK: - secrets

struct Secret: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Manage secrets (API keys, tokens).",
                                                    subcommands: [Set.self, Get.self, Ls.self, Rm.self, Export.self, Import.self])

    struct Set: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Store a secret. Reads the value from stdin unless given.")
        @Argument var name: String
        @Argument(help: "Value; omit to read from stdin (recommended).") var value: String?
        @Option(help: "text, binary, env, json") var contentType: String = "text"
        @OptionGroup var g: GlobalOptions
        func run() throws {
            var data: Data
            if let v = value { data = Data(v.utf8) }
            else {
                data = Output.readAllStdin()
                if contentType == "text", data.last == 0x0a { data.removeLast() }
            }
            let s = try g.backend().setSecret(SetSecretParams(name: name, value: data, contentType: contentType))
            if g.json { Output.json(s) } else { print("stored secret '\(s.name)' (\(data.count) bytes, \(s.recipients.count) recipient(s))") }
        }
    }

    struct Get: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print a secret.")
        @Argument var name: String
        @Option var purpose: String?
        @Flag(help: "Do not append a trailing newline.") var noNewline = false
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let v = try g.backend().getSecret(name, purpose: purpose)
            FileHandle.standardOutput.write(v.value)
            if !noNewline, v.contentType != "binary" { FileHandle.standardOutput.write(Data("\n".utf8)) }
        }
    }

    struct Ls: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "List secrets.")
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let s = try g.backend().listSecrets()
            if g.json { Output.json(s); return }
            if s.isEmpty { print("no secrets. add one with: safeski secret set NAME"); return }
            let f = ISO8601DateFormatter()
            for x in s { print("\(x.name.padding(toLength: 32, withPad: " ", startingAt: 0)) \(x.contentType.padding(toLength: 8, withPad: " ", startingAt: 0)) \(f.string(from: x.updated))  recipients=\(x.recipients.count)") }
        }
    }

    struct Rm: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Delete a secret.")
        @Argument var name: String
        @OptionGroup var g: GlobalOptions
        func run() throws { try g.backend().deleteSecret(name); print("deleted '\(name)'") }
    }

    struct Export: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print `export NAME=value` lines for use with eval (prefer `safeski run`).")
        @Argument(help: "Secret names; default all.") var names: [String] = []
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let b = try g.backend()
            let list = names.isEmpty ? try b.listSecrets().map(\.name) : names
            for n in list {
                let v = try b.getSecret(n, purpose: "export")
                let s = String(decoding: v.value, as: UTF8.self).replacingOccurrences(of: "'", with: "'\\''")
                print("export \(n)='\(s)'")
            }
        }
    }

    struct Import: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Import KEY=value lines from a .env file (or stdin).")
        @Argument var file: String = "-"
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let b = try g.backend()
            let text = String(decoding: try Output.readInput(file), as: UTF8.self)
            var n = 0
            for raw in text.split(separator: "\n") {
                var line = raw.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                if line.hasPrefix("export ") { line = String(line.dropFirst(7)) }
                guard let eq = line.firstIndex(of: "=") else { continue }
                let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)
                var val = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
                if (val.hasPrefix("\"") && val.hasSuffix("\"")) || (val.hasPrefix("'") && val.hasSuffix("'")), val.count >= 2 {
                    val = String(val.dropFirst().dropLast())
                }
                _ = try b.setSecret(SetSecretParams(name: key, value: Data(val.utf8), contentType: "text"))
                n += 1
            }
            print("imported \(n) secret(s)")
        }
    }
}

// MARK: - run

struct Run: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Run a command with secrets injected as environment variables.")
    @Option(name: [.short, .long], parsing: .upToNextOption, help: "Secret to inject (NAME or NAME=ENVVAR). Repeatable.") var secret: [String] = []
    @Flag(help: "Inject every secret.") var all = false
    @Option(help: "Shown in approval prompts.") var purpose: String?
    @Argument(parsing: .captureForPassthrough, help: "Command and arguments.") var command: [String]
    @OptionGroup var g: GlobalOptions

    func run() throws {
        guard !command.isEmpty else { Output.fail("usage: safeski run [-s NAME ...] -- cmd args") }
        let b = try g.backend()
        var env = ProcessInfo.processInfo.environment
        let specs: [String] = all ? try b.listSecrets().map(\.name) : secret
        for spec in specs {
            let parts = spec.split(separator: "=", maxSplits: 1).map(String.init)
            let name = parts[0]; let envName = parts.count > 1 ? parts[1] : parts[0]
            let v = try b.getSecret(name, purpose: purpose ?? "run \(command[0])")
            env[envName] = String(decoding: v.value, as: UTF8.self)
        }
        // Advertise the agent to children.
        let paths = SafeskiPaths.default
        if UnixSocketClient.isListening(path: paths.agentSocket.path) { env["SAFESKI_SOCKET"] = paths.agentSocket.path }
        if UnixSocketClient.isListening(path: paths.sshAgentSocket.path), env["SSH_AUTH_SOCK"] == nil { env["SSH_AUTH_SOCK"] = paths.sshAgentSocket.path }
        var cmd = command
        if cmd.first == "--" { cmd.removeFirst() }
        execvpWithEnv(cmd, env: env)
    }
}

func execvpWithEnv(_ argv: [String], env: [String: String]) -> Never {
    let cargs = argv.map { strdup($0) } + [nil]
    let cenv = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
    execve(resolveExecutable(argv[0]), cargs, cenv)
    Output.fail("exec \(argv[0]): \(String(cString: strerror(errno)))")
}

func resolveExecutable(_ name: String) -> String {
    if name.contains("/") { return name }
    for dir in (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin").split(separator: ":") {
        let p = "\(dir)/\(name)"
        if FileManager.default.isExecutableFile(atPath: p) { return p }
    }
    return name
}

// MARK: - agent

struct Agent: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Run or manage the background agent.",
                                                    subcommands: [Start.self, Install.self, Uninstall.self, AgentStatus.self, Env.self])

    struct Start: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run the agent in the foreground (launchd runs this).")
        @Flag(help: "Disable SSH agent frontend.") var noSsh = false
        @Flag(help: "Disable the secretless HTTP proxy.") var noProxy = false
        @Flag(help: "Headless: never prompt; approvals fail closed.") var headless = false
        func run() throws {
            let agent = try AgentServer(interactive: !headless)
            try agent.start()
            try AgentExtensions.start(agent: agent, ssh: !noSsh, proxy: !noProxy)
            signal(SIGPIPE, SIG_IGN)
            let stop = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
            signal(SIGTERM, SIG_IGN)
            stop.setEventHandler { agent.stop(); AgentExtensions.stop(); Foundation.exit(0) }
            stop.resume()
            let int = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            signal(SIGINT, SIG_IGN)
            int.setEventHandler { agent.stop(); AgentExtensions.stop(); Foundation.exit(0) }
            int.resume()
            // Sign the audit head every 10 minutes.
            let timer = DispatchSource.makeTimerSource(queue: .global())
            timer.schedule(deadline: .now() + 600, repeating: 600)
            timer.setEventHandler {
                let store = agent.service.store
                if let dev = try? store.loadDevice(), let key = try? store.identityKey() {
                    _ = try? agent.service.audit.signHead(with: key, deviceID: dev.deviceID, to: store.paths.auditDir.appendingPathComponent("head.sig.json"))
                }
            }
            timer.resume()
            RunLoop.main.run()
        }
    }

    struct Install: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Install and start the per-user LaunchAgent.")
        func run() throws {
            let exe = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
            let resolved = CallerIdentity.resolvePath(pid: getpid()) ?? exe
            let plist = Launchd.agentPlist(executable: resolved)
            let url = Launchd.agentPlistURL
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try plist.write(to: url, atomically: true, encoding: .utf8)
            _ = Launchd.run(["bootout", "gui/\(getuid())/\(Launchd.agentLabel)"])
            let r = Launchd.run(["bootstrap", "gui/\(getuid())", url.path])
            guard r.status == 0 else { Output.fail("launchctl bootstrap failed: \(r.output)") }
            print("installed \(url.path)")
            print("agent socket: \(SafeskiPaths.default.agentSocket.path)")
            print("add to your shell: eval \"$(safeski agent env)\"")
        }
    }

    struct Uninstall: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Stop and remove the LaunchAgent.")
        func run() throws {
            _ = Launchd.run(["bootout", "gui/\(getuid())/\(Launchd.agentLabel)"])
            try? FileManager.default.removeItem(at: Launchd.agentPlistURL)
            print("uninstalled")
        }
    }

    struct AgentStatus: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "status", abstract: "Show whether the agent is running.")
        func run() throws {
            let p = SafeskiPaths.default
            if UnixSocketClient.isListening(path: p.agentSocket.path) {
                let s = try RemoteBackend(socketPath: p.agentSocket.path).status()
                print("running pid \(s.pid), up \(Int(s.uptimeSeconds))s, socket \(s.socket)")
                if let ssh = s.sshSocket { print("ssh agent: \(ssh)") }
                if let extra = s.extra { for (k, v) in extra.sorted(by: { $0.key < $1.key }) { print("\(k): \(v)") } }
            } else {
                print("not running (socket \(p.agentSocket.path))")
                throw ExitCode(1)
            }
        }
    }

    struct Env: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print shell exports for SAFESKI_SOCKET and SSH_AUTH_SOCK.")
        func run() throws {
            let p = SafeskiPaths.default
            print("export SAFESKI_SOCKET=\"\(p.agentSocket.path)\"")
            print("export SSH_AUTH_SOCK=\"\(p.sshAgentSocket.path)\"")
        }
    }
}

enum Launchd {
    static let agentLabel = "dev.safeski.agent"
    static var agentPlistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents/\(agentLabel).plist")
    }
    static func agentPlist(executable: String) -> String {
        let logs = SafeskiPaths.default.logs.path
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(agentLabel)</string>
          <key>ProgramArguments</key><array><string>\(executable)</string><string>agent</string><string>start</string></array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
          <key>ProcessType</key><string>Interactive</string>
          <key>StandardOutPath</key><string>\(logs)/agent.log</string>
          <key>StandardErrorPath</key><string>\(logs)/agent.log</string>
          <key>EnvironmentVariables</key><dict><key>SAFESKI_HOME</key><string>\(SafeskiPaths.default.root.path)</string></dict>
        </dict></plist>
        """
    }
    static func run(_ args: [String]) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { return (1, error.localizedDescription) }
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
    }
}

// MARK: - policy / audit / status

struct PolicyCmd: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "policy", abstract: "Inspect or reload policy.",
                                                    subcommands: [Show.self, Check.self, Reload.self, Path.self])
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the parsed policy as JSON.")
        func run() throws {
            let doc = try Policy.load(from: SafeskiPaths.default.policy)
            print(doc.raw.description)
        }
    }
    struct Check: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Parse policy.toml and report errors.")
        func run() throws {
            let doc = try Policy.load(from: SafeskiPaths.default.policy)
            print("ok: \(doc.keys.count) key rule set(s), \(doc.secrets.count) secret rule set(s), \(doc.tokens.count) token(s)")
        }
    }
    struct Reload: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Ask the agent to reload policy.")
        @OptionGroup var g: GlobalOptions
        func run() throws { try g.backend().reloadPolicy(); print("reloaded") }
    }
    struct Path: ParsableCommand {
        func run() { print(SafeskiPaths.default.policy.path) }
    }
}

struct Audit: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Read or verify the audit log.", subcommands: [Tail.self, VerifyChain.self])
    struct Tail: ParsableCommand {
        @Option(name: .shortAndLong) var n: Int = 20
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let events = try g.backend().auditTail(n)
            if g.json { Output.json(events); return }
            let f = ISO8601DateFormatter()
            for e in events {
                let who = e.caller?.displayName ?? "-"
                print("\(e.seq)\t\(f.string(from: e.time))\t\(e.outcome.padding(toLength: 8, withPad: " ", startingAt: 0))\t\(e.action.padding(toLength: 14, withPad: " ", startingAt: 0))\t\(e.resource ?? "-")\t\(who)")
            }
        }
    }
    struct VerifyChain: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "verify", abstract: "Verify the hash chain and head signature.")
        func run() throws {
            let paths = SafeskiPaths.default
            let (count, broken) = try AuditLog.verify(url: paths.auditLog)
            if let b = broken { print("BROKEN at seq \(b) of \(count)"); throw ExitCode(1) }
            print("chain ok: \(count) entries")
            let sigURL = paths.auditDir.appendingPathComponent("head.sig.json")
            if FileIO.exists(sigURL) {
                let sig = try JSONDecoder.safeski.decode(AuditHeadSignature.self, from: FileIO.read(sigURL))
                let dev = try Store(paths: paths).loadDevice()
                let pk = try P256.Signing.PublicKey(x963Representation: dev.identityPublicKey)
                let ok = (try? P256.Signing.ECDSASignature(rawRepresentation: sig.signature)).map {
                    pk.isValidSignature($0, for: AuditLog.headMessage(seq: sig.seq, hash: sig.hash))
                } ?? false
                print("head signature at seq \(sig.seq): \(ok ? "valid" : "INVALID")")
            }
        }
    }
}

struct Status: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show device and agent status.")
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let b = try g.backend()
        let s = try b.status()
        if g.json { Output.json(s); return }
        print("safeski \(s.version)")
        print("device:   \(s.deviceName) (\(s.deviceID))")
        print("mode:     \(b.isRemote ? "agent pid \(s.pid), up \(Int(s.uptimeSeconds))s" : "local (no agent)")")
        print("socket:   \(s.socket)")
        if let ssh = s.sshSocket { print("ssh:      \(ssh)") }
        print("keys:     \(s.keys)   secrets: \(s.secrets)   audit entries: \(s.auditHead)")
        if let extra = s.extra { for (k, v) in extra.sorted(by: { $0.key < $1.key }) { print("\(k): \(v)") } }
    }
}

struct Whoami: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Show how the agent identifies this caller (useful for writing policy rules).")
    @OptionGroup var g: GlobalOptions
    func run() throws {
        let c = try g.backend().whoami()
        if g.json { Output.json(c); return }
        print("transport:   \(c.transport)")
        print("path:        \(c.path ?? "-")")
        print("parent:      \(c.parentPath ?? "-")")
        print("signing_id:  \(c.signingID ?? "-")")
        print("team_id:     \(c.teamID ?? "-")")
        print("uid/pid:     \(c.uid.map(String.init) ?? "-")/\(c.pid.map(String.init) ?? "-")")
        print("valid sig:   \(c.signatureValid.map(String.init) ?? "-")")
        if let t = c.tokenName { print("token:       \(t)") }
    }
}

// MARK: - tokens (containers / remote callers)

struct Token: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Session tokens for callers without peer credentials (containers, remote).",
                                                    subcommands: [Create.self, Ls.self, Rm.self])
    struct Create: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create a token and append it to policy.toml. The token is printed once.")
        @Argument var name: String
        @Option(help: "Lifetime, e.g. 24h, 7d. Default: no expiry.") var expires: String?
        @Flag(help: "Print `export SAFESKI_TOKEN=...` for eval (containers: safeski docker env/run read it).") var export = false
        func run() throws {
            try Names.validate(name)
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            let token = "ssk_" + Base64URL.encode(Data(bytes))
            let hash = Data(SHA256.hash(data: Data(token.utf8))).hexString
            var block = "\n[tokens.\(name)]\nhash = \"\(hash)\"\n"
            if let e = expires {
                guard let secs = parseDuration(e) else { Output.fail("bad duration \(e)") }
                block += "expires = \"\(ISO8601DateFormatter().string(from: Date().addingTimeInterval(secs)))\"\n"
            }
            let url = SafeskiPaths.default.policy
            var text = FileIO.exists(url) ? String(decoding: try FileIO.read(url), as: UTF8.self) : PolicyDocument.defaultTOML
            if text.contains("[tokens.\(name)]") { Output.fail("token '\(name)' already exists in policy") }
            text += block
            try FileIO.writePrivate(Data(text.utf8), to: url)
            print(export ? "export SAFESKI_TOKEN=\(token)" : token)
            FileHandle.standardError.write(Data("token '\(name)' added to \(url.path). Grant it access with rules like { token = \"\(name)\" }.\n".utf8))
        }
    }
    struct Ls: ParsableCommand {
        func run() throws {
            let doc = try Policy.load(from: SafeskiPaths.default.policy)
            for (n, t) in doc.tokens.sorted(by: { $0.key < $1.key }) {
                print("\(n.padding(toLength: 24, withPad: " ", startingAt: 0)) expires=\(t.expires.map { ISO8601DateFormatter().string(from: $0) } ?? "never")")
            }
        }
    }
    struct Rm: ParsableCommand {
        @Argument var name: String
        func run() throws {
            let url = SafeskiPaths.default.policy
            var text = String(decoding: try FileIO.read(url), as: UTF8.self)
            guard let r = text.range(of: "\n[tokens.\(name)]\n") else { Output.fail("token '\(name)' not found") }
            // remove until next table header or EOF
            let after = text[r.upperBound...]
            let end = after.range(of: "\n[")?.lowerBound ?? text.endIndex
            text.removeSubrange(r.lowerBound..<end)
            try FileIO.writePrivate(Data(text.utf8), to: url)
            print("removed token '\(name)'")
        }
    }
}

func parseDuration(_ s: String) -> TimeInterval? {
    guard let unit = s.last, let n = Double(s.dropLast()) else { return nil }
    switch unit {
    case "s": return n
    case "m": return n * 60
    case "h": return n * 3600
    case "d": return n * 86400
    default: return nil
    }
}

// MARK: - devices

struct Device: ParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Multi-device: export this device, enroll others, re-share secrets.",
                                                    subcommands: [Show.self, Enroll.self, Ls.self, Rm.self, Reshare.self])
    struct Show: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print this device's public record (give this to another device to enroll).")
        func run() throws { Output.json(try Store().loadDevice().publicRecord) }
    }
    struct Enroll: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Enroll another device from its public record (file or stdin), then re-share secrets to it.")
        @Argument var file: String = "-"
        func run() throws {
            let store = Store()
            var rec = try JSONDecoder.safeski.decode(DevicePublicRecord.self, from: try Output.readInput(file))
            let me = try store.loadDevice()
            guard rec.deviceID != me.deviceID else { Output.fail("that is this device") }
            rec.enrollmentSignature = try store.identityKey().sign(rec.canonicalBytes)
            rec.enrolledBy = me.deviceID
            try store.saveDevice(rec)
            let n = try store.reshareAll()
            print("enrolled \(rec.name) (\(rec.deviceID)); re-shared \(n) item(s)")
        }
    }
    struct Ls: ParsableCommand {
        func run() throws {
            let store = Store()
            let me = try store.loadDevice()
            print("\(me.deviceID)  \(me.name)  (this device)")
            for d in try store.listDevices() { print("\(d.deviceID)  \(d.name)  enrolled by \(d.enrolledBy ?? "-")") }
        }
    }
    struct Rm: ParsableCommand {
        @Argument var id: String
        func run() throws { try Store().removeDevice(id); print("removed \(id). Note: existing envelopes still include it until secrets are rotated.") }
    }
    struct Reshare: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Re-wrap all secrets and software keys to every enrolled device.")
        func run() throws { print("re-shared \(try Store().reshareAll()) item(s)") }
    }
}
