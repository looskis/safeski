import ArgumentParser
import Foundation
import SafeskiCore

/// `safeski broker`: the root LaunchDaemon that forwards other users' (and system services')
/// requests to the right user's agent with the real caller's identity attached.
struct BrokerCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "broker",
        abstract: "Cross-user access: a root daemon that routes callers to the right user's agent.",
        subcommands: [Start.self, Install.self, Uninstall.self, BrokerStatus.self])

    static let label = "dev.safeski.broker"
    static let plistPath = "/Library/LaunchDaemons/\(label).plist"
    static let libexec = "/usr/local/libexec/safeski"

    struct Start: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run the broker in the foreground (launchd runs this as root).")
        @Option(help: "Broker socket path (default \(BrokerConfig.defaultSocket), or $SAFESKI_BROKER_SOCKET).") var socket: String?
        @Option(help: "Registry directory (default \(BrokerConfig.defaultRegistry), or $SAFESKI_BROKER_REGISTRY).") var registry: String?
        @Flag(help: "Testing only: run as the current user instead of root. Agents then only accept forwarded identities from this uid when started with SAFESKI_BROKER_TRUST_UID=$(id -u).")
        var allowNonRoot = false

        func run() throws {
            let broker = BrokerServer(socketPath: socket ?? BrokerConfig.socketPath,
                                      registryDir: registry ?? BrokerConfig.registryDir,
                                      allowNonRoot: allowNonRoot)
            if getuid() != 0, !allowNonRoot { Output.fail("the broker must run as root (launchd), or pass --allow-non-root for testing") }
            if allowNonRoot, getuid() != 0 {
                FileHandle.standardError.write(Data("warning: running as uid \(getuid()); agents must be started with SAFESKI_BROKER_TRUST_UID=\(getuid()) to trust this broker\n".utf8))
            }
            try broker.start()
            signal(SIGPIPE, SIG_IGN)
            for sig in [SIGTERM, SIGINT] {
                let src = DispatchSource.makeSignalSource(signal: sig, queue: .main)
                signal(sig, SIG_IGN)
                src.setEventHandler { broker.stop(); Foundation.exit(0) }
                src.resume()
                _ = Unmanaged.passRetained(src)  // keep alive for the process lifetime
            }
            RunLoop.main.run()
        }
    }

    struct Install: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the LaunchDaemon plist and the sudo commands that install it. Never runs sudo itself.")
        @Option(help: "Write the plist here instead of stdout.") var out: String?
        @Option(help: "Binary launchd should run. Default: copy this binary to \(BrokerCmd.libexec).") var binary: String?
        @Flag(help: "Run the current binary in place instead of copying it to \(BrokerCmd.libexec).") var inPlace = false

        func run() throws {
            let current = CallerIdentity.resolvePath(pid: getpid()) ?? URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
            let target = binary ?? (inPlace ? current : "\(BrokerCmd.libexec)/safeski")
            let plist = BrokerCmd.plist(executable: target)
            var steps: [String] = []
            if binary == nil, !inPlace {
                steps.append("sudo mkdir -p \(BrokerCmd.libexec)")
                steps.append("sudo install -m 0755 -o root -g wheel '\(current)' '\(target)'")
            }
            steps.append("sudo mkdir -p -m 0755 /var/run/safeski")
            steps.append("sudo mkdir -p /var/run/safeski/agents && sudo chmod 1777 /var/run/safeski/agents")
            if let out {
                try plist.write(toFile: out, atomically: true, encoding: .utf8)
                steps.append("sudo install -m 0644 -o root -g wheel '\(out)' \(BrokerCmd.plistPath)")
            } else {
                print(plist)
                print("# ---- save the plist above to a file (or rerun with --out FILE), then: ----")
                steps.append("sudo install -m 0644 -o root -g wheel ./\(BrokerCmd.label).plist \(BrokerCmd.plistPath)")
            }
            steps.append("sudo launchctl bootout system/\(BrokerCmd.label) 2>/dev/null || true")
            steps.append("sudo launchctl bootstrap system \(BrokerCmd.plistPath)")
            steps.append("safeski agent uninstall && safeski agent install   # restart your agent so it registers with the broker")
            if out != nil { print("wrote \(out!)") }
            print("# Install the broker by running these commands yourself (safeski never runs sudo):")
            for s in steps { print(s) }
            print("# Note: /var/run is cleared on reboot; the plist recreates the directories on load.")
        }
    }

    struct Uninstall: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the sudo commands that remove the LaunchDaemon.")
        func run() throws {
            print("# Remove the broker by running these commands yourself (safeski never runs sudo):")
            print("sudo launchctl bootout system/\(BrokerCmd.label)")
            print("sudo rm -f \(BrokerCmd.plistPath)")
            print("sudo rm -rf /var/run/safeski")
            print("sudo rm -rf \(BrokerCmd.libexec)   # only if the binary was copied there")
        }
    }

    struct BrokerStatus: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "status", abstract: "Show whether the broker is listening and which users have registered agents.")
        @Option(help: "Broker socket path.") var socket: String?
        @Option(help: "Registry directory.") var registry: String?
        @Flag(name: .long, help: "Emit JSON.") var json = false

        struct Report: Encodable {
            struct Entry: Encodable { var uid: UInt32; var socket: String?; var listening: Bool; var error: String? }
            var socket: String; var listening: Bool; var registry: String; var agents: [Entry]
        }

        func run() throws {
            let sock = socket ?? BrokerConfig.socketPath
            let reg = BrokerRegistry(dir: registry ?? BrokerConfig.registryDir)
            let agents = reg.list().map { e in
                Report.Entry(uid: e.uid, socket: e.socketPath, listening: e.socketPath.map { UnixSocketClient.isListening(path: $0) } ?? false, error: e.error)
            }
            let rep = Report(socket: sock, listening: UnixSocketClient.isListening(path: sock), registry: reg.dir, agents: agents)
            if json { Output.json(rep); return }
            print("broker socket: \(rep.socket) (\(rep.listening ? "listening" : "not listening"))")
            print("registry:      \(rep.registry)\(reg.exists ? "" : " (missing)")")
            if agents.isEmpty { print("registered agents: none") }
            for a in agents {
                let who = getpwuid(a.uid).map { String(cString: $0.pointee.pw_name) } ?? "?"
                if let s = a.socket { print("  uid \(a.uid) (\(who)): \(s) \(a.listening ? "running" : "NOT RUNNING")") }
                else { print("  uid \(a.uid) (\(who)): invalid entry: \(a.error ?? "?")") }
            }
            if !rep.listening { throw ExitCode(1) }
        }
    }

    static func plist(executable: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(label)</string>
          <key>ProgramArguments</key><array><string>\(executable)</string><string>broker</string><string>start</string></array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
          <key>UserName</key><string>root</string>
          <key>StandardOutPath</key><string>/var/log/safeski-broker.log</string>
          <key>StandardErrorPath</key><string>/var/log/safeski-broker.log</string>
        </dict></plist>
        """
    }
}
