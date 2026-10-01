import ArgumentParser
import Foundation
import SafeskiCore

/// `safeski ssh`: everything needed to point ssh and git at the safeski ssh-agent.
struct SSHCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ssh",
        abstract: "Use safeski keys with ssh and git (agent socket, public keys, commit signing).",
        subcommands: [Keys.self, Setup.self, AllowedSigners.self, Env.self]
    )

    // MARK: helpers shared by the subcommands

    struct SSHKeyInfo: Encodable {
        var name: String
        var kind: KeyKind
        var type: String
        var fingerprint: String
        var publicKey: String
    }

    static func sshKeys(_ b: Backend) throws -> [(key: KeySummary, identity: SSHIdentity)] {
        SSHKeys.identities(for: try b.listKeys())
    }

    static func info(_ k: KeySummary, _ id: SSHIdentity) -> SSHKeyInfo {
        SSHKeyInfo(name: k.name, kind: k.kind, type: id.type, fingerprint: id.fingerprint, publicKey: id.authorizedKeyLine)
    }

    /// The socket ssh clients should use: whatever the running agent reports, else the default path.
    static func socketPath(_ b: Backend) -> String {
        if b.isRemote, let s = (try? b.status())?.sshSocket { return s }
        return SafeskiPaths.default.sshAgentSocket.path
    }

    /// Principal for allowed_signers: `git config user.email`, else USER@hostname.
    static func defaultPrincipal() -> String {
        if let email = gitConfig("user.email"), !email.isEmpty { return email }
        let user = ProcessInfo.processInfo.environment["USER"] ?? NSUserName()
        let host = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        return "\(user)@\(host)"
    }

    static func gitConfig(_ key: String) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["git", "config", "--get", key]
        let pipe = Pipe(); p.standardOutput = pipe; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        p.waitUntilExit()
        guard p.terminationStatus == 0 else { return nil }
        return String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func pick(_ keys: [(key: KeySummary, identity: SSHIdentity)], name: String?) throws -> (key: KeySummary, identity: SSHIdentity) {
        if let n = name {
            guard let k = keys.first(where: { $0.key.name == n }) else {
                throw SafeskiError.notFound("ssh-capable key '\(n)' (see `safeski ssh keys`)")
            }
            return k
        }
        guard let first = keys.first else {
            throw SafeskiError.notFound("no ssh-capable keys; create one with `safeski keygen <name>`")
        }
        return first
    }

    // MARK: keys

    struct Keys: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print authorized_keys lines for every ssh-capable key.")
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let keys = try SSHCmd.sshKeys(try g.backend())
            if g.json { Output.json(keys.map { SSHCmd.info($0.key, $0.identity) }); return }
            if keys.isEmpty { print("no ssh-capable keys. create one with: safeski keygen <name>"); return }
            for (_, id) in keys { print(id.authorizedKeyLine) }
        }
    }

    // MARK: setup

    struct Setup: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the ssh config, shell export, and git signing commands for this agent.")
        @Option(help: "Key to use for git commit signing (default: first ssh-capable key).") var key: String?
        @Option(help: "Principal for the allowed_signers line (default: git user.email, else USER@host).") var principal: String?
        @Option(help: "Path for the allowed signers file in the printed git commands.") var allowedSignersFile: String = "~/.ssh/allowed_signers"
        @Flag(help: "Print `git config --global` instead of repository-local commands.") var global = false
        @OptionGroup var g: GlobalOptions

        struct Plan: Encodable {
            var sshSocket: String
            var sshConfig: String
            var shellExport: String
            var signingKey: SSHKeyInfo?
            var gitCommands: [String]
            var allowedSignersLine: String?
            var allowedSignersFile: String
        }

        func run() throws {
            let b = try g.backend()
            let sock = SSHCmd.socketPath(b)
            let keys = try SSHCmd.sshKeys(b)
            let chosen = keys.isEmpty ? nil : try SSHCmd.pick(keys, name: key)
            let who = principal ?? SSHCmd.defaultPrincipal()
            let scope = global ? "--global " : ""
            let sshConfig = "Host *\n    IdentityAgent \"\(sock)\""
            let export = "export SSH_AUTH_SOCK=\"\(sock)\""
            var git: [String] = []
            if let c = chosen {
                git = [
                    "git config \(scope)gpg.format ssh",
                    // "key::" tells git the value is a literal public key, not a file path.
                    "git config \(scope)user.signingkey \"key::\(c.identity.authorizedKeyLine)\"",
                    "git config \(scope)commit.gpgsign true",
                    "git config \(scope)gpg.ssh.allowedSignersFile \(allowedSignersFile)",
                ]
            }
            let signers = chosen.map { "\(who) \($0.identity.authorizedKeyLine)" }
            if g.json {
                Output.json(Plan(sshSocket: sock, sshConfig: sshConfig, shellExport: export,
                                 signingKey: chosen.map { SSHCmd.info($0.key, $0.identity) }, gitCommands: git,
                                 allowedSignersLine: signers, allowedSignersFile: allowedSignersFile))
                return
            }
            print("# ssh agent socket: \(sock)")
            if !b.isRemote { print("# (agent not running: start it with `safeski agent install` or `safeski agent start`)") }
            print("")
            print("# 1. ~/.ssh/config — make ssh/git use the safeski agent")
            print(sshConfig)
            print("")
            print("# 2. shell profile (~/.zshrc) — for ssh-add -L, ssh-keygen -Y, and tools that read SSH_AUTH_SOCK")
            print(export)
            print("")
            if let c = chosen {
                print("# 3. git commit signing with key '\(c.key.name)' (\(c.identity.fingerprint))")
                for line in git { print(line) }
                print("")
                print("# 4. allowed signers — append to \(allowedSignersFile) so `git log --show-signature` verifies")
                print(signers ?? "")
            } else {
                print("# 3. git commit signing: no ssh-capable keys yet. create one with `safeski keygen git-signing`")
            }
        }
    }

    // MARK: allowed-signers

    struct AllowedSigners: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "allowed-signers",
                                                        abstract: "Print `<principal> <pubkey>` lines for git's gpg.ssh.allowedSignersFile.")
        @Option(help: "Principal (default: git user.email, else USER@host).") var principal: String?
        @Option(help: "Only this key (default: every ssh-capable key).") var key: String?
        @OptionGroup var g: GlobalOptions

        struct Line: Encodable { var principal: String; var key: String; var line: String }

        func run() throws {
            var keys = try SSHCmd.sshKeys(try g.backend())
            if let k = key { keys = [try SSHCmd.pick(keys, name: k)] }
            let who = principal ?? SSHCmd.defaultPrincipal()
            let lines = keys.map { Line(principal: who, key: $0.key.name, line: "\(who) \($0.identity.authorizedKeyLine)") }
            if g.json { Output.json(lines); return }
            for l in lines { print(l.line) }
        }
    }

    // MARK: env

    struct Env: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print `export SSH_AUTH_SOCK=...` for eval.")
        @OptionGroup var g: GlobalOptions
        func run() throws {
            let b = try g.backend()
            let sock = SSHCmd.socketPath(b)
            if g.json { Output.json(["SSH_AUTH_SOCK": sock]); return }
            print("export SSH_AUTH_SOCK=\"\(sock)\"")
        }
    }
}
