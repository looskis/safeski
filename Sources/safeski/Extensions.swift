import ArgumentParser
import Foundation
import SafeskiCore

/// Registration points for optional modules. Each module owns one file in this target
/// (SSHCommands.swift, ProxyCommands.swift, OIDCCommands.swift, PKCS11Commands.swift,
/// BrokerCommands.swift) and exposes a command type plus an optional agent frontend hook.
enum ExtraCommands {
    static var all: [ParsableCommand.Type] {
        [SSHCmd.self, ProxyCmd.self, OIDCCmd.self, PKCS11Cmd.self, BrokerCmd.self, DockerCmd.self]
    }
}

enum AgentExtensions {
    static func start(agent: AgentServer, ssh: Bool, proxy: Bool) throws {
        if ssh { try SSHFrontend.start(agent: agent) }
        if proxy { try ProxyFrontend.start(agent: agent) }
        try OIDCFrontend.start(agent: agent)
        try BrokerFrontend.registerWithBroker(agent: agent)
    }
    static func stop() {
        SSHFrontend.stop(); ProxyFrontend.stop(); OIDCFrontend.stop(); BrokerFrontend.stop()
    }
}
