import Foundation
import SafeskiCore

/// Owned by the SSH module: wires the ssh-agent socket into the running agent process.
enum SSHFrontend {
    private static var server: SSHAgentServer?

    static func start(agent: AgentServer) throws {
        let srv = SSHAgentServer(agent: agent)
        try srv.start()
        server = srv
    }

    static func stop() {
        server?.stop()
        server = nil
    }
}
