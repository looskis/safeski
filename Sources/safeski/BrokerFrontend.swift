import Foundation
import SafeskiCore

/// Agent-side half of the broker: publish this user's agent socket in the broker registry
/// (`/var/run/safeski/agents/<uid>`, or `SAFESKI_BROKER_REGISTRY`) so the root broker can
/// forward other users' requests to it. Silently a no-op when no registry directory exists.
enum BrokerFrontend {
    private static var registered: BrokerRegistry?

    static func registerWithBroker(agent: AgentServer) throws {
        let reg = BrokerRegistry()
        guard reg.isWritable else { return }
        do {
            try reg.register(uid: getuid(), socketPath: agent.paths.agentSocket.path)
            registered = reg
            agent.log("registered with broker: \(reg.entryPath(uid: getuid())) -> \(agent.paths.agentSocket.path)")
        } catch {
            agent.log("broker registry \(reg.dir): \(error.localizedDescription) (continuing without broker)")
        }
    }

    static func stop() {
        registered?.unregister(uid: getuid())
        registered = nil
    }
}
