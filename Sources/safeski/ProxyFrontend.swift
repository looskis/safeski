import Foundation
import SafeskiCore

// Owned by the Proxy module. Attaches the secretless proxy to the running agent.
enum ProxyFrontend {
    private static var module: ProxyModule?

    static func start(agent: AgentServer) throws {
        let m = ProxyModule(service: agent.service)
        m.log = agent.log
        module = m
        do { try m.start() }
        catch {
            // A busy port must not take the whole agent down; the RPC methods stay registered so
            // `safeski proxy status` can explain what happened.
            agent.log("proxy: failed to start: \(error.localizedDescription)")
        }
    }

    static func stop() {
        module?.stop()
        module = nil
    }
}
