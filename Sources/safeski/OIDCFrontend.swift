import Foundation
import SafeskiCore

/// Agent-side OIDC: registers the `oidc.token` / `oidc.jwks` / `oidc.discovery` RPC methods, reports
/// issuer + key in `status`, and (when `[oidc].listen` is set) serves discovery + JWKS over a tiny
/// local HTTP server so consumers on this Mac can validate safeski tokens without public hosting.
enum OIDCFrontend {
    static let tokenMethod = "oidc.token"
    static let jwksMethod = "oidc.jwks"
    static let discoveryMethod = "oidc.discovery"

    private static var server: OIDCHTTPServer?

    /// Build an issuer from the agent's *current* policy, so `policy.reload` takes effect.
    static func makeIssuer(agent: AgentServer, caller: CallerIdentity) throws -> OIDCIssuer {
        let service = agent.service
        let config = try OIDCConfig(policy: service.policy)
        let dev = try service.store.loadDevice()
        let issuer = OIDCIssuer(config: config, access: OIDCKeyAccess(service: service, caller: caller),
                                deviceID: dev.deviceID, deviceName: dev.name)
        issuer.onMint = { minted, _ in
            _ = try? service.audit.append(action: "oidc.token", resource: minted.key, outcome: "allow", caller: caller, detail: [
                "aud": .string(minted.aud), "sub": .string(minted.sub), "kid": .string(minted.kid),
                "jti": .string(minted.jti), "exp": .number(Double(minted.exp)),
            ])
        }
        return issuer
    }

    static func start(agent: AgentServer) throws {
        let service = agent.service

        service.extraMethods[tokenMethod] = { params, caller in
            let req = try params.decode(TokenRequest.self)
            return try JSONValue(try makeIssuer(agent: agent, caller: caller).mint(req))
        }
        service.extraMethods[jwksMethod] = { _, caller in try makeIssuer(agent: agent, caller: caller).jwks() }
        service.extraMethods[discoveryMethod] = { _, caller in try makeIssuer(agent: agent, caller: caller).discovery() }

        // Chain onto whatever another module already reports.
        let previous = service.statusExtras
        service.statusExtras = {
            var extra = previous()
            guard let cfg = try? OIDCConfig(policy: service.policy), cfg.isConfigured else { return extra }
            extra["oidc.issuer"] = .string(cfg.issuer ?? "(unset)")
            extra["oidc.key"] = .string(cfg.key)
            if let k = try? service.store.loadKey(cfg.key), k.kind == .enclaveSigning,
               let j = OIDCDiscovery.jwk(for: k.summary), let kid = j["kid"]?.stringValue {
                extra["oidc.kid"] = .string(kid)
            }
            if let s = server { extra["oidc.listen"] = .string(s.url) }
            return extra
        }

        // Local discovery server. A bad config is logged, not fatal: the agent's other duties continue.
        let config: OIDCConfig
        do { config = try OIDCConfig(policy: service.policy) }
        catch { agent.log("oidc: \(error.localizedDescription)"); return }
        guard let listen = config.listen else { return }
        // Served documents reflect the agent's own (owner) view of the keys; no policy prompt is
        // involved because only public material is read.
        let owner = CallerIdentity.local()
        let srv = try OIDCHTTPServer(listen: listen, handler: OIDCHTTPServer.routes(issuer: {
            try makeIssuer(agent: agent, caller: owner)
        }))
        srv.log = { agent.log("oidc http: \($0)") }
        do {
            try srv.start()
            server = srv
            agent.log("oidc discovery listening on \(srv.url) (issuer \(config.issuer ?? "(unset)"))")
        } catch {
            agent.log("oidc: discovery server not started: \(error.localizedDescription)")
        }
    }

    static func stop() {
        server?.stop()
        server = nil
    }
}
