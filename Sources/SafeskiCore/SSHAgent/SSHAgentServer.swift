import Foundation

/// ssh-agent frontend. Listens on a unix socket (normally `paths.sshAgentSocket`) and serves
/// every ssh-capable key through `Service.sign`, so policy, approvals, and the audit log apply
/// exactly as for RPC callers. The peer is identified by the socket server (`CallerIdentity`),
/// which is what policy rules such as `{ path = "/usr/bin/ssh" }` match against.
public final class SSHAgentServer {
    public let service: Service
    public let path: String
    private var server: UnixSocketServer?
    public var log: (String) -> Void = { _ in }

    public init(service: Service, path: String) {
        self.service = service
        self.path = path
    }

    /// Convenience: serve `agent.service` on `agent.paths.sshAgentSocket` and advertise the socket
    /// through `agent.sshSocketPath` so `safeski status` shows it.
    public convenience init(agent: AgentServer) {
        self.init(service: agent.service, path: agent.paths.sshAgentSocket.path)
        self.log = agent.log
        self.agent = agent
    }

    private weak var agent: AgentServer?

    public func start() throws {
        let srv = UnixSocketServer(path: path, label: "ssh-agent") { [weak self] fd, ident in
            self?.handle(fd: fd, caller: ident)
        }
        try srv.start()
        server = srv
        agent?.sshSocketPath = path
        log("ssh agent listening on \(path)")
    }

    public func stop() {
        server?.stop()
        server = nil
        if agent?.sshSocketPath == path { agent?.sshSocketPath = nil }
    }

    // MARK: connection handling

    /// One ssh client connection: loop reading frames until the peer hangs up. Any error in a
    /// single request yields `SSH_AGENT_FAILURE`; only transport errors end the loop.
    func handle(fd: Int32, caller: CallerIdentity) {
        while true {
            let frame: Data?
            do { frame = try Framing.readFrame(fd: fd) } catch {
                log("ssh: \(caller.displayName): \(error.localizedDescription)")
                return
            }
            guard let frame else { return }
            let reply = respond(to: frame, caller: caller)
            do { try Framing.writeFrame(fd: fd, reply) } catch { return }
        }
    }

    /// Compute the reply to one request frame. Never throws; never crashes.
    public func respond(to frame: Data, caller: CallerIdentity) -> Data {
        let req: SSHAgentRequest
        do { req = try SSHAgentProtocol.parseRequest(frame) } catch {
            log("ssh: \(caller.displayName): malformed request: \(error.localizedDescription)")
            return SSHAgentProtocol.failureReply
        }
        switch req {
        case .requestIdentities:
            do {
                let ids = SSHKeys.identities(for: try service.listKeys(caller: caller)).map(\.identity)
                return SSHAgentProtocol.identitiesAnswer(ids)
            } catch {
                log("ssh: \(caller.displayName): list keys: \(error.localizedDescription)")
                return SSHAgentProtocol.failureReply
            }
        case let .signRequest(keyBlob, data, _):
            return sign(keyBlob: keyBlob, data: data, caller: caller)
        case .lock, .unlock:
            return SSHAgentProtocol.failureReply
        case .extensionRequest(let name):
            log("ssh: \(caller.displayName): unsupported extension \(name)")
            return SSHAgentProtocol.failureReply
        case .unsupported(let type):
            log("ssh: \(caller.displayName): refused message type \(type) (keys are managed by safeski)")
            return SSHAgentProtocol.failureReply
        }
    }

    private func sign(keyBlob: Data, data: Data, caller: CallerIdentity) -> Data {
        do {
            let keys = try service.listKeys(caller: caller)
            guard let match = SSHKeys.identities(for: keys).first(where: { $0.identity.blob == keyBlob }) else {
                log("ssh: \(caller.displayName): sign request for unknown key")
                return SSHAgentProtocol.failureReply
            }
            let raw = try service.sign(SignParams(key: match.key.name, data: data, digest: false, purpose: "ssh"), caller: caller)
            let blob = try SSHKeys.signatureBlob(kind: match.key.kind, raw: raw)
            return SSHAgentProtocol.signResponse(blob)
        } catch {
            log("ssh: \(caller.displayName): sign: \(error.localizedDescription)")
            return SSHAgentProtocol.failureReply
        }
    }
}
