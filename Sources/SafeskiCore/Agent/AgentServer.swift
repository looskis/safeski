import Foundation

/// The agent: owns the Service and the RPC unix socket. Frontends (SSH agent, proxy, OIDC) attach
/// to the same Service instance in-process.
public final class AgentServer {
    public let service: Service
    public let paths: SafeskiPaths
    private var server: UnixSocketServer?
    public var sshSocketPath: String?
    public var log: (String) -> Void = { msg in
        let ts = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardError.write(Data("\(ts) \(msg)\n".utf8))
    }

    public init(paths: SafeskiPaths = .default, interactive: Bool = true) throws {
        self.paths = paths
        try paths.ensureLayout()
        self.service = try Service(store: Store(paths: paths), interactive: interactive)
    }

    public func start() throws {
        let sockPath = paths.agentSocket.path
        let srv = UnixSocketServer(path: sockPath, label: "agent") { [weak self] fd, ident in
            self?.handle(fd: fd, caller: ident)
        }
        try srv.start()
        server = srv
        log("agent listening on \(sockPath)")
        try? service.audit.append(action: "agent.start", outcome: "allow", caller: nil,
                                  detail: ["pid": .number(Double(getpid())), "version": .string(Version.string)])
    }

    public func stop() {
        server?.stop()
        try? service.audit.append(action: "agent.stop", outcome: "allow", caller: nil)
    }

    private func handle(fd: Int32, caller peer: CallerIdentity) {
        var caller = peer
        var first = true
        while true {
            let frame: Data?
            do { frame = try Framing.readFrame(fd: fd) } catch { return }
            guard let frame else { return }
            let resp: RPCResponse
            do {
                let req = try JSONDecoder.safeski.decode(RPCRequest.self, from: frame)
                if first, req.method == BrokerProtocol.helloMethod {
                    // The root broker forwards the real caller's identity in its first frame.
                    first = false
                    if BrokerProtocol.isTrustedBrokerPeer(peer) {
                        caller = try BrokerProtocol.forwardedIdentity(from: req.params)
                        resp = RPCResponse(id: req.id, result: .bool(true))
                    } else {
                        resp = RPCResponse(id: req.id, error: RPCError(code: "denied", message: "\(BrokerProtocol.helloMethod) is only accepted from the root broker"))
                    }
                } else {
                    first = false
                    resp = service.dispatch(req, caller: caller, socket: paths.agentSocket.path, sshSocket: sshSocketPath)
                }
            } catch {
                resp = RPCResponse(id: 0, error: RPCError(code: "invalid_format", message: "bad request: \(error.localizedDescription)"))
            }
            do { try Framing.writeFrame(fd: fd, try JSONEncoder.safeskiCompact.encode(resp)) } catch { return }
        }
    }
}
