import Darwin
import Foundation

/// The broker lets callers reach another macOS user's agent (or their own, from a context
/// where the per-user socket is not reachable). It is a root LaunchDaemon that owns a
/// world-connectable socket, identifies the real peer, looks up the target user's agent
/// socket in a registry, connects to it as root, forwards the peer's identity in a
/// `_broker.hello` frame, then pumps bytes in both directions. The broker audits nothing:
/// the agent audits with the forwarded identity.
public enum BrokerProtocol {
    /// First frame a client sends to the broker: `{"id":0,"method":"_broker.connect","params":{"user":"<uid|name>"}}`.
    public static let connectMethod = "_broker.connect"
    /// First frame the broker sends to the agent: `{"id":0,"method":"_broker.hello","params":{"caller":{...}}}`.
    public static let helloMethod = "_broker.hello"
    public static let transport = "broker"

    /// Build the forwarded-identity hello the broker sends to an agent.
    public static func helloRequest(caller: CallerIdentity) throws -> RPCRequest {
        var c = caller
        c.transport = transport
        return RPCRequest(id: 0, method: helloMethod, params: .object(["caller": try JSONValue(c)]))
    }

    /// Decode the forwarded identity from a `_broker.hello` params object. The transport is always
    /// forced to "broker" so a forwarded identity can never masquerade as "unix" or "local".
    public static func forwardedIdentity(from params: JSONValue) throws -> CallerIdentity {
        guard let raw = params["caller"] else { throw SafeskiError.invalidFormat("_broker.hello: missing caller") }
        var c = try raw.decode(CallerIdentity.self)
        c.transport = transport
        c.tokenName = nil
        return c
    }

    /// Whether `peer` is allowed to assert a forwarded identity on an agent socket: root, or (test-only)
    /// the uid named by `SAFESKI_BROKER_TRUST_UID`.
    public static func isTrustedBrokerPeer(_ peer: CallerIdentity) -> Bool {
        guard let uid = peer.uid else { return false }
        if uid == 0 { return true }
        if let s = ProcessInfo.processInfo.environment["SAFESKI_BROKER_TRUST_UID"], let t = UInt32(s), t == uid { return true }
        return false
    }

    /// Build the client-side hello for the broker.
    public static func connectRequest(user: String?) -> RPCRequest {
        var p: [String: JSONValue] = [:]
        if let u = user, !u.isEmpty { p["user"] = .string(u) }
        return RPCRequest(id: 0, method: connectMethod, params: .object(p))
    }
}

/// Where the broker socket and registry live. Overridable for tests and non-root runs.
public enum BrokerConfig {
    public static let defaultSocket = "/var/run/safeski/broker.sock"
    public static let defaultRegistry = "/var/run/safeski/agents"

    public static var socketPath: String {
        if let s = ProcessInfo.processInfo.environment["SAFESKI_BROKER_SOCKET"], !s.isEmpty { return s }
        return defaultSocket
    }
    public static var registryDir: String {
        if let s = ProcessInfo.processInfo.environment["SAFESKI_BROKER_REGISTRY"], !s.isEmpty { return s }
        return defaultRegistry
    }
}

/// `<registry>/<uid>` -> a file containing the agent socket path. The directory is 1777 so each
/// user can write their own entry; the broker only trusts an entry owned by that uid.
public struct BrokerRegistry {
    public let dir: String
    public init(dir: String = BrokerConfig.registryDir) { self.dir = dir }

    public func entryPath(uid: uid_t) -> String { "\(dir)/\(uid)" }

    public var exists: Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: dir, isDirectory: &isDir) && isDir.boolValue
    }
    public var isWritable: Bool { exists && access(dir, W_OK) == 0 }

    /// Create the registry directory (mode 1777). Intended to run as root; works for tests too.
    public func create() throws {
        if !exists {
            guard mkdir(dir, 0o1777) == 0 || errno == EEXIST else {
                throw SafeskiError.io("mkdir \(dir): \(String(cString: strerror(errno)))")
            }
        }
        chmod(dir, 0o1777)
    }

    /// Write this uid's entry (0644). Replaces any existing entry we own.
    public func register(uid: uid_t = getuid(), socketPath: String) throws {
        let p = entryPath(uid: uid)
        unlink(p)
        let fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { throw SafeskiError.io("register \(p): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        try Framing.writeAll(fd: fd, Data((socketPath + "\n").utf8))
        fchmod(fd, 0o644)
    }

    public func unregister(uid: uid_t = getuid()) {
        unlink(entryPath(uid: uid))
    }

    /// Resolve the agent socket for `uid`. Only a regular file owned by `uid` is trusted, and the
    /// socket it names must itself be owned by `uid`.
    public func lookup(uid: uid_t) throws -> String {
        let p = entryPath(uid: uid)
        var st = stat()
        guard lstat(p, &st) == 0 else { throw SafeskiError.notFound("no agent registered for uid \(uid)") }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw SafeskiError.denied("registry entry for uid \(uid) is not a regular file") }
        guard st.st_uid == uid else { throw SafeskiError.denied("registry entry for uid \(uid) is owned by uid \(st.st_uid)") }
        guard st.st_size < 4096 else { throw SafeskiError.invalidFormat("registry entry for uid \(uid) too large") }
        let text = String(decoding: try FileIO.read(URL(fileURLWithPath: p)), as: UTF8.self)
        let sock = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard sock.hasPrefix("/") else { throw SafeskiError.invalidFormat("registry entry for uid \(uid) is not an absolute path") }
        var sst = stat()
        guard stat(sock, &sst) == 0 else { throw SafeskiError.notFound("agent socket for uid \(uid) does not exist (\(sock))") }
        guard (sst.st_mode & S_IFMT) == S_IFSOCK else { throw SafeskiError.denied("\(sock) is not a socket") }
        guard sst.st_uid == uid else { throw SafeskiError.denied("agent socket \(sock) is owned by uid \(sst.st_uid), not \(uid)") }
        return sock
    }

    public struct Entry { public var uid: uid_t; public var socketPath: String?; public var error: String? }

    /// Every entry in the registry, with its resolution status.
    public func list() -> [Entry] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return [] }
        return names.compactMap { UInt32($0) }.sorted().map { uid in
            do { return Entry(uid: uid, socketPath: try lookup(uid: uid), error: nil) }
            catch { return Entry(uid: uid, socketPath: nil, error: (error as? SafeskiError)?.message ?? error.localizedDescription) }
        }
    }

    /// Resolve "501" or "alice" to a uid.
    public static func resolveUser(_ s: String) throws -> uid_t {
        if let n = UInt32(s) { return n }
        guard let pw = getpwnam(s) else { throw SafeskiError.notFound("unknown user '\(s)'") }
        return pw.pointee.pw_uid
    }
}

public final class BrokerServer {
    public let socketPath: String
    public let registry: BrokerRegistry
    public let allowNonRoot: Bool
    private var server: UnixSocketServer?
    public var log: (String) -> Void = { msg in
        let ts = ISO8601DateFormatter().string(from: Date())
        FileHandle.standardError.write(Data("\(ts) broker: \(msg)\n".utf8))
    }

    public init(socketPath: String = BrokerConfig.socketPath, registryDir: String = BrokerConfig.registryDir, allowNonRoot: Bool = false) {
        self.socketPath = socketPath
        self.registry = BrokerRegistry(dir: registryDir)
        self.allowNonRoot = allowNonRoot
    }

    public func start() throws {
        guard getuid() == 0 || allowNonRoot else { throw SafeskiError.denied("the broker must run as root (or pass allowNonRoot for tests)") }
        // Socket directory 0755 (not the 0700 UnixSocketServer would create) so any user can connect.
        let dir = (socketPath as NSString).deletingLastPathComponent
        if mkdir(dir, 0o755) != 0, errno != EEXIST { throw SafeskiError.io("mkdir \(dir): \(String(cString: strerror(errno)))") }
        chmod(dir, 0o755)
        try registry.create()
        let srv = UnixSocketServer(path: socketPath, label: "broker") { [weak self] fd, peer in
            self?.handle(fd: fd, peer: peer)
        }
        try srv.start()
        srv.setMode(0o666)
        server = srv
        log("listening on \(socketPath), registry \(registry.dir)")
    }

    public func stop() { server?.stop(); server = nil }

    private func reply(fd: Int32, _ resp: RPCResponse) {
        if let d = try? JSONEncoder.safeskiCompact.encode(resp) { try? Framing.writeFrame(fd: fd, d) }
    }

    private func handle(fd: Int32, peer: CallerIdentity) {
        // 1. hello from the client
        let req: RPCRequest
        do {
            guard let frame = try Framing.readFrame(fd: fd) else { return }
            req = try JSONDecoder.safeski.decode(RPCRequest.self, from: frame)
        } catch {
            reply(fd: fd, RPCResponse(id: 0, error: RPCError(code: "invalid_format", message: "bad hello: \(error.localizedDescription)")))
            return
        }
        guard req.method == BrokerProtocol.connectMethod else {
            reply(fd: fd, RPCResponse(id: req.id, error: RPCError(code: "rpc", message: "first frame must be \(BrokerProtocol.connectMethod)")))
            return
        }
        // 2. resolve the target agent
        let agentFD: Int32
        let uid: uid_t
        do {
            if let u = req.params["user"]?.stringValue, !u.isEmpty { uid = try BrokerRegistry.resolveUser(u) }
            else if let n = req.params["user"]?.intValue { uid = uid_t(n) }
            else if let own = peer.uid { uid = own }
            else { throw SafeskiError.denied("cannot determine caller uid") }
            let sock = try registry.lookup(uid: uid)
            do { agentFD = try UnixSocketClient.connect(path: sock) }
            catch { throw SafeskiError.notFound("agent for uid \(uid) is not running (\(sock))") }
        } catch {
            reply(fd: fd, RPCResponse(id: req.id, error: RPCError(error)))
            return
        }
        defer { close(agentFD) }
        // 3. forwarded-identity hello to the agent
        do {
            let hello = try BrokerProtocol.helloRequest(caller: peer)
            try Framing.writeFrame(fd: agentFD, try JSONEncoder.safeskiCompact.encode(hello))
            guard let frame = try Framing.readFrame(fd: agentFD) else { throw SafeskiError.rpc("agent closed during hello") }
            let resp = try JSONDecoder.safeski.decode(RPCResponse.self, from: frame)
            if let e = resp.error { throw e.asError }
        } catch {
            reply(fd: fd, RPCResponse(id: req.id, error: RPCError(code: "rpc", message: "agent refused forwarded identity: \((error as? SafeskiError)?.message ?? error.localizedDescription)")))
            return
        }
        reply(fd: fd, RPCResponse(id: req.id, result: .object(["uid": .number(Double(uid))])))
        log("\(peer.description) -> uid \(uid)")
        // 4. pump bytes both ways until either side closes
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            BrokerServer.pump(from: agentFD, to: fd)
            shutdown(fd, SHUT_WR)
            done.signal()
        }
        BrokerServer.pump(from: fd, to: agentFD)
        shutdown(agentFD, SHUT_WR)
        done.wait()
    }

    static func pump(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = buf.withUnsafeMutableBytes { Darwin.read(src, $0.baseAddress, $0.count) }
            if n < 0 { if errno == EINTR { continue }; return }
            if n == 0 { return }
            do { try Framing.writeAll(fd: dst, Data(buf[0..<n])) } catch { return }
        }
    }
}
