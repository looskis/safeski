import Foundation
import Darwin

/// RPC client over the agent's unix socket. One connection per client instance; requests are serialized.
public final class RPCClient {
    public let socketPath: String
    public var token: String?
    /// Optional request sent once, immediately after connecting (e.g. the broker's `_broker.connect`).
    /// Its response must not be an error, or the connection is dropped and the error thrown.
    public var connectHello: RPCRequest?
    private var fd: Int32 = -1
    private var nextID = 1
    private let lock = NSLock()

    public init(socketPath: String, token: String? = nil, connectHello: RPCRequest? = nil) {
        self.socketPath = socketPath; self.token = token; self.connectHello = connectHello
    }
    deinit { if fd >= 0 { close(fd) } }

    private func ensureConnected() throws {
        if fd >= 0 { return }
        fd = try UnixSocketClient.connect(path: socketPath)
        guard let hello = connectHello else { return }
        do {
            try Framing.writeFrame(fd: fd, try JSONEncoder.safeskiCompact.encode(hello))
            guard let data = try Framing.readFrame(fd: fd) else { throw SafeskiError.rpc("connection closed during hello") }
            let resp = try JSONDecoder.safeski.decode(RPCResponse.self, from: data)
            if let e = resp.error { throw e.asError }
        } catch {
            close(fd); fd = -1
            throw error
        }
    }

    /// Connect eagerly (and send the hello, if any). `call` connects lazily otherwise.
    public func connect() throws {
        lock.lock(); defer { lock.unlock() }
        try ensureConnected()
    }

    public func call(_ method: String, params: JSONValue = .object([:])) throws -> JSONValue {
        lock.lock(); defer { lock.unlock() }
        try ensureConnected()
        let id = nextID; nextID += 1
        let req = RPCRequest(id: id, method: method, params: params, token: token)
        try Framing.writeFrame(fd: fd, try JSONEncoder.safeskiCompact.encode(req))
        guard let data = try Framing.readFrame(fd: fd) else {
            close(fd); fd = -1
            throw SafeskiError.rpc("agent closed connection")
        }
        let resp = try JSONDecoder.safeski.decode(RPCResponse.self, from: data)
        if let e = resp.error { throw e.asError }
        return resp.result ?? .null
    }

    public func call<P: Encodable, R: Decodable>(_ method: String, _ params: P, as: R.Type) throws -> R {
        try call(method, params: try JSONValue(params)).decode(R.self)
    }
    public func call<R: Decodable>(_ method: String, as: R.Type) throws -> R {
        try call(method).decode(R.self)
    }
}
