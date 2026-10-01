import Foundation
import Darwin

/// RPC client over the agent's unix socket. One connection per client instance; requests are serialized.
public final class RPCClient {
    public let socketPath: String
    public var token: String?
    private var fd: Int32 = -1
    private var nextID = 1
    private let lock = NSLock()

    public init(socketPath: String, token: String? = nil) {
        self.socketPath = socketPath; self.token = token
    }
    deinit { if fd >= 0 { close(fd) } }

    private func ensureConnected() throws {
        if fd < 0 { fd = try UnixSocketClient.connect(path: socketPath) }
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
