import CryptoKit
import Foundation

/// OpenID discovery and JWKS documents for the safeski issuer.
public enum OIDCDiscovery {
    public static let configurationPath = "/.well-known/openid-configuration"
    public static let jwksPath = "/.well-known/jwks.json"
    /// Also served, for hosts that cannot create a dot-directory.
    public static let jwksAltPath = "/jwks.json"

    /// The JWK (with kid/use/alg) for an enclave-signing key.
    public static func jwk(for key: KeySummary) -> [String: JSONValue]? {
        guard key.kind == .enclaveSigning, let pk = try? P256.Signing.PublicKey(x963Representation: key.publicKey) else { return nil }
        var j = pk.jwk
        j["kid"] = .string(pk.jwkThumbprint)
        j["use"] = .string("sig")
        j["alg"] = .string("ES256")
        return j
    }

    /// JWKS containing `primary` first, then every other enclave-signing key labeled `oidc = "true"`
    /// (lets you publish a successor key before switching `[oidc].key`).
    public static func jwks(keys: [KeySummary], primary: KeySummary) -> JSONValue {
        var out: [JSONValue] = []
        var seen: Set<String> = []
        func add(_ k: KeySummary) {
            guard let j = jwk(for: k), let kid = j["kid"]?.stringValue, !seen.contains(kid) else { return }
            seen.insert(kid); out.append(.object(j))
        }
        add(primary)
        for k in keys.sorted(by: { $0.name < $1.name }) where k.name != primary.name && k.labels["oidc"] == "true" { add(k) }
        return .object(["keys": .array(out)])
    }

    public static func jwksURI(issuer: String) -> String { issuer + jwksPath }

    public static func configuration(issuer: String) -> JSONValue {
        .object([
            "issuer": .string(issuer),
            "jwks_uri": .string(jwksURI(issuer: issuer)),
            "id_token_signing_alg_values_supported": .array([.string("ES256")]),
            "response_types_supported": .array([.string("id_token")]),
            "subject_types_supported": .array([.string("public")]),
            "claims_supported": .array(["iss", "sub", "aud", "iat", "nbf", "exp", "jti"].map { .string($0) }),
            "scopes_supported": .array([.string("openid")]),
            "token_endpoint_auth_methods_supported": .array([.string("none")]),
            "grant_types_supported": .array([.string("urn:ietf:params:oauth:grant-type:token-exchange")]),
        ])
    }

    /// Write `<dir>/.well-known/openid-configuration` and `<dir>/.well-known/jwks.json` (plus
    /// `<dir>/jwks.json`) for static hosting. Returns the files written.
    @discardableResult
    public static func publish(configuration: JSONValue, jwks: JSONValue, to dir: URL) throws -> [URL] {
        let fm = FileManager.default
        let wk = dir.appendingPathComponent(".well-known")
        try fm.createDirectory(at: wk, withIntermediateDirectories: true)
        let files: [(URL, JSONValue)] = [
            (wk.appendingPathComponent("openid-configuration"), configuration),
            (wk.appendingPathComponent("jwks.json"), jwks),
            (dir.appendingPathComponent("jwks.json"), jwks),
        ]
        for (url, doc) in files {
            var data = try JSONEncoder.oidcPretty.encode(doc)
            data.append(0x0a)
            do { try data.write(to: url, options: [.atomic]) }
            catch { throw SafeskiError.io("write \(url.path): \(error.localizedDescription)") }
        }
        return files.map(\.0)
    }
}

/// Minimal HTTP/1.1 server (GET/HEAD only) for serving discovery + JWKS to local consumers.
/// POSIX sockets, one thread per connection, no keep-alive.
public final class OIDCHTTPServer {
    public struct Response {
        public var status: Int
        public var contentType: String
        public var body: Data
        public init(status: Int, contentType: String, body: Data) { self.status = status; self.contentType = contentType; self.body = body }
        public static func json(_ v: JSONValue) -> Response {
            var d = (try? JSONEncoder.oidcPretty.encode(v)) ?? Data("{}".utf8)
            d.append(0x0a)
            return Response(status: 200, contentType: "application/json", body: d)
        }
        public static func text(_ status: Int, _ s: String) -> Response {
            Response(status: status, contentType: "text/plain; charset=utf-8", body: Data((s + "\n").utf8))
        }
    }

    public typealias Handler = (_ path: String) -> Response

    public let host: String
    public private(set) var port: UInt16
    private let handler: Handler
    private var fd: Int32 = -1
    private var running = false
    private let queue = DispatchQueue(label: "safeski.oidc.http", attributes: .concurrent)
    public var log: (String) -> Void = { _ in }

    public init(host: String, port: UInt16, handler: @escaping Handler) {
        self.host = host; self.port = port; self.handler = handler
    }

    public convenience init(listen: String, handler: @escaping Handler) throws {
        let (h, p) = try OIDCConfig.parseListen(listen)
        self.init(host: h, port: p, handler: handler)
    }

    /// Bind and start accepting. With port 0 the kernel picks one; read `port` afterwards.
    public func start() throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SafeskiError.io("socket: \(String(cString: strerror(errno)))") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            close(fd); fd = -1
            throw SafeskiError.io("oidc.listen: '\(host)' is not an IPv4 address")
        }
        let len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let r = withUnsafePointer(to: &addr) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, len) } }
        guard r == 0 else {
            let e = errno; close(fd); fd = -1
            throw SafeskiError.io("bind \(host):\(port): \(String(cString: strerror(e)))")
        }
        guard listen(fd, 16) == 0 else {
            let e = errno; close(fd); fd = -1
            throw SafeskiError.io("listen: \(String(cString: strerror(e)))")
        }
        if port == 0 {
            var bound = sockaddr_in()
            var blen = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = withUnsafeMutablePointer(to: &bound) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &blen) } }
            port = UInt16(bigEndian: bound.sin_port)
        }
        running = true
        let lfd = fd
        Thread.detachNewThread { [weak self] in
            while let self, self.running {
                let cfd = accept(lfd, nil, nil)
                if cfd < 0 { if errno == EINTR { continue }; break }
                var on: Int32 = 1
                setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
                var tv = timeval(tv_sec: 5, tv_usec: 0)
                setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                self.queue.async {
                    self.serve(cfd)
                    close(cfd)
                }
            }
        }
    }

    public func stop() {
        running = false
        if fd >= 0 { close(fd); fd = -1 }
    }

    public var url: String { "http://\(host):\(port)" }

    private func serve(_ cfd: Int32) {
        // Read headers (up to 16 KiB) until the blank line.
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while buf.count < 16384 {
            let n = Darwin.read(cfd, &chunk, chunk.count)
            if n <= 0 { if n < 0 && errno == EINTR { continue }; break }
            buf.append(contentsOf: chunk[0..<n])
            if buf.range(of: Data("\r\n\r\n".utf8)) != nil || buf.range(of: Data("\n\n".utf8)) != nil { break }
        }
        guard let text = String(data: buf, encoding: .utf8), let firstLine = text.split(whereSeparator: { $0 == "\n" || $0 == "\r" }).first else {
            write(cfd, OIDCHTTPServer.render(.text(400, "bad request"), head: false)); return
        }
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2 else { write(cfd, OIDCHTTPServer.render(.text(400, "bad request"), head: false)); return }
        let method = String(parts[0]).uppercased()
        var path = String(parts[1])
        if let q = path.firstIndex(of: "?") { path = String(path[..<q]) }
        guard method == "GET" || method == "HEAD" else {
            write(cfd, OIDCHTTPServer.render(.text(405, "method not allowed"), head: false)); return
        }
        let resp = handler(path)
        log("\(method) \(path) -> \(resp.status)")
        write(cfd, OIDCHTTPServer.render(resp, head: method == "HEAD"))
    }

    private func write(_ cfd: Int32, _ data: Data) { try? Framing.writeAll(fd: cfd, data) }

    static func render(_ r: Response, head: Bool) -> Data {
        let reason: String
        switch r.status {
        case 200: reason = "OK"
        case 400: reason = "Bad Request"
        case 404: reason = "Not Found"
        case 405: reason = "Method Not Allowed"
        case 500: reason = "Internal Server Error"
        default: reason = "Status"
        }
        var head_ = "HTTP/1.1 \(r.status) \(reason)\r\n"
        head_ += "Content-Type: \(r.contentType)\r\n"
        head_ += "Content-Length: \(r.body.count)\r\n"
        head_ += "Cache-Control: max-age=300\r\n"
        head_ += "Access-Control-Allow-Origin: *\r\n"
        head_ += "Connection: close\r\n"
        head_ += "Server: safeski\r\n\r\n"
        var out = Data(head_.utf8)
        if !head { out.append(r.body) }
        return out
    }

    /// The standard route table for an issuer: discovery, JWKS (both paths), a root index, healthz.
    public static func routes(issuer: @escaping () throws -> OIDCIssuer) -> Handler {
        return { path in
            do {
                switch path {
                case OIDCDiscovery.configurationPath: return .json(try issuer().discovery())
                case OIDCDiscovery.jwksPath, OIDCDiscovery.jwksAltPath: return .json(try issuer().jwks())
                case "/healthz": return .text(200, "ok")
                case "/":
                    let iss = (try? issuer().config.requireIssuer()) ?? "(issuer not configured)"
                    return .text(200, "safeski OIDC provider\nissuer: \(iss)\n\(OIDCDiscovery.configurationPath)\n\(OIDCDiscovery.jwksPath)")
                default: return .text(404, "not found")
                }
            } catch {
                return .text(500, (error as? SafeskiError)?.errorDescription ?? error.localizedDescription)
            }
        }
    }
}
