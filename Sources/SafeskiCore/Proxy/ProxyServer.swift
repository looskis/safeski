import Foundation
import Darwin

/// Minimal TCP listener: accept loop on a background thread, one handler invocation per connection
/// on a concurrent queue. Mirrors `UnixSocketServer`.
public final class TCPListener {
    public let host: String
    public let port: UInt16
    private var fd: Int32 = -1
    private var running = false
    private let queue: DispatchQueue
    private let handler: (Int32) -> Void
    /// The port actually bound (useful when `port` was 0).
    public private(set) var boundPort: UInt16 = 0

    public init(host: String, port: UInt16, label: String, handler: @escaping (Int32) -> Void) {
        self.host = host; self.port = port; self.handler = handler
        self.queue = DispatchQueue(label: "safeski.\(label)", attributes: .concurrent)
    }

    public func start() throws {
        let v6 = host.contains(":")
        fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SafeskiError.io("socket: \(String(cString: strerror(errno)))") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let bindResult: Int32
        if v6 {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            guard inet_pton(AF_INET6, host, &addr.sin6_addr) == 1 else { close(fd); fd = -1; throw SafeskiError.io("bad listen address \(host)") }
            bindResult = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        } else {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else { close(fd); fd = -1; throw SafeskiError.io("bad listen address \(host)") }
            bindResult = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        }
        guard bindResult == 0 else {
            let e = errno; close(fd); fd = -1
            throw SafeskiError.io("bind \(host):\(port): \(String(cString: strerror(e)))")
        }
        guard listen(fd, 128) == 0 else {
            let e = errno; close(fd); fd = -1
            throw SafeskiError.io("listen: \(String(cString: strerror(e)))")
        }
        // Discover the bound port.
        var sa = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        withUnsafeMutablePointer(to: &sa) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                if getsockname(fd, sp, &len) == 0 {
                    if v6 { sp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { boundPort = UInt16(bigEndian: $0.pointee.sin6_port) } }
                    else { sp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { boundPort = UInt16(bigEndian: $0.pointee.sin_port) } }
                }
            }
        }
        running = true
        let lfd = fd
        Thread.detachNewThread { [weak self] in
            while let self, self.running {
                let cfd = accept(lfd, nil, nil)
                if cfd < 0 { if errno == EINTR { continue }; break }
                var one: Int32 = 1
                setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
                setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
                self.queue.async {
                    self.handler(cfd)
                    close(cfd)
                }
            }
        }
    }

    public func stop() {
        running = false
        if fd >= 0 { close(fd); fd = -1 }
    }
}

/// The secretless proxy HTTP server. Owns no state of its own beyond the listener; configuration,
/// sessions, policy and audit come from the `ProxyModule`.
public final class ProxyServer {
    unowned let module: ProxyModule
    private var listener: TCPListener?
    public var readTimeout: TimeInterval = 30
    public var writeTimeout: TimeInterval = 120
    public var upstreamIdleTimeout: TimeInterval = 300
    public var upstreamTotalTimeout: TimeInterval = 3600

    init(module: ProxyModule) { self.module = module }

    public var boundPort: UInt16 { listener?.boundPort ?? 0 }

    func start(host: String, port: UInt16) throws {
        let l = TCPListener(host: host, port: port, label: "proxy") { [weak self] fd in
            self?.handleConnection(fd: fd)
        }
        try l.start()
        listener = l
    }

    func stop() { listener?.stop(); listener = nil }

    // MARK: connection handling

    private func handleConnection(fd: Int32) {
        var tv = timeval(tv_sec: Int(readTimeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var wtv = timeval(tv_sec: Int(writeTimeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &wtv, socklen_t(MemoryLayout<timeval>.size))
        let reader = HTTPRequestReader { try ProxyServer.readChunk(fd: fd) }
        do {
            guard let head = try reader.readHead() else { return }
            if head.header("expect")?.lowercased() == "100-continue", HTTPRequestReader.hasBody(head) {
                try Framing.writeAll(fd: fd, Data("HTTP/1.1 100 Continue\r\n\r\n".utf8))
            }
            var req = head
            req.body = try reader.readBody(for: head)
            handleRequest(req, fd: fd)
        } catch let e as HTTPError {
            module.log("proxy: \(e.localizedDescription)")
            try? Framing.writeAll(fd: fd, HTTPResponseWriter.json(status: e.status, ["error": .string("bad_request"), "message": .string(e.localizedDescription)]))
        } catch {
            module.log("proxy: connection error: \(error.localizedDescription)")
            try? Framing.writeAll(fd: fd, HTTPResponseWriter.json(status: 500, ["error": .string("internal"), "message": .string("internal error")]))
        }
        shutdown(fd, SHUT_WR)
    }

    static func readChunk(fd: Int32) throws -> Data {
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n > 0 { return Data(buf[0..<n]) }
            if n == 0 { return Data() }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK { throw HTTPError.timeout }
            throw SafeskiError.io("read: \(String(cString: strerror(errno)))")
        }
    }

    // MARK: request pipeline

    private struct Resolved {
        var route: ProxyRoute
        var session: ProxySession
        var path: String
        var query: String?
    }

    private func reply(_ fd: Int32, _ status: Int, _ error: String, _ message: String, extra: [(String, String)] = []) {
        try? Framing.writeAll(fd: fd, HTTPResponseWriter.json(status: status, ["error": .string(error), "message": .string(message)], extraHeaders: extra))
    }

    private func deny(_ fd: Int32, status: Int, error: String, message: String, route: String?, req: HTTPRequest, path: String,
                      session: ProxySession?, extra: [(String, String)] = []) {
        var d: [String: JSONValue] = ["method": .string(req.method), "path": .string(path), "status": .number(Double(status)), "reason": .string(message)]
        if let s = session { d["session"] = .string(s.id); if let l = s.label { d["label"] = .string(l) } }
        _ = try? module.service.audit.append(action: "proxy.request", resource: route ?? "-", outcome: "deny", caller: session?.caller, detail: d)
        reply(fd, status, error, message, extra: extra)
    }

    private func handleRequest(_ req: HTTPRequest, fd: Int32) {
        let config = module.currentConfig()
        let fullPath = req.path
        guard fullPath.hasPrefix("/") else { reply(fd, 400, "bad_request", "bad path"); return }
        let segments = fullPath.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
        guard segments.contains(where: { $0 == ".." }) == false else { reply(fd, 400, "bad_request", "path traversal"); return }
        let kind = segments.first.map(String.init) ?? ""

        let session: ProxySession
        let routeName: String
        let rest: String
        switch kind {
        case "s":
            guard segments.count >= 3, !segments[1].isEmpty else {
                reply(fd, 404, "not_found", "expected /s/<session>/<route>/<path>"); return
            }
            guard let s = module.sessions.lookup(token: String(segments[1])) else {
                deny(fd, status: 403, error: "invalid_session", message: "unknown or expired proxy session", route: nil, req: req, path: fullPath, session: nil)
                return
            }
            session = s
            routeName = String(segments[2])
            rest = segments.count > 3 ? "/" + segments[3...].joined(separator: "/") : "/"
        case "r":
            guard config.allowUnsessioned else {
                deny(fd, status: 403, error: "session_required", message: "unsessioned requests are disabled (proxy.allow_unsessioned = false)", route: nil, req: req, path: fullPath, session: nil)
                return
            }
            guard segments.count >= 2, !segments[1].isEmpty else { reply(fd, 404, "not_found", "expected /r/<route>/<path>"); return }
            session = module.anonymousSession
            routeName = String(segments[1])
            rest = segments.count > 2 ? "/" + segments[2...].joined(separator: "/") : "/"
        case "":
            reply(fd, 404, "not_found", "safeski proxy: use /s/<session>/<route>/<path>"); return
        default:
            reply(fd, 404, "not_found", "unknown prefix '/\(kind)'; use /s/<session>/<route>/<path>"); return
        }

        guard let route = config.routes[routeName] else {
            deny(fd, status: 404, error: "unknown_route", message: "unknown route '\(routeName)'", route: routeName, req: req, path: rest, session: session)
            return
        }
        guard session.allows(route: routeName) else {
            deny(fd, status: 403, error: "route_not_in_session", message: "session does not include route '\(routeName)'", route: routeName, req: req, path: rest, session: session)
            return
        }
        let r = Resolved(route: route, session: session, path: rest, query: req.query)
        let caller = session.caller

        // Policy: first matching rule, approval through the broker.
        if module.service.policy.defaults.requireValidSignature, caller.transport == "unix", caller.signatureValid != true {
            deny(fd, status: 403, error: "policy_denied", message: "caller code signature is invalid or unverifiable", route: routeName, req: req, path: rest, session: session)
            return
        }
        guard let rule = route.rule(for: req.method, path: rest, caller: caller) else {
            deny(fd, status: 403, error: "policy_denied", message: "no rule allows \(req.method) \(rest) on route '\(routeName)'", route: routeName, req: req, path: rest, session: session)
            return
        }
        let resource = "\(routeName) \(req.method) \(rest)"
        let ttl = rule.ttl ?? module.service.policy.defaults.ttl
        let decision: Decision
        switch rule.approve {
        case .never: decision = Decision(verdict: .allow, rule: rule.caller, ttl: ttl)
        case .deny: decision = Decision(verdict: .deny("rule denies \(req.method) \(rest) on route '\(routeName)'"), rule: rule.caller, ttl: ttl)
        default: decision = Decision(verdict: .approve(rule.approve), rule: rule.caller, ttl: ttl)
        }
        let via: String
        do {
            via = try module.service.approvals.authorize(decision: decision, caller: caller, kind: "route", resource: resource,
                                                         purpose: session.label.map { "proxy session \($0)" } ?? "proxy")
        } catch {
            let msg = (error as? SafeskiError)?.message ?? error.localizedDescription
            deny(fd, status: 403, error: "policy_denied", message: msg, route: routeName, req: req, path: rest, session: session)
            return
        }

        // Budget.
        if let wait = module.sessions.consumeBudget(session, route: routeName, budget: route.budget) {
            let secs = Int(wait.rounded(.up))
            deny(fd, status: 429, error: "budget_exceeded",
                 message: "route '\(routeName)' budget of \(route.budget?.requests ?? 0) requests per \(Int(route.budget?.per ?? 0))s exceeded; retry in \(secs)s",
                 route: routeName, req: req, path: rest, session: session, extra: [("Retry-After", String(secs))])
            return
        }

        // Credentials.
        var injected: [(String, String)] = []
        do {
            for h in route.headers {
                let v = try ProxyRoute.substitute(h.value) { name in
                    if let c = module.sessions.cachedSecret(session, name) { return c }
                    let sv = try module.service.getSecret(name, purpose: "proxy:\(routeName)", caller: caller)
                    let str = String(decoding: sv.value, as: UTF8.self)
                    module.sessions.cacheSecret(session, name, str)
                    return str
                }
                injected.append((h.name, v))
            }
        } catch {
            let msg = (error as? SafeskiError)?.message ?? error.localizedDescription
            deny(fd, status: 403, error: "credential_unavailable", message: "credential for route '\(routeName)' unavailable: \(msg)", route: routeName, req: req, path: rest, session: session)
            return
        }

        forward(r, req: req, injected: injected, via: via, fd: fd)
    }

    // MARK: upstream

    private func forward(_ r: Resolved, req: HTTPRequest, injected: [(String, String)], via: String, fd: Int32) {
        var urlString = r.route.upstream + r.path
        if let q = r.query { urlString += "?" + q }
        guard let url = URL(string: urlString) else {
            deny(fd, status: 400, error: "bad_request", message: "cannot build upstream URL", route: r.route.name, req: req, path: r.path, session: r.session)
            return
        }
        var ureq = URLRequest(url: url)
        ureq.httpMethod = req.method
        ureq.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        ureq.timeoutInterval = upstreamIdleTimeout
        let injectedNames = Set(injected.map { $0.0.lowercased() })
        let stripped = Set(r.route.strip)
        for h in req.headers {
            let n = h.name.lowercased()
            if HTTPRequest.hopByHop.contains(n) || stripped.contains(n) || injectedNames.contains(n) { continue }
            // Let URLSession negotiate and transparently decode content encoding.
            if n == "accept-encoding" { continue }
            ureq.addValue(h.value, forHTTPHeaderField: h.name)
        }
        for (n, v) in injected { ureq.setValue(v, forHTTPHeaderField: n) }
        if !req.body.isEmpty { ureq.httpBody = req.body }

        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        cfg.urlCache = nil
        cfg.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        cfg.timeoutIntervalForRequest = upstreamIdleTimeout
        cfg.timeoutIntervalForResource = upstreamTotalTimeout
        cfg.httpMaximumConnectionsPerHost = 4

        let relay = UpstreamRelay(fd: fd, method: req.method)
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: cfg, delegate: relay, delegateQueue: queue)
        let started = Date()
        let task = session.dataTask(with: ureq)
        task.resume()
        relay.done.wait()
        session.finishTasksAndInvalidate()
        let ms = Int(Date().timeIntervalSince(started) * 1000)

        var detail: [String: JSONValue] = [
            "method": .string(req.method), "path": .string(r.path), "status": .number(Double(relay.status)),
            "bytes": .number(Double(relay.bytes)), "ms": .number(Double(ms)), "via": .string(via), "session": .string(r.session.id),
        ]
        if let l = r.session.label { detail["label"] = .string(l) }
        if let e = relay.failure { detail["error"] = .string(e) }
        let outcome = relay.failure != nil && relay.status == 0 ? "error" : (via == "approved" ? "approved" : "allow")
        _ = try? module.service.audit.append(action: "proxy.request", resource: r.route.name, outcome: outcome, caller: r.session.caller, detail: detail)
    }
}

/// Streams an upstream response to the client socket as it arrives.
final class UpstreamRelay: NSObject, URLSessionDataDelegate {
    let fd: Int32
    let method: String
    let done = DispatchSemaphore(value: 0)
    private(set) var status = 0
    private(set) var bytes = 0
    private(set) var failure: String?
    private var headWritten = false
    private var chunked = false
    private var hasBody = true
    private var clientGone = false

    static let dropResponseHeaders: Set<String> = [
        "connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding",
        "proxy-authenticate", "trailer", "upgrade",
    ]

    init(fd: Int32, method: String) { self.fd = fd; self.method = method }

    private func write(_ d: Data) {
        guard !clientGone else { return }
        do { try Framing.writeAll(fd: fd, d) } catch { clientGone = true }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // pass redirects through to the client
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let http = response as? HTTPURLResponse else { completionHandler(.cancel); return }
        status = http.statusCode
        var headers: [(String, String)] = []
        var contentLength: String?
        var encoded = false
        for (k, v) in http.allHeaderFields {
            guard let name = k as? String, let value = v as? String else { continue }
            let n = name.lowercased()
            if n == "content-length" { contentLength = value }
            if n == "content-encoding", value.lowercased() != "identity" { encoded = true }
            if UpstreamRelay.dropResponseHeaders.contains(n) { continue }
            headers.append((name, value))
        }
        hasBody = !(method == "HEAD" || status == 204 || status == 304 || (100..<200).contains(status))
        if hasBody {
            if let cl = contentLength, !encoded {
                headers.append(("Content-Length", cl)); chunked = false
            } else {
                headers.append(("Transfer-Encoding", "chunked")); chunked = true
            }
        } else if method == "HEAD", let cl = contentLength, !encoded {
            headers.append(("Content-Length", cl))
        }
        headers.append(("Connection", "close"))
        write(HTTPResponseWriter.head(status: status, headers: headers))
        headWritten = true
        if clientGone { completionHandler(.cancel) } else { completionHandler(.allow) }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard hasBody, !data.isEmpty else { return }
        bytes += data.count
        write(chunked ? HTTPResponseWriter.chunk(data) : data)
        if clientGone { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error {
            failure = clientGone ? "client disconnected" : error.localizedDescription
            if !headWritten {
                status = 502
                write(HTTPResponseWriter.json(status: 502, ["error": .string("upstream_failed"), "message": .string("upstream request failed: \(error.localizedDescription)")]))
                headWritten = true
            }
        } else if chunked {
            write(HTTPResponseWriter.lastChunk)
        }
        done.signal()
    }
}
