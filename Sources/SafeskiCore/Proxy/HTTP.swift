import Foundation
import Darwin

/// A parsed HTTP/1.1 request.
public struct HTTPRequest: Equatable {
    public var method: String
    /// Request target as sent (origin form), e.g. "/s/tok/route/v1/messages?x=1".
    public var target: String
    public var version: String
    public var headers: [(name: String, value: String)]
    public var body: Data

    public init(method: String, target: String, version: String = "HTTP/1.1", headers: [(name: String, value: String)] = [], body: Data = Data()) {
        self.method = method; self.target = target; self.version = version; self.headers = headers; self.body = body
    }

    public static func == (a: HTTPRequest, b: HTTPRequest) -> Bool {
        a.method == b.method && a.target == b.target && a.version == b.version && a.body == b.body
            && a.headers.map { "\($0.name):\($0.value)" } == b.headers.map { "\($0.name):\($0.value)" }
    }

    public var path: String {
        if let q = target.firstIndex(of: "?") { return String(target[..<q]) }
        return target
    }
    public var query: String? {
        guard let q = target.firstIndex(of: "?") else { return nil }
        return String(target[target.index(after: q)...])
    }

    /// First value of a header (case-insensitive name).
    public func header(_ name: String) -> String? {
        let n = name.lowercased()
        return headers.first { $0.name.lowercased() == n }?.value
    }

    public static func isValidHeaderName(_ n: String) -> Bool {
        guard !n.isEmpty else { return false }
        return n.utf8.allSatisfy { c in
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
                || "!#$%&'*+-.^_`|~".utf8.contains(c)
        }
    }

    /// Request headers that are never forwarded (hop-by-hop, plus ones the upstream client sets itself).
    public static let hopByHop: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "expect",
    ]
}

public enum HTTPError: Error, LocalizedError, Equatable {
    case malformed(String)
    case tooLarge(String)
    case timeout
    public var errorDescription: String? {
        switch self {
        case .malformed(let s): return "malformed request: \(s)"
        case .tooLarge(let s): return "request too large: \(s)"
        case .timeout: return "request timed out"
        }
    }
    public var status: Int {
        switch self {
        case .malformed: return 400
        case .tooLarge: return 413
        case .timeout: return 408
        }
    }
}

/// Incremental HTTP/1.1 request reader over any byte source. The source closure returns the next
/// chunk of bytes, an empty Data at EOF, or throws.
public final class HTTPRequestReader {
    public var maxHeaderBytes = 64 * 1024
    public var maxBodyBytes = 64 * 1024 * 1024
    private let source: () throws -> Data
    private var buffer = Data()
    private var eof = false

    public init(source: @escaping () throws -> Data) { self.source = source }

    /// Convenience: parse one request from a complete byte buffer.
    public static func parse(_ data: Data, maxBody: Int = 64 * 1024 * 1024) throws -> HTTPRequest {
        var d = data
        let r = HTTPRequestReader {
            let out = d; d = Data(); return out
        }
        r.maxBodyBytes = maxBody
        guard let req = try r.readRequest() else { throw HTTPError.malformed("empty request") }
        return req
    }

    private func fill() throws -> Bool {
        if eof { return false }
        let chunk = try source()
        if chunk.isEmpty { eof = true; return false }
        buffer.append(chunk)
        return true
    }

    /// Reads the head of a request (request line + headers). Returns nil at clean EOF before any bytes.
    /// The body is not yet read; call `readBody(for:)` (or `readRequest`) next.
    public func readHead() throws -> HTTPRequest? {
        let sep = Data("\r\n\r\n".utf8)
        var searchFrom = 0
        while true {
            if let r = buffer.range(of: sep, in: searchFrom..<buffer.count) {
                let head = buffer.subdata(in: 0..<r.lowerBound)
                buffer.removeSubrange(0..<r.upperBound)
                return try HTTPRequestReader.parseHead(head)
            }
            guard buffer.count <= maxHeaderBytes else { throw HTTPError.tooLarge("headers exceed \(maxHeaderBytes) bytes") }
            searchFrom = max(0, buffer.count - 3)
            guard try fill() else {
                if buffer.isEmpty { return nil }
                // Tolerate bare "\n\n" separators from sloppy clients.
                if let r = buffer.range(of: Data("\n\n".utf8)) {
                    let head = buffer.subdata(in: 0..<r.lowerBound)
                    buffer.removeSubrange(0..<r.upperBound)
                    return try HTTPRequestReader.parseHead(head)
                }
                throw HTTPError.malformed("connection closed before end of headers")
            }
        }
    }

    public func readRequest() throws -> HTTPRequest? {
        guard var req = try readHead() else { return nil }
        req.body = try readBody(for: req)
        return req
    }

    /// Whether the request carries a body that `readBody` will consume.
    public static func hasBody(_ req: HTTPRequest) -> Bool {
        if let te = req.header("transfer-encoding"), te.lowercased().contains("chunked") { return true }
        if let cl = req.header("content-length"), let n = Int(cl), n > 0 { return true }
        return false
    }

    public func readBody(for req: HTTPRequest) throws -> Data {
        if let te = req.header("transfer-encoding") {
            let codings = te.lowercased().split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            guard codings == ["chunked"] else { throw HTTPError.malformed("unsupported transfer-encoding '\(te)'") }
            return try readChunked()
        }
        if let cl = req.header("content-length") {
            guard let n = Int(cl.trimmingCharacters(in: .whitespaces)), n >= 0 else { throw HTTPError.malformed("bad content-length") }
            guard n <= maxBodyBytes else { throw HTTPError.tooLarge("body exceeds \(maxBodyBytes) bytes") }
            return try readExactly(n)
        }
        return Data()
    }

    private func readExactly(_ n: Int) throws -> Data {
        while buffer.count < n {
            guard try fill() else { throw HTTPError.malformed("connection closed before end of body") }
        }
        let out = buffer.prefix(n)
        buffer.removeSubrange(0..<n)
        return Data(out)
    }

    private func readLine() throws -> String {
        while true {
            if let r = buffer.range(of: Data("\r\n".utf8)) {
                let line = String(decoding: buffer[0..<r.lowerBound], as: UTF8.self)
                buffer.removeSubrange(0..<r.upperBound)
                return line
            }
            guard buffer.count <= maxHeaderBytes else { throw HTTPError.tooLarge("chunk line too long") }
            guard try fill() else { throw HTTPError.malformed("connection closed inside chunked body") }
        }
    }

    private func readChunked() throws -> Data {
        var out = Data()
        while true {
            let line = try readLine()
            let sizeText = line.split(separator: ";", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            guard let size = Int(sizeText, radix: 16) else { throw HTTPError.malformed("bad chunk size '\(line)'") }
            if size == 0 {
                // trailers until blank line
                while true {
                    let t = try readLine()
                    if t.isEmpty { break }
                }
                return out
            }
            guard out.count + size <= maxBodyBytes else { throw HTTPError.tooLarge("body exceeds \(maxBodyBytes) bytes") }
            out.append(try readExactly(size))
            let crlf = try readExactly(2)
            guard crlf == Data("\r\n".utf8) else { throw HTTPError.malformed("missing CRLF after chunk") }
        }
    }

    static func parseHead(_ head: Data) throws -> HTTPRequest {
        guard let text = String(data: head, encoding: .utf8) ?? String(data: head, encoding: .isoLatin1) else {
            throw HTTPError.malformed("non-text headers")
        }
        var lines = text.components(separatedBy: "\r\n")
        if lines.count == 1 { lines = text.components(separatedBy: "\n") }
        // Tolerate leading blank lines (RFC 7230 §3.5).
        while let f = lines.first, f.isEmpty { lines.removeFirst() }
        guard let requestLine = lines.first else { throw HTTPError.malformed("empty request") }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count == 3 else { throw HTTPError.malformed("bad request line") }
        let method = parts[0], target = parts[1], version = parts[2]
        guard !method.isEmpty, method.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }), method.count <= 20 else { throw HTTPError.malformed("bad method") }
        guard target.hasPrefix("/") || target == "*" else { throw HTTPError.malformed("only origin-form request targets are supported") }
        guard version == "HTTP/1.1" || version == "HTTP/1.0" else { throw HTTPError.malformed("unsupported version '\(version)'") }
        var headers: [(String, String)] = []
        for raw in lines.dropFirst() {
            if raw.isEmpty { continue }
            if raw.first == " " || raw.first == "\t" {
                // obs-fold continuation
                guard !headers.isEmpty else { throw HTTPError.malformed("header continuation without header") }
                headers[headers.count - 1].1 += " " + raw.trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = raw.firstIndex(of: ":") else { throw HTTPError.malformed("bad header line") }
            let name = String(raw[..<colon])
            guard HTTPRequest.isValidHeaderName(name) else { throw HTTPError.malformed("bad header name") }
            let value = raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !value.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\0" }) else { throw HTTPError.malformed("bad header value") }
            headers.append((name, value))
        }
        return HTTPRequest(method: method.uppercased(), target: target, version: version, headers: headers)
    }
}

/// Builds HTTP/1.1 response bytes.
public enum HTTPResponseWriter {
    public static func reason(_ status: Int) -> String {
        switch status {
        case 100: return "Continue"
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 204: return "No Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 304: return "Not Modified"
        case 307: return "Temporary Redirect"
        case 308: return "Permanent Redirect"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 413: return "Payload Too Large"
        case 429: return "Too Many Requests"
        case 500: return "Internal Server Error"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default: return "Status"
        }
    }

    /// Serialize a status line plus headers (caller supplies framing headers).
    public static func head(status: Int, headers: [(String, String)]) -> Data {
        var s = "HTTP/1.1 \(status) \(reason(status))\r\n"
        for (k, v) in headers { s += "\(k): \(sanitize(v))\r\n" }
        s += "\r\n"
        return Data(s.utf8)
    }

    /// A complete JSON response with Content-Length and Connection: close.
    public static func json(status: Int, _ body: [String: JSONValue], extraHeaders: [(String, String)] = []) -> Data {
        let b = (try? JSONEncoder.safeskiCompact.encode(JSONValue.object(body))) ?? Data("{}".utf8)
        var h: [(String, String)] = [("Content-Type", "application/json"), ("Content-Length", String(b.count)), ("Connection", "close")]
        h.append(contentsOf: extraHeaders)
        return head(status: status, headers: h) + b
    }

    public static func chunk(_ data: Data) -> Data {
        var out = Data(String(data.count, radix: 16).utf8)
        out.append(contentsOf: [0x0d, 0x0a])
        out.append(data)
        out.append(contentsOf: [0x0d, 0x0a])
        return out
    }
    public static let lastChunk = Data("0\r\n\r\n".utf8)

    static func sanitize(_ v: String) -> String {
        v.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
    }
}
