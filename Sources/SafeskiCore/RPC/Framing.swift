import Foundation
import Darwin

/// Blocking length-prefixed framing over a file descriptor.
public enum Framing {
    public static let maxFrame = 16 * 1024 * 1024

    public static func readFrame(fd: Int32) throws -> Data? {
        guard let header = try readExact(fd: fd, count: 4) else { return nil }
        let n = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard n <= maxFrame else { throw SafeskiError.rpc("frame too large (\(n))") }
        // readExact returns a short buffer on EOF; a partial body is a truncated frame, not a frame.
        guard let body = try readExact(fd: fd, count: n), body.count == n else { throw SafeskiError.rpc("truncated frame") }
        return body
    }

    public static func writeFrame(fd: Int32, _ data: Data) throws {
        var header = Data(count: 4)
        let n = UInt32(data.count)
        header[0] = UInt8(n >> 24); header[1] = UInt8((n >> 16) & 0xff); header[2] = UInt8((n >> 8) & 0xff); header[3] = UInt8(n & 0xff)
        try writeAll(fd: fd, header + data)
    }

    public static func readExact(fd: Int32, count: Int) throws -> Data? {
        if count == 0 { return Data() }
        var buf = Data(count: count)
        var got = 0
        while got < count {
            let r = buf.withUnsafeMutableBytes { p -> Int in
                Darwin.read(fd, p.baseAddress!.advanced(by: got), count - got)
            }
            if r == 0 { return got == 0 ? nil : buf.prefix(got) }
            if r < 0 {
                if errno == EINTR { continue }
                throw SafeskiError.rpc("read: \(String(cString: strerror(errno)))")
            }
            got += r
        }
        return buf
    }

    public static func writeAll(fd: Int32, _ data: Data) throws {
        var off = 0
        while off < data.count {
            let r = data.withUnsafeBytes { p -> Int in
                Darwin.write(fd, p.baseAddress!.advanced(by: off), data.count - off)
            }
            if r < 0 {
                if errno == EINTR { continue }
                throw SafeskiError.rpc("write: \(String(cString: strerror(errno)))")
            }
            off += r
        }
    }
}

/// Minimal AF_UNIX server: accept loop on a background thread, one thread per connection.
public final class UnixSocketServer {
    public let path: String
    private var fd: Int32 = -1
    private let handler: (Int32, CallerIdentity) -> Void
    private var running = false
    private let queue: DispatchQueue

    public init(path: String, label: String, handler: @escaping (Int32, CallerIdentity) -> Void) {
        self.path = path; self.handler = handler
        self.queue = DispatchQueue(label: "safeski.\(label)", attributes: .concurrent)
    }

    public func start() throws {
        try UnixSocketServer.prepareSocketDir(path)
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SafeskiError.io("socket: \(String(cString: strerror(errno)))") }
        unlink(path)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard path.utf8.count <= maxLen else { throw SafeskiError.io("socket path too long (\(path.utf8.count) > \(maxLen)): \(path)") }
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: CChar.self, capacity: maxLen + 1) { cp in
                _ = path.withCString { strncpy(cp, $0, maxLen) }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, len) }
        }
        guard bindResult == 0 else { throw SafeskiError.io("bind \(path): \(String(cString: strerror(errno)))") }
        chmod(path, 0o600)
        guard listen(fd, 64) == 0 else { throw SafeskiError.io("listen: \(String(cString: strerror(errno)))") }
        running = true
        let lfd = fd
        Thread.detachNewThread { [weak self] in
            while let self, self.running {
                let cfd = accept(lfd, nil, nil)
                if cfd < 0 { if errno == EINTR { continue }; break }
                var one: Int32 = 1
                setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
                let ident = CallerIdentity.fromUnixSocket(fd: cfd)
                self.queue.async {
                    self.handler(cfd, ident)
                    close(cfd)
                }
            }
        }
    }

    public func stop() {
        running = false
        if fd >= 0 { close(fd); fd = -1 }
        unlink(path)
    }

    static func prepareSocketDir(_ path: String) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }

    /// Set the socket's mode (e.g. 0o666 for a broker socket shared across users).
    public func setMode(_ mode: mode_t) { chmod(path, mode) }
}

public enum UnixSocketClient {
    public static func connect(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SafeskiError.io("socket: \(String(cString: strerror(errno)))") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard path.utf8.count <= maxLen else { close(fd); throw SafeskiError.io("socket path too long: \(path)") }
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: CChar.self, capacity: maxLen + 1) { cp in
                _ = path.withCString { strncpy(cp, $0, maxLen) }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let r = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) }
        }
        guard r == 0 else { let e = errno; close(fd); throw SafeskiError.io("connect \(path): \(String(cString: strerror(e)))") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    public static func isListening(path: String) -> Bool {
        guard let fd = try? connect(path: path) else { return false }
        close(fd); return true
    }
}
