import CryptoKit
import Foundation

/// Append-only, hash-chained JSONL audit log. Each entry commits to the previous entry's hash.
/// `safeski audit verify` recomputes the chain; the agent periodically signs the head with the
/// device identity key (see `AuditLog.signHead`).
public struct AuditEvent: Codable, Equatable {
    public var seq: Int
    public var time: Date
    public var action: String            // e.g. "key.sign", "secret.get", "proxy.request"
    public var resource: String?         // key/secret/route name
    public var outcome: String           // "allow" | "deny" | "error" | "approved"
    public var caller: CallerIdentity?
    public var detail: [String: JSONValue]?
    public var prev: String              // hex sha256 of previous line ("0"*64 for genesis)
    public var hash: String              // hex sha256 over canonical(entry without `hash`)

    struct Unhashed: Codable {
        var seq: Int; var time: Date; var action: String; var resource: String?; var outcome: String
        var caller: CallerIdentity?; var detail: [String: JSONValue]?; var prev: String
    }

    var unhashed: Unhashed {
        Unhashed(seq: seq, time: time, action: action, resource: resource, outcome: outcome, caller: caller, detail: detail, prev: prev)
    }

    static func computeHash(_ u: Unhashed) throws -> String {
        let data = try JSONEncoder.safeskiCompact.encode(u)
        return Data(SHA256.hash(data: data)).hexString
    }
}

public struct AuditHeadSignature: Codable {
    public var seq: Int
    public var hash: String
    public var deviceID: String
    public var time: Date
    public var signature: Data   // raw r||s over "safeski-audit-head:\(seq):\(hash)"
}

public final class AuditLog {
    public let url: URL
    private let lock = NSLock()
    private var lastSeq: Int
    private var lastHash: String

    public static let genesis = String(repeating: "0", count: 64)

    public init(url: URL) throws {
        self.url = url
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        if let last = try AuditLog.readAll(url: url).last {
            lastSeq = last.seq; lastHash = last.hash
        } else {
            lastSeq = 0; lastHash = AuditLog.genesis
        }
    }

    @discardableResult
    public func append(action: String, resource: String? = nil, outcome: String, caller: CallerIdentity? = nil,
                       detail: [String: JSONValue]? = nil) throws -> AuditEvent {
        lock.lock(); defer { lock.unlock() }
        let seq = lastSeq + 1
        let u = AuditEvent.Unhashed(seq: seq, time: Date(), action: action, resource: resource, outcome: outcome,
                                    caller: caller, detail: detail, prev: lastHash)
        let hash = try AuditEvent.computeHash(u)
        let ev = AuditEvent(seq: seq, time: u.time, action: action, resource: resource, outcome: outcome,
                            caller: caller, detail: detail, prev: lastHash, hash: hash)
        var line = try JSONEncoder.safeskiCompact.encode(ev)
        line.append(0x0a)
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let fh = try? FileHandle(forWritingTo: url) else { throw SafeskiError.io("open audit log") }
        defer { try? fh.close() }
        try fh.seekToEnd()
        try fh.write(contentsOf: line)
        lastSeq = seq; lastHash = hash
        return ev
    }

    public var head: (seq: Int, hash: String) { lock.lock(); defer { lock.unlock() }; return (lastSeq, lastHash) }

    public static func readAll(url: URL) throws -> [AuditEvent] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        let data = try FileIO.read(url)
        let dec = JSONDecoder.safeski
        var out: [AuditEvent] = []
        for line in data.split(separator: 0x0a) where !line.isEmpty {
            out.append(try dec.decode(AuditEvent.self, from: line))
        }
        return out
    }

    public func tail(_ n: Int) throws -> [AuditEvent] {
        let all = try AuditLog.readAll(url: url)
        return Array(all.suffix(n))
    }

    /// Verify the chain. Returns (entries, firstBrokenSeq?).
    public static func verify(url: URL) throws -> (count: Int, broken: Int?) {
        let all = try readAll(url: url)
        var prev = genesis
        var expectedSeq = 1
        for ev in all {
            if ev.seq != expectedSeq || ev.prev != prev { return (all.count, ev.seq) }
            let h = try AuditEvent.computeHash(ev.unhashed)
            if h != ev.hash { return (all.count, ev.seq) }
            prev = ev.hash; expectedSeq += 1
        }
        return (all.count, nil)
    }

    public static func headMessage(seq: Int, hash: String) -> Data {
        Data("safeski-audit-head:\(seq):\(hash)".utf8)
    }

    public func signHead(with key: EnclaveSigningKey, deviceID: String, to url: URL) throws -> AuditHeadSignature {
        let (seq, hash) = head
        let sig = try key.sign(AuditLog.headMessage(seq: seq, hash: hash))
        let rec = AuditHeadSignature(seq: seq, hash: hash, deviceID: deviceID, time: Date(), signature: sig)
        try FileIO.writePrivate(try JSONEncoder.safeski.encode(rec), to: url)
        return rec
    }
}
