import Foundation

/// Filesystem layout for a safeski home. Override the root with SAFESKI_HOME.
public struct SafeskiPaths {
    public let root: URL

    public init(root: URL) { self.root = root }

    public static var `default`: SafeskiPaths {
        if let env = ProcessInfo.processInfo.environment["SAFESKI_HOME"], !env.isEmpty {
            return SafeskiPaths(root: URL(fileURLWithPath: (env as NSString).expandingTildeInPath))
        }
        return SafeskiPaths(root: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".safeski"))
    }

    public var device: URL { root.appendingPathComponent("device.json") }
    public var keys: URL { root.appendingPathComponent("keys") }
    public var secrets: URL { root.appendingPathComponent("secrets") }
    public var devices: URL { root.appendingPathComponent("devices") }
    public var policy: URL { root.appendingPathComponent("policy.toml") }
    public var auditDir: URL { root.appendingPathComponent("audit") }
    public var auditLog: URL { auditDir.appendingPathComponent("log.jsonl") }
    public var logs: URL { root.appendingPathComponent("logs") }
    public var sessions: URL { root.appendingPathComponent("sessions") }
    public var tls: URL { root.appendingPathComponent("tls") }

    /// Runtime (socket) directory. Kept short because sun_path is 104 bytes on macOS.
    public var runtime: URL {
        if let env = ProcessInfo.processInfo.environment["SAFESKI_RUNTIME_DIR"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        return root.appendingPathComponent("run")
    }
    public var agentSocket: URL { runtime.appendingPathComponent("agent.sock") }
    public var sshAgentSocket: URL { runtime.appendingPathComponent("ssh.sock") }
    public var brokerSocket: URL { URL(fileURLWithPath: "/var/run/safeski/broker.sock") }

    public func ensureLayout() throws {
        let fm = FileManager.default
        for dir in [root, keys, secrets, devices, auditDir, logs, sessions, runtime, tls] {
            try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        }
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    }
}

public enum FileIO {
    /// Atomic write with 0600 permissions.
    public static func writePrivate(_ data: Data, to url: URL) throws {
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).tmp-\(UUID().uuidString)")
        do {
            try data.write(to: tmp, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
            _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            throw SafeskiError.io("write \(url.path): \(error.localizedDescription)")
        }
    }

    public static func read(_ url: URL) throws -> Data {
        do { return try Data(contentsOf: url) }
        catch { throw SafeskiError.io("read \(url.path): \(error.localizedDescription)") }
    }

    public static func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }
}

public enum Names {
    /// Key and secret names: [A-Za-z0-9._-], 1..64 chars, no leading dot.
    public static func validate(_ name: String) throws {
        guard !name.isEmpty, name.count <= 64, !name.hasPrefix(".") else {
            throw SafeskiError.invalidFormat("name '\(name)' must be 1-64 chars and not start with '.'")
        }
        for c in name.unicodeScalars {
            let ok = (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "." || c == "_" || c == "-"
            guard ok else { throw SafeskiError.invalidFormat("name '\(name)' contains invalid character '\(c)'") }
        }
    }
}
