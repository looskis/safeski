import Foundation
import Security
import Darwin

/// Who is asking. Built from unix-socket peer credentials and the code-signing identity of the
/// peer process. For connections that cross a VM boundary (containers) peer credentials are
/// meaningless, so those callers authenticate with a session token instead.
public struct CallerIdentity: Codable, Equatable, CustomStringConvertible {
    public var uid: uid_t?
    public var gid: gid_t?
    public var pid: pid_t?
    /// Executable path of the peer process.
    public var path: String?
    /// Code-signing identifier (CFBundleIdentifier or binary name for ad-hoc).
    public var signingID: String?
    /// Apple Team ID if signed with a developer identity.
    public var teamID: String?
    /// Whether the signature validated (dynamic validity check).
    public var signatureValid: Bool?
    /// Best-effort argv of the peer (only readable for same-uid or root).
    public var commandLine: [String]?
    /// Parent process executable path (helps attribute node/python scripts to the agent that launched them).
    public var parentPath: String?
    /// Session token name, when the caller authenticated with a token (containers, remote).
    public var tokenName: String?
    /// Free-form transport label: "unix", "token", "local", "broker".
    public var transport: String

    public init(transport: String) { self.transport = transport }

    /// The CLI running as the current user, in-process (no socket).
    public static func local() -> CallerIdentity {
        var c = CallerIdentity(transport: "local")
        c.uid = getuid(); c.gid = getgid(); c.pid = getpid()
        c.path = ProcessInfo.processInfo.arguments.first.flatMap { CallerIdentity.resolvePath(pid: getpid()) ?? $0 }
        c.commandLine = ProcessInfo.processInfo.arguments
        return c
    }

    public var description: String {
        var parts: [String] = []
        if let p = path { parts.append(p) }
        if let t = teamID { parts.append("team=\(t)") }
        if let s = signingID { parts.append("id=\(s)") }
        if let u = uid { parts.append("uid=\(u)") }
        if let p = pid { parts.append("pid=\(p)") }
        if let t = tokenName { parts.append("token=\(t)") }
        return parts.isEmpty ? transport : parts.joined(separator: " ")
    }

    /// Short label for approval prompts.
    public var displayName: String {
        if let t = tokenName { return "token \(t)" }
        if let cmd = commandLine, let first = cmd.first {
            let base = (first as NSString).lastPathComponent
            // node /path/to/claude -> "claude (node)"
            if ["node", "python", "python3", "ruby", "bun", "deno"].contains(base), cmd.count > 1 {
                return "\((cmd[1] as NSString).lastPathComponent) (\(base))"
            }
            return base
        }
        if let p = path { return (p as NSString).lastPathComponent }
        return transport
    }

    // MARK: - Peer identification

    static let LOCAL_PEERCRED: Int32 = 0x001
    static let LOCAL_PEERPID: Int32 = 0x002
    static let LOCAL_PEERTOKEN: Int32 = 0x006

    /// Identify the peer on a connected AF_UNIX socket.
    public static func fromUnixSocket(fd: Int32) -> CallerIdentity {
        var c = CallerIdentity(transport: "unix")
        var cred = xucred()
        var len = socklen_t(MemoryLayout<xucred>.size)
        if getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &len) == 0 {
            c.uid = cred.cr_uid
            if cred.cr_ngroups > 0 { c.gid = cred.cr_groups.0 }
        }
        var pid: pid_t = 0
        var plen = socklen_t(MemoryLayout<pid_t>.size)
        if getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &plen) == 0, pid > 0 {
            c.pid = pid
        }
        var token = audit_token_t()
        var tlen = socklen_t(MemoryLayout<audit_token_t>.size)
        if getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tlen) == 0 {
            c.apply(codeSigningFor: token)
        }
        if let pid = c.pid {
            if c.path == nil { c.path = resolvePath(pid: pid) }
            c.commandLine = commandLine(pid: pid)
            if let ppid = parentPID(pid: pid), ppid > 1 { c.parentPath = resolvePath(pid: ppid) }
        }
        return c
    }

    mutating func apply(codeSigningFor token: audit_token_t) {
        var tok = token
        let tokenData = withUnsafeBytes(of: &tok) { Data($0) }
        let attrs: [CFString: Any] = [kSecGuestAttributeAudit: tokenData]
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs as CFDictionary, [], &code) == errSecSuccess, let code else { return }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return }
        var url: CFURL?
        if SecCodeCopyPath(staticCode, [], &url) == errSecSuccess, let u = url as URL? { path = u.path }
        var info: CFDictionary?
        if SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
           let d = info as? [String: Any] {
            signingID = d[kSecCodeInfoIdentifier as String] as? String
            teamID = d[kSecCodeInfoTeamIdentifier as String] as? String
        }
        signatureValid = SecCodeCheckValidity(code, [], nil) == errSecSuccess
    }

    public static func resolvePath(pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: Int(4 * MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        guard n > 0 else { return nil }
        return String(cString: buf)
    }

    public static func parentPID(pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return pid_t(info.pbi_ppid)
    }

    /// Read argv via sysctl KERN_PROCARGS2. Works for same-uid processes (or as root).
    public static func commandLine(pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0 else { return nil }
        guard size > 4 else { return nil }
        let argc = Int(buf[0]) | Int(buf[1]) << 8 | Int(buf[2]) << 16 | Int(buf[3]) << 24
        var i = 4
        // skip exec path
        while i < size, buf[i] != 0 { i += 1 }
        while i < size, buf[i] == 0 { i += 1 }
        var args: [String] = []
        while args.count < argc, i < size {
            let start = i
            while i < size, buf[i] != 0 { i += 1 }
            args.append(String(decoding: buf[start..<i], as: UTF8.self))
            i += 1
        }
        return args
    }
}
