import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

@Suite("Audit log", .enclaveSerialized)
struct AuditTests {
    struct Verified: Equatable { var count: Int; var broken: Int? }
    private func verified(_ url: URL) throws -> Verified {
        let r = try AuditLog.verify(url: url)
        return Verified(count: r.count, broken: r.broken)
    }
    private func lines(_ url: URL) throws -> [String] {
        String(decoding: try Data(contentsOf: url), as: UTF8.self).split(separator: "\n").map(String.init)
    }
    private func writeLines(_ l: [String], to url: URL) throws {
        try Data((l.joined(separator: "\n") + "\n").utf8).write(to: url)
    }

    @Test func appendBuildsChain() throws {
        let home = try TempHome("audit")
        defer { home.cleanup() }
        let log = try AuditLog(url: home.paths.auditLog)
        #expect(log.head.seq == 0)
        #expect(log.head.hash == AuditLog.genesis)
        #expect(try verified(home.paths.auditLog) == Verified(count: 0, broken: nil))

        var caller = CallerIdentity.testUnix(path: "/usr/bin/ssh")
        caller.teamID = "TEAM"
        let e1 = try log.append(action: "one", resource: "r1", outcome: "allow", caller: caller, detail: ["k": .string("v"), "n": .number(3)])
        let e2 = try log.append(action: "two", outcome: "deny")
        let e3 = try log.append(action: "three", resource: "r3", outcome: "approved")

        #expect(e1.seq == 1 && e2.seq == 2 && e3.seq == 3)
        #expect(e1.prev == AuditLog.genesis)
        #expect(e2.prev == e1.hash)
        #expect(e3.prev == e2.hash)
        #expect(e1.hash.count == 64 && e2.hash.count == 64)
        #expect(e1.hash != e2.hash)
        #expect(try AuditEvent.computeHash(e1.unhashed) == e1.hash)
        #expect(log.head.seq == 3 && log.head.hash == e3.hash)
        #expect(try posixMode(home.paths.auditLog) == 0o600)

        let all = try AuditLog.readAll(url: home.paths.auditLog)
        #expect(all.count == 3)
        #expect(all[0].caller?.path == "/usr/bin/ssh")
        #expect(all[0].caller?.teamID == "TEAM")
        #expect(all[0].detail?["k"] == .string("v"))
        #expect(all[0].detail?["n"] == .number(3))
        #expect(all[0].resource == "r1" && all[1].resource == nil)
        #expect(all.map(\.hash) == [e1.hash, e2.hash, e3.hash])
        #expect(try log.tail(2).map(\.seq) == [2, 3])
        #expect(try log.tail(10).count == 3)
        #expect(try verified(home.paths.auditLog) == Verified(count: 3, broken: nil))
    }

    @Test func tamperedMiddleLineIsDetected() throws {
        let home = try TempHome("audit-tamper")
        defer { home.cleanup() }
        let log = try AuditLog(url: home.paths.auditLog)
        for a in ["one", "two", "three", "four"] { try log.append(action: a, outcome: "allow") }
        #expect(try verified(home.paths.auditLog) == Verified(count: 4, broken: nil))

        var l = try lines(home.paths.auditLog)
        #expect(l[1].contains("\"action\":\"two\""))
        l[1] = l[1].replacingOccurrences(of: "\"action\":\"two\"", with: "\"action\":\"TWO\"")
        try writeLines(l, to: home.paths.auditLog)
        #expect(try verified(home.paths.auditLog) == Verified(count: 4, broken: 2))

        // a consistent rewrite of one line (hash fixed up) still breaks at the next link
        var evs = try AuditLog.readAll(url: home.paths.auditLog)
        evs[1].action = "forged"
        evs[1].hash = try AuditEvent.computeHash(evs[1].unhashed)
        let enc = JSONEncoder.safeskiCompact
        try writeLines(try evs.map { String(decoding: try enc.encode($0), as: UTF8.self) }, to: home.paths.auditLog)
        #expect(try verified(home.paths.auditLog) == Verified(count: 4, broken: 3))
    }

    @Test func deletedLineIsDetected() throws {
        let home = try TempHome("audit-del")
        defer { home.cleanup() }
        let log = try AuditLog(url: home.paths.auditLog)
        for a in ["one", "two", "three", "four"] { try log.append(action: a, outcome: "allow") }

        let original = try lines(home.paths.auditLog)
        var l = original
        l.remove(at: 1)
        try writeLines(l, to: home.paths.auditLog)
        let r = try AuditLog.verify(url: home.paths.auditLog)
        #expect(r.count == 3)
        #expect(r.broken == 3)   // seq 3 now follows seq 1

        // deleting the first line is detected at seq 2 (wrong seq, and its prev is not genesis)
        var l2 = original
        l2.remove(at: 0)
        try writeLines(l2, to: home.paths.auditLog)
        #expect(try AuditLog.verify(url: home.paths.auditLog).broken == 2)

        // truncating the tail is not detectable from the chain alone (that is what signHead is for)
        try writeLines(Array(original.prefix(2)), to: home.paths.auditLog)
        #expect(try verified(home.paths.auditLog) == Verified(count: 2, broken: nil))
    }

    @Test func reopenContinuesChain() throws {
        let home = try TempHome("audit-reopen")
        defer { home.cleanup() }
        let e3: AuditEvent
        do {
            let log = try AuditLog(url: home.paths.auditLog)
            try log.append(action: "one", outcome: "allow")
            try log.append(action: "two", outcome: "allow")
            e3 = try log.append(action: "three", outcome: "allow")
        }
        let log2 = try AuditLog(url: home.paths.auditLog)
        #expect(log2.head.seq == 3 && log2.head.hash == e3.hash)
        let e4 = try log2.append(action: "four", outcome: "allow")
        #expect(e4.seq == 4)
        #expect(e4.prev == e3.hash)
        #expect(try verified(home.paths.auditLog) == Verified(count: 4, broken: nil))
        #expect(try AuditLog.readAll(url: home.paths.auditLog).map(\.action) == ["one", "two", "three", "four"])
    }

    @Test func signHeadVerifiesWithIdentityKey() throws {
        let home = try TempHome("audit-sign")
        defer { home.cleanup() }
        let log = try AuditLog(url: home.paths.auditLog)
        try log.append(action: "one", outcome: "allow")
        let last = try log.append(action: "two", outcome: "allow")

        let identity = try EnclaveSigningKey(create: .none)
        let sigURL = home.paths.auditDir.appendingPathComponent("head.sig.json")
        let rec = try log.signHead(with: identity, deviceID: "dev1", to: sigURL)
        #expect(rec.seq == 2 && rec.hash == last.hash && rec.deviceID == "dev1")
        #expect(rec.signature.count == 64)
        #expect(try posixMode(sigURL) == 0o600)

        let msg = AuditLog.headMessage(seq: rec.seq, hash: rec.hash)
        #expect(msg == Data("safeski-audit-head:2:\(last.hash)".utf8))
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: rec.signature)
        #expect(identity.publicKey.isValidSignature(sig, for: msg))
        #expect(!identity.publicKey.isValidSignature(sig, for: AuditLog.headMessage(seq: 1, hash: rec.hash)))
        #expect(!P256.Signing.PrivateKey().publicKey.isValidSignature(sig, for: msg))

        let onDisk = try JSONDecoder.safeski.decode(AuditHeadSignature.self, from: Data(contentsOf: sigURL))
        #expect(onDisk.seq == rec.seq && onDisk.hash == rec.hash && onDisk.signature == rec.signature)
    }
}
