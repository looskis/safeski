import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

@Suite("SSH wire format")
struct SSHWireTests {
    @Test func roundTrip() throws {
        var w = SSHWire()
        w.writeUInt32(0xDEAD_BEEF)
        w.writeString("hello")
        w.writeString(Data([0, 1, 2]))
        w.writeByte(7)
        w.writeBool(true)
        w.writeBool(false)
        w.writeString("")
        #expect(w.data.prefix(4) == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(w.data[4..<8] == Data([0, 0, 0, 5]))

        var r = SSHWire.Reader(w.data)
        #expect(try r.readUInt32() == 0xDEAD_BEEF)
        #expect(try r.readString() == Data("hello".utf8))
        #expect(try r.readString() == Data([0, 1, 2]))
        #expect(try r.readByte() == 7)
        #expect(try r.readByte() == 1)
        #expect(try r.readByte() == 0)
        #expect(try r.readString() == Data())
        #expect(r.isAtEnd)
        #expect(r.remaining == 0)
        #expect(SSHWire(w.data).data == w.data)
    }

    @Test func mpintEncoding() throws {
        func mp(_ bytes: [UInt8]) -> Data { var w = SSHWire(); w.writeMPInt(Data(bytes)); return w.data }
        // leading zeros are stripped
        #expect(mp([0x00, 0x00, 0x7f, 0x01]) == Data([0, 0, 0, 2, 0x7f, 0x01]))
        // high bit set -> 0x00 prefix
        #expect(mp([0x80, 0x01]) == Data([0, 0, 0, 3, 0x00, 0x80, 0x01]))
        // strip then re-prefix
        #expect(mp([0x00, 0x00, 0xff]) == Data([0, 0, 0, 2, 0x00, 0xff]))
        // plain
        #expect(mp([0x01, 0x02]) == Data([0, 0, 0, 2, 0x01, 0x02]))
        // reading back and dropping the sign byte recovers the magnitude
        var r = SSHWire.Reader(mp([0x80, 0x01]))
        var s = try r.readString()
        if s.first == 0 { s = s.dropFirst() }
        #expect(s == Data([0x80, 0x01]))
    }

    @Test func readerErrorsAndSlices() throws {
        var short = SSHWire.Reader(Data([0, 0]))
        #expect(safeskiError { _ = try short.readUInt32() }?.code == "invalid_format")
        var trunc = SSHWire.Reader(Data([0, 0, 0, 9, 1, 2]))
        #expect(safeskiError { _ = try trunc.readString() }?.code == "invalid_format")
        var empty = SSHWire.Reader(Data())
        #expect(safeskiError { _ = try empty.readByte() }?.code == "invalid_format")
        #expect(empty.readRest() == Data())

        // a Data slice with a non-zero startIndex must be handled
        var w = SSHWire(); w.writeUInt32(99); w.writeString("abc"); w.writeByte(0xee)
        let padded = Data([9, 9, 9, 9]) + w.data
        var r = SSHWire.Reader(padded[4...])
        #expect(try r.readUInt32() == 99)
        #expect(try r.readString() == Data("abc".utf8))
        #expect(r.readRest() == Data([0xee]))
        #expect(r.isAtEnd)
    }
}

@Suite("ECDSA formats")
struct ECDSAFormatTests {
    @Test func rawDERRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let msg = Data("der".utf8)
        let sig = try key.signature(for: msg)
        let raw = sig.rawRepresentation
        #expect(raw.count == 64)
        let der = try ECDSAFormat.rawToDER(raw)
        #expect(der.first == 0x30)
        #expect(der == sig.derRepresentation)
        #expect(try ECDSAFormat.derToRaw(der) == raw)
        #expect(key.publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der), for: msg))
        #expect(safeskiError { _ = try ECDSAFormat.rawToDER(Data(repeating: 1, count: 63)) }?.code == "invalid_format")
        #expect(safeskiError { _ = try ECDSAFormat.derToRaw(Data([0x30, 0x01, 0x00])) }?.code == "invalid_format")
    }

    @Test func rawToSSHStructure() throws {
        // r with the high bit set, s without; both deterministic
        let r = Data(repeating: 0x80, count: 32)
        let s = Data([0x00, 0x00]) + Data(repeating: 0x42, count: 30)
        let blob = try ECDSAFormat.rawToSSH(r + s)
        var outer = SSHWire.Reader(blob)
        #expect(try outer.readString() == Data("ecdsa-sha2-nistp256".utf8))
        var inner = SSHWire.Reader(try outer.readString())
        #expect(outer.isAtEnd)
        #expect(try inner.readString() == Data([0x00]) + r)
        #expect(try inner.readString() == Data(repeating: 0x42, count: 30))
        #expect(inner.isAtEnd)
        #expect(safeskiError { _ = try ECDSAFormat.rawToSSH(Data(repeating: 0, count: 65)) }?.code == "invalid_format")
    }
}

@Suite("Base64URL and hex")
struct Base64HexTests {
    @Test func base64URLRoundTrip() throws {
        for n in 0...10 {
            let d = Data((0..<n).map { UInt8(truncatingIfNeeded: $0 * 37 + 251) })
            let s = Base64URL.encode(d)
            #expect(!s.contains("=") && !s.contains("+") && !s.contains("/"))
            #expect(Base64URL.decode(s) == d, "len \(n)")
        }
        #expect(Base64URL.encode(Data([0xfb, 0xff])) == "-_8")
        #expect(Base64URL.decode("-_8") == Data([0xfb, 0xff]))
        #expect(Base64URL.decode("AQID") == Data([1, 2, 3]))
        #expect(Base64URL.decode("AQI") == Data([1, 2]))
        #expect(Base64URL.decode("AQ") == Data([1]))
        #expect(Base64URL.decode("") == Data())
        #expect(Base64URL.decode("!!!") == nil)
        // padded input is tolerated
        #expect(Base64URL.decode("AQ==") == Data([1]))
    }

    @Test func hex() {
        #expect(Data(hexString: "00ff10") == Data([0x00, 0xff, 0x10]))
        #expect(Data(hexString: "ABCDef") == Data([0xab, 0xcd, 0xef]))
        #expect(Data(hexString: "") == Data())
        #expect(Data(hexString: "abc") == nil)
        #expect(Data(hexString: "zz") == nil)
        #expect(Data(hexString: "0g") == nil)
        let d = Data((0...255).map { UInt8($0) })
        #expect(Data(hexString: d.hexString) == d)
        #expect(Data([0xde, 0xad]).hexString == "dead")
    }
}

@Suite("Public key formats")
struct PublicKeyFormatTests {
    let key = P256.Signing.PrivateKey()

    @Test func sshEncoding() throws {
        let pub = key.publicKey
        let line = try pub.encoded(.ssh, comment: "me@host")
        #expect(line.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(line.hasSuffix(" me@host"))
        let parts = line.split(separator: " ")
        #expect(parts.count == 3)
        let blob = try #require(Data(base64Encoded: String(parts[1])))
        #expect(blob == pub.sshBlob)
        var r = SSHWire.Reader(blob)
        #expect(try r.readString() == Data("ecdsa-sha2-nistp256".utf8))
        #expect(try r.readString() == Data("nistp256".utf8))
        #expect(try r.readString() == pub.x963Representation)
        #expect(r.isAtEnd)
        #expect(pub.sshFingerprint.hasPrefix("SHA256:"))
        #expect(!pub.sshFingerprint.contains("="))
    }

    @Test func jwkEncoding() throws {
        let pub = key.publicKey
        let raw = pub.rawRepresentation
        #expect(raw.count == 64)
        let jwk = pub.jwk
        #expect(jwk["kty"] == .string("EC"))
        #expect(jwk["crv"] == .string("P-256"))
        #expect(jwk["x"] == .string(Base64URL.encode(raw.prefix(32))))
        #expect(jwk["y"] == .string(Base64URL.encode(raw.suffix(32))))
        #expect(Base64URL.decode(jwk["x"]!.stringValue!)! + Base64URL.decode(jwk["y"]!.stringValue!)! == raw)

        let text = try pub.encoded(.jwk)
        let parsed = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
        #expect(parsed == .object(jwk))

        // RFC 7638: SHA-256 over the lexicographically ordered required members, no whitespace
        let canon = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(jwk["x"]!.stringValue!)\",\"y\":\"\(jwk["y"]!.stringValue!)\"}"
        let expected = Base64URL.encode(Data(SHA256.hash(data: Data(canon.utf8))))
        #expect(pub.jwkThumbprint == expected)
        #expect(pub.jwkThumbprint == pub.jwkThumbprint)
        #expect(pub.jwkThumbprint.count == 43)
        #expect(P256.Signing.PrivateKey().publicKey.jwkThumbprint != pub.jwkThumbprint)
    }

    @Test func otherEncodings() throws {
        let pub = key.publicKey
        #expect(try pub.encoded(.hex) == pub.rawRepresentation.hexString)
        #expect(try pub.encoded(.raw) == pub.rawRepresentation.base64EncodedString())
        #expect(try pub.encoded(.der) == pub.derRepresentation.base64EncodedString())
        #expect(try pub.encoded(.pem).hasPrefix("-----BEGIN PUBLIC KEY-----"))
        #expect(try P256.Signing.PublicKey(pemRepresentation: pub.encoded(.pem)).rawRepresentation == pub.rawRepresentation)
    }

    @Test func sshFingerprintMatchesSSHKeygen() throws {
        let keygen = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        try #require(FileManager.default.isExecutableFile(atPath: keygen.path), "ssh-keygen missing")
        let home = try TempHome("keygen")
        defer { home.cleanup() }
        let pub = key.publicKey
        let file = home.root.appendingPathComponent("id.pub")
        try Data((try pub.encoded(.ssh, comment: "test") + "\n").utf8).write(to: file)

        let p = Process()
        p.executableURL = keygen
        p.arguments = ["-lf", file.path]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        try p.run()
        let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        #expect(p.terminationStatus == 0, Comment(rawValue: output))
        #expect(output.contains(pub.sshFingerprint), Comment(rawValue: output))
        #expect(output.hasPrefix("256 "), Comment(rawValue: output))
        #expect(output.contains("(ECDSA)"), Comment(rawValue: output))
    }
}
