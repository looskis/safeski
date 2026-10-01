import Foundation

public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ s: String) -> Data? {
        var str = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while str.count % 4 != 0 { str.append("=") }
        return Data(base64Encoded: str)
    }
}

public extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = Data.hexVal(chars[i]), let lo = Data.hexVal(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        self = out
    }

    private static func hexVal(_ c: UInt8) -> UInt8? {
        switch c {
        case 48...57: return c - 48
        case 65...70: return c - 55
        case 97...102: return c - 87
        default: return nil
        }
    }
}

/// Minimal SSH wire-format writer/reader (RFC 4251 string/mpint/uint32).
public struct SSHWire {
    public var data = Data()
    public init() {}
    public init(_ data: Data) { self.data = data }

    public mutating func writeUInt32(_ v: UInt32) {
        var be = v.bigEndian
        data.append(Data(bytes: &be, count: 4))
    }
    public mutating func writeString(_ s: Data) {
        writeUInt32(UInt32(s.count)); data.append(s)
    }
    public mutating func writeString(_ s: String) { writeString(Data(s.utf8)) }
    public mutating func writeMPInt(_ raw: Data) {
        // strip leading zeros, prepend 0x00 if high bit set.
        // Work on [UInt8]: Data.removeFirst() shifts startIndex, so a later insert(_, at: 0) would trap.
        var bytes = [UInt8](raw)
        while bytes.first == 0 && bytes.count > 1 { bytes.removeFirst() }
        if let f = bytes.first, f & 0x80 != 0 { bytes.insert(0, at: 0) }
        writeString(Data(bytes))
    }
    public mutating func writeByte(_ b: UInt8) { data.append(b) }
    public mutating func writeBool(_ b: Bool) { data.append(b ? 1 : 0) }

    public struct Reader {
        let data: Data
        public private(set) var offset: Int
        public init(_ data: Data) { self.data = data; self.offset = 0 }
        public var remaining: Int { data.count - offset }
        public var isAtEnd: Bool { remaining == 0 }
        public mutating func readByte() throws -> UInt8 {
            guard remaining >= 1 else { throw SafeskiError.invalidFormat("ssh wire: short read") }
            let b = data[data.startIndex + offset]; offset += 1; return b
        }
        public mutating func readUInt32() throws -> UInt32 {
            guard remaining >= 4 else { throw SafeskiError.invalidFormat("ssh wire: short read") }
            let s = data.startIndex + offset
            let v = UInt32(data[s]) << 24 | UInt32(data[s+1]) << 16 | UInt32(data[s+2]) << 8 | UInt32(data[s+3])
            offset += 4; return v
        }
        public mutating func readString() throws -> Data {
            let n = Int(try readUInt32())
            guard remaining >= n else { throw SafeskiError.invalidFormat("ssh wire: short string") }
            let s = data.startIndex + offset
            let out = data.subdata(in: s..<(s + n)); offset += n; return out
        }
        public mutating func readRest() -> Data {
            let s = data.startIndex + offset; offset = data.count
            return data.subdata(in: s..<data.endIndex)
        }
    }
}
