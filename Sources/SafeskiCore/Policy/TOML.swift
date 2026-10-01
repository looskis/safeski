import Foundation

/// A small TOML parser covering the subset safeski's policy files use:
/// - bare/quoted keys, dotted keys, `[table]`, `[[array of tables]]`
/// - strings ("..." with escapes, '...' literal), integers, floats, booleans
/// - arrays (multi-line ok), inline tables `{ a = 1, b = "x" }`
/// - comments
/// Unsupported: dates, multi-line strings. Values decode into `JSONValue`.
public struct TOMLParser {
    public enum TOMLError: Error, LocalizedError {
        case syntax(line: Int, message: String)
        public var errorDescription: String? {
            if case .syntax(let l, let m) = self { return "TOML syntax error at line \(l): \(m)" }
            return "TOML error"
        }
    }

    private let text: [Character]
    private var pos = 0
    private var line = 1
    private var root: [String: JSONValue] = [:]
    private var currentPath: [String] = []
    private var arrayTablePaths: Set<String> = []

    public static func parse(_ s: String) throws -> JSONValue {
        var p = TOMLParser(text: Array(s))
        try p.parseDocument()
        return .object(p.root)
    }

    private init(text: [Character]) { self.text = text }

    // MARK: lexing helpers
    private var atEnd: Bool { pos >= text.count }
    private var peek: Character? { atEnd ? nil : text[pos] }
    private mutating func advance() { if let c = peek { if c == "\n" { line += 1 }; pos += 1 } }
    private mutating func skipSpaces() { while let c = peek, c == " " || c == "\t" { advance() } }
    private mutating func skipWhitespaceAndComments() {
        while let c = peek {
            if c == " " || c == "\t" || c == "\n" || c == "\r" { advance() }
            else if c == "#" { while let d = peek, d != "\n" { advance() } }
            else { break }
        }
    }
    private mutating func skipLineRest() throws {
        skipSpaces()
        if peek == "#" { while let d = peek, d != "\n" { advance() } }
        if let c = peek, c != "\n", c != "\r" { throw TOMLError.syntax(line: line, message: "unexpected '\(c)'") }
    }
    private func err(_ m: String) -> TOMLError { .syntax(line: line, message: m) }

    // MARK: document
    private mutating func parseDocument() throws {
        while true {
            skipWhitespaceAndComments()
            guard let c = peek else { return }
            if c == "[" {
                try parseTableHeader()
            } else {
                let keys = try parseKey()
                skipSpaces()
                guard peek == "=" else { throw err("expected '=' after key") }
                advance(); skipSpaces()
                let v = try parseValue()
                try setValue(path: currentPath + keys, value: v)
                try skipLineRest()
            }
        }
    }

    private mutating func parseTableHeader() throws {
        advance() // [
        var isArray = false
        if peek == "[" { isArray = true; advance() }
        skipSpaces()
        let keys = try parseKey()
        skipSpaces()
        guard peek == "]" else { throw err("expected ']'") }
        advance()
        if isArray { guard peek == "]" else { throw err("expected ']]'") }; advance() }
        try skipLineRest()
        if isArray {
            let joined = keys.joined(separator: "\u{0}")
            arrayTablePaths.insert(joined)
            // append a new table to the array at `keys`
            var arr = (getValue(path: keys)?.arrayValue) ?? []
            arr.append(.object([:]))
            try setValue(path: keys, value: .array(arr), replace: true)
            currentPath = keys
        } else {
            if getValue(path: keys) == nil { try setValue(path: keys, value: .object([:])) }
            currentPath = keys
        }
    }

    private mutating func parseKey() throws -> [String] {
        var parts: [String] = []
        while true {
            skipSpaces()
            guard let c = peek else { throw err("expected key") }
            if c == "\"" { parts.append(try parseBasicString()) }
            else if c == "'" { parts.append(try parseLiteralString()) }
            else {
                var s = ""
                while let d = peek, d.isLetter || d.isNumber || d == "_" || d == "-" { s.append(d); advance() }
                guard !s.isEmpty else { throw err("bad key character '\(c)'") }
                parts.append(s)
            }
            skipSpaces()
            if peek == "." { advance(); continue }
            return parts
        }
    }

    private mutating func parseValue() throws -> JSONValue {
        guard let c = peek else { throw err("expected value") }
        switch c {
        case "\"": return .string(try parseBasicString())
        case "'": return .string(try parseLiteralString())
        case "[": return try parseArray()
        case "{": return try parseInlineTable()
        case "t", "f":
            if matchWord("true") { return .bool(true) }
            if matchWord("false") { return .bool(false) }
            throw err("bad literal")
        default:
            return try parseNumber()
        }
    }

    private mutating func matchWord(_ w: String) -> Bool {
        let chars = Array(w)
        guard pos + chars.count <= text.count, Array(text[pos..<pos + chars.count]) == chars else { return false }
        let after = pos + chars.count < text.count ? text[pos + chars.count] : " "
        guard !(after.isLetter || after.isNumber || after == "_") else { return false }
        pos += chars.count
        return true
    }

    private mutating func parseNumber() throws -> JSONValue {
        var s = ""
        while let d = peek, d.isNumber || d == "+" || d == "-" || d == "." || d == "e" || d == "E" || d == "_" || d == "x" || (d.isHexDigit && s.hasPrefix("0x")) {
            if d != "_" { s.append(d) }; advance()
        }
        guard !s.isEmpty else { throw err("expected value") }
        if s.hasPrefix("0x"), let v = Int(s.dropFirst(2), radix: 16) { return .number(Double(v)) }
        if let i = Int(s) { return .number(Double(i)) }
        if let f = Double(s) { return .number(f) }
        throw err("bad number '\(s)'")
    }

    private mutating func parseBasicString() throws -> String {
        advance() // "
        var s = ""
        while let c = peek {
            if c == "\"" { advance(); return s }
            if c == "\\" {
                advance()
                guard let e = peek else { throw err("bad escape") }
                advance()
                switch e {
                case "n": s.append("\n")
                case "t": s.append("\t")
                case "r": s.append("\r")
                case "\"": s.append("\"")
                case "\\": s.append("\\")
                case "u", "U":
                    let n = e == "u" ? 4 : 8
                    guard pos + n <= text.count, let code = UInt32(String(text[pos..<pos + n]), radix: 16), let sc = Unicode.Scalar(code) else { throw err("bad unicode escape") }
                    s.append(Character(sc)); pos += n
                default: throw err("bad escape \\\(e)")
                }
                continue
            }
            if c == "\n" { throw err("newline in string") }
            s.append(c); advance()
        }
        throw err("unterminated string")
    }

    private mutating func parseLiteralString() throws -> String {
        advance() // '
        var s = ""
        while let c = peek {
            if c == "'" { advance(); return s }
            if c == "\n" { throw err("newline in string") }
            s.append(c); advance()
        }
        throw err("unterminated string")
    }

    private mutating func parseArray() throws -> JSONValue {
        advance() // [
        var items: [JSONValue] = []
        while true {
            skipWhitespaceAndComments()
            if peek == "]" { advance(); return .array(items) }
            items.append(try parseValue())
            skipWhitespaceAndComments()
            if peek == "," { advance(); continue }
            skipWhitespaceAndComments()
            guard peek == "]" else { throw err("expected ',' or ']' in array") }
            advance(); return .array(items)
        }
    }

    private mutating func parseInlineTable() throws -> JSONValue {
        advance() // {
        var obj: [String: JSONValue] = [:]
        skipSpaces()
        if peek == "}" { advance(); return .object(obj) }
        while true {
            skipSpaces()
            let keys = try parseKey()
            skipSpaces()
            guard peek == "=" else { throw err("expected '=' in inline table") }
            advance(); skipSpaces()
            let v = try parseValue()
            var tmp = JSONValue.object(obj)
            try TOMLParser.set(&tmp, path: keys, value: v, replace: false, line: line)
            obj = tmp.objectValue ?? [:]
            skipSpaces()
            if peek == "," { advance(); continue }
            guard peek == "}" else { throw err("expected ',' or '}' in inline table") }
            advance(); return .object(obj)
        }
    }

    // MARK: tree helpers
    private func getValue(path: [String]) -> JSONValue? {
        var cur: JSONValue = .object(root)
        for k in path {
            if case .array(let a) = cur, let last = a.last { cur = last }
            guard let next = cur[k] else { return nil }
            cur = next
        }
        return cur
    }

    private mutating func setValue(path: [String], value: JSONValue, replace: Bool = false) throws {
        var tmp = JSONValue.object(root)
        try TOMLParser.set(&tmp, path: path, value: value, replace: replace, line: line)
        root = tmp.objectValue ?? [:]
    }

    /// Sets value at path, descending into the last element of arrays-of-tables along the way.
    private static func set(_ node: inout JSONValue, path: [String], value: JSONValue, replace: Bool, line: Int) throws {
        guard let key = path.first else { return }
        if case .array(var arr) = node, var last = arr.last {
            try set(&last, path: path, value: value, replace: replace, line: line)
            arr[arr.count - 1] = last
            node = .array(arr)
            return
        }
        guard case .object(var obj) = node else { throw TOMLError.syntax(line: line, message: "cannot set key '\(key)' on non-table") }
        if path.count == 1 {
            if obj[key] != nil, !replace {
                // Allow defining a table that was implicitly created, but not redefining values.
                if case .object(let existing) = obj[key]!, case .object(let new) = value, new.isEmpty, !existing.isEmpty {
                    node = .object(obj); return
                }
                if case .object(let existing) = obj[key]!, case .object = value, existing.isEmpty { obj[key] = value; node = .object(obj); return }
                throw TOMLError.syntax(line: line, message: "duplicate key '\(key)'")
            }
            obj[key] = value
        } else {
            var child = obj[key] ?? .object([:])
            try set(&child, path: Array(path.dropFirst()), value: value, replace: replace, line: line)
            obj[key] = child
        }
        node = .object(obj)
    }
}
