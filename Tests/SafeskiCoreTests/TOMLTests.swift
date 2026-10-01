import Foundation
import Testing
@testable import SafeskiCore

@Suite("TOML parser")
struct TOMLTests {
    private func lineOf(_ error: Error?) -> Int? {
        if case .syntax(let line, _)? = error as? TOMLParser.TOMLError { return line }
        return nil
    }
    private func messageOf(_ error: Error?) -> String {
        if case .syntax(_, let m)? = error as? TOMLParser.TOMLError { return m }
        return ""
    }
    private func parseError(_ s: String) -> Error? {
        do { _ = try TOMLParser.parse(s); return nil } catch { return error }
    }

    @Test func tables() throws {
        let t = try TOMLParser.parse("""
        top = "level"
        [a]
        x = 1
        [b.c]
        y = "s"
        [b]
        z = true
        """)
        #expect(t["top"]?.stringValue == "level")
        #expect(t["a"]?["x"]?.intValue == 1)
        #expect(t["b"]?["c"]?["y"]?.stringValue == "s")
        #expect(t["b"]?["z"]?.boolValue == true)
    }

    @Test func nestedDottedKeys() throws {
        let t = try TOMLParser.parse("""
        a.b.c = 1
        a.b.d = 2
        a.e = "x"
        [srv]
        host.name = "h"
        host.port = 8080
        """)
        #expect(t["a"]?["b"]?["c"]?.intValue == 1)
        #expect(t["a"]?["b"]?["d"]?.intValue == 2)
        #expect(t["a"]?["e"]?.stringValue == "x")
        #expect(t["srv"]?["host"]?["name"]?.stringValue == "h")
        #expect(t["srv"]?["host"]?["port"]?.intValue == 8080)
    }

    @Test func quotedKeys() throws {
        let t = try TOMLParser.parse("""
        "dotted.name" = 1
        'lit.key' = 2
        [secrets."WEIRD KEY"]
        v = 3
        """)
        #expect(t["dotted.name"]?.intValue == 1)
        #expect(t["lit.key"]?.intValue == 2)
        #expect(t["secrets"]?["WEIRD KEY"]?["v"]?.intValue == 3)
    }

    @Test func arrayOfTables() throws {
        let t = try TOMLParser.parse("""
        [[fruit]]
        name = "apple"
        physical.color = "red"
        [fruit.taste]
        sweet = true

        [[fruit]]
        name = "banana"
        physical.color = "yellow"
        """)
        let fruit = try #require(t["fruit"]?.arrayValue)
        #expect(fruit.count == 2)
        #expect(fruit[0]["name"]?.stringValue == "apple")
        #expect(fruit[0]["physical"]?["color"]?.stringValue == "red")
        #expect(fruit[0]["taste"]?["sweet"]?.boolValue == true)
        #expect(fruit[1]["name"]?.stringValue == "banana")
        #expect(fruit[1]["physical"]?["color"]?.stringValue == "yellow")
        #expect(fruit[1]["taste"] == nil)
    }

    @Test func inlineTables() throws {
        let t = try TOMLParser.parse("""
        point = { x = 1, y = -2 }
        nested = { a = { b = { c = "d" } }, flag = false }
        empty = {}
        dotted = { k.l = "m" }
        """)
        #expect(t["point"]?["x"]?.intValue == 1)
        #expect(t["point"]?["y"]?.intValue == -2)
        #expect(t["nested"]?["a"]?["b"]?["c"]?.stringValue == "d")
        #expect(t["nested"]?["flag"]?.boolValue == false)
        #expect(t["empty"]?.objectValue?.isEmpty == true)
        #expect(t["dotted"]?["k"]?["l"]?.stringValue == "m")
    }

    @Test func arraysMultilineTrailingComma() throws {
        let t = try TOMLParser.parse("""
        ints = [1, 2, 3]
        empty = []
        rules = [
          { path = "/a" },   # first
          # a comment line inside the array
          { path = "/b", ttl = 5 },
        ]
        nested = [[1, 2], ["a", "b"]]
        """)
        #expect(t["ints"]?.arrayValue?.compactMap(\.intValue) == [1, 2, 3])
        #expect(t["empty"]?.arrayValue?.isEmpty == true)
        let rules = try #require(t["rules"]?.arrayValue)
        #expect(rules.count == 2)
        #expect(rules[0]["path"]?.stringValue == "/a")
        #expect(rules[1]["ttl"]?.intValue == 5)
        #expect(t["nested"]?[1]?[0]?.stringValue == "a")
    }

    @Test func basicStringEscapes() throws {
        let t = try TOMLParser.parse(#"s = "a\tb\nc\"d\\e\u0041\U0001F600 end""#)
        #expect(t["s"]?.stringValue == "a\tb\nc\"d\\eA\u{1F600} end")
    }

    @Test func literalStrings() throws {
        let t = try TOMLParser.parse(#"s = 'C:\path\n"quoted" #nothash'"#)
        #expect(t["s"]?.stringValue == #"C:\path\n"quoted" #nothash"#)
    }

    @Test func numbers() throws {
        let t = try TOMLParser.parse("""
        a = 42
        b = -7
        c = 3.5
        d = -0.25
        e = 0xff
        f = 1_000_000
        g = 1e3
        h = +5
        """)
        #expect(t["a"]?.intValue == 42)
        #expect(t["b"]?.intValue == -7)
        #expect(t["c"]?.doubleValue == 3.5)
        #expect(t["d"]?.doubleValue == -0.25)
        #expect(t["e"]?.intValue == 255)
        #expect(t["f"]?.intValue == 1_000_000)
        #expect(t["g"]?.doubleValue == 1000)
        #expect(t["h"]?.intValue == 5)
    }

    @Test func booleans() throws {
        let t = try TOMLParser.parse("t = true\nf = false")
        #expect(t["t"]?.boolValue == true)
        #expect(t["f"]?.boolValue == false)
        // `trueish` is not a boolean literal
        #expect(parseError("x = trueish") != nil)
    }

    @Test func commentsAtEndOfLines() throws {
        let t = try TOMLParser.parse("""
        # leading comment
        a = 1 # trailing
        s = "x # not a comment" # real comment
        [tbl] # table comment
        b = [ 1, # one
              2 ] # two
        """)
        #expect(t["a"]?.intValue == 1)
        #expect(t["s"]?.stringValue == "x # not a comment")
        #expect(t["tbl"]?["b"]?.arrayValue?.count == 2)
    }

    @Test func crlfLineEndings() throws {
        let t = try TOMLParser.parse("a = 1\r\n[b]\r\nc = 2\r\n")
        #expect(t["a"]?.intValue == 1)
        #expect(t["b"]?["c"]?.intValue == 2)
    }

    @Test func duplicateKeyIsAnError() {
        let e = parseError("a = 1\n\na = 2")
        #expect(lineOf(e) == 3)
        #expect(messageOf(e).contains("duplicate key 'a'"))

        let inline = parseError("t = { a = 1, a = 2 }")
        #expect(messageOf(inline).contains("duplicate key"))

        // a value cannot be redefined as a table either
        let asTable = parseError("a = 1\n[a]\nb = 2")
        #expect(asTable != nil)
    }

    @Test func unterminatedStringReportsLine() {
        let e = parseError("a = 1\nb = \"oops")
        #expect(lineOf(e) == 2)
        #expect(messageOf(e).contains("unterminated string"))

        let multi = parseError("a = 1\nb = 2\nc = 'open\nd = 3")
        #expect(lineOf(multi) == 3)
        #expect(messageOf(multi).contains("newline in string"))

        #expect((e as? LocalizedError)?.errorDescription?.contains("line 2") == true)
    }

    @Test func otherSyntaxErrors() {
        #expect(messageOf(parseError("a 1")).contains("expected '='"))
        #expect(messageOf(parseError("[a")).contains("expected ']'"))
        #expect(messageOf(parseError("a = [1 2]")).contains("expected ',' or ']'"))
        #expect(messageOf(parseError("a = { x = 1 y = 2 }")).contains("expected ',' or '}'"))
        #expect(messageOf(parseError("a = 1 b = 2")).contains("unexpected"))
        #expect(messageOf(parseError("a = \"bad \\q escape\"")).contains("bad escape"))
    }

    @Test func defaultPolicyParses() throws {
        let t = try TOMLParser.parse(PolicyDocument.defaultTOML)
        #expect(t["defaults"]?["approve"]?.stringValue == "once")
        #expect(t["defaults"]?["ttl"]?.intValue == 300)
        #expect(t["defaults"]?["deny_unmatched"]?.boolValue == false)
        #expect(t["keys"] == nil)
        #expect(t["secrets"] == nil)
    }

    @Test func realisticPolicy() throws {
        let t = try TOMLParser.parse("""
        [defaults]
        approve = "once"
        ttl = 300

        [keys.github-ssh]
        access = "biometry-any"
        rules = [
          { path = "/usr/bin/ssh", approve = "never" },
          { path = "/usr/bin/git", approve = "never" },
        ]

        [secrets.ANTHROPIC_API_KEY]
        rules = [
          { parent = "**/claude", approve = "once", ttl = 3600 },
          { token = "docker-dev", approve = "never" },
        ]

        [tokens.docker-dev]
        hash = "abc"
        """)
        let key = try #require(t["keys"]?["github-ssh"])
        #expect(key["access"]?.stringValue == "biometry-any")
        let rules = try #require(key["rules"]?.arrayValue)
        #expect(rules.count == 2)
        #expect(rules[1]["path"]?.stringValue == "/usr/bin/git")
        #expect(rules[1]["approve"]?.stringValue == "never")
        let srules = try #require(t["secrets"]?["ANTHROPIC_API_KEY"]?["rules"]?.arrayValue)
        #expect(srules[0]["parent"]?.stringValue == "**/claude")
        #expect(srules[0]["ttl"]?.intValue == 3600)
        #expect(srules[1]["token"]?.stringValue == "docker-dev")
        #expect(t["tokens"]?["docker-dev"]?["hash"]?.stringValue == "abc")
    }
}
