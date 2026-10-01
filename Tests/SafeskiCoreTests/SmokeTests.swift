import Testing
@testable import SafeskiCore

@Test func globMatching() {
    #expect(Glob.match("/usr/bin/ssh", "/usr/bin/ssh"))
    #expect(Glob.match("**/ssh", "/usr/bin/ssh"))
    #expect(!Glob.match("/usr/*/ssh", "/usr/local/bin/ssh"))
    #expect(Glob.match("/usr/**/ssh", "/usr/local/bin/ssh"))
}
