import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

/// A fresh, hermetic safeski home under /tmp/ssk-tests/<random>/. Kept short so that
/// `<root>/run/agent.sock` stays well under the 104-byte sun_path limit.
struct TempHome {
    let root: URL
    let paths: SafeskiPaths

    /// Process-wide, once: make sure the environment cannot redirect sockets or homes at ~/.safeski.
    private static let scrubEnvironment: Void = {
        unsetenv("SAFESKI_RUNTIME_DIR")
        unsetenv("SAFESKI_HOME")
        unsetenv("SAFESKI_SOCKET")
        unsetenv("SAFESKI_TOKEN")
    }()

    init(_ prefix: String = "ssk") throws {
        _ = TempHome.scrubEnvironment
        let base = URL(fileURLWithPath: "/tmp/ssk-tests", isDirectory: true)
        let dir = base.appendingPathComponent("\(prefix)-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        root = dir
        paths = SafeskiPaths(root: dir)
        precondition(!root.path.contains(".safeski"), "tests must never touch ~/.safeski")
    }

    func cleanup() { try? FileManager.default.removeItem(at: root) }

    func writePolicy(_ toml: String) throws {
        try FileIO.writePrivate(Data(toml.utf8), to: paths.policy)
    }
}

/// Secure Enclave operations go through a synchronous XPC call into ctkd. When Swift Testing runs a
/// dozen enclave-creating tests at once on the cooperative pool, every pool thread ends up blocked in
/// that XPC call and the run wedges. This trait serializes the tests that touch the enclave (or run a
/// `Service`/`Store` that does) without blocking pool threads: it waits on an actor-based gate.
struct EnclaveSerialized: TestTrait, SuiteTrait, TestScoping {
    actor Gate {
        private var locked = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func acquire() async {
            if !locked { locked = true; return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func release() {
            if waiters.isEmpty { locked = false } else { waiters.removeFirst().resume() }
        }
    }
    static let gate = Gate()

    var isRecursive: Bool { true }

    func scopeProvider(for test: Test, testCase: Test.Case?) -> Self? {
        // provideScope is offered once per test (testCase == nil) and once per test case. Scope only the
        // case level: scoping the test or suite level as well would re-acquire the gate and deadlock.
        testCase == nil ? nil : self
    }

    func provideScope(for test: Test, testCase: Test.Case?, performing function: @Sendable () async throws -> Void) async throws {
        await Self.gate.acquire()
        do { try await function() } catch { await Self.gate.release(); throw error }
        await Self.gate.release()
    }
}

extension Trait where Self == ConditionTrait {
    /// Skips the test where no Secure Enclave exists (CI virtual machines), or when
    /// `SAFESKI_DISABLE_ENCLAVE=1` reproduces that locally.
    static var requiresEnclave: Self { .enabled(if: EnclaveProbe.usable, "needs a working Secure Enclave") }
}

/// Whether this machine has an enclave that actually works, decided once per test process.
/// Swift Testing evaluates `.enabled(if:)` while planning the run, so this must never block:
/// on some virtual machines (GitHub's hosted macOS runners) asking CryptoKit about the enclave
/// hangs outright. Everything that touches the enclave therefore runs on a separate thread and
/// is abandoned after a few seconds. `SAFESKI_DISABLE_ENCLAVE=1` skips the question entirely.
enum EnclaveProbe {
    static let usable: Bool = {
        if let v = getenv("SAFESKI_DISABLE_ENCLAVE"), String(cString: v) == "1" { return false }
        let done = DispatchSemaphore(value: 0)
        final class Box: @unchecked Sendable { var ok = false }
        let box = Box()
        Thread.detachNewThread {
            box.ok = Enclave.isAvailable && (try? EnclaveSigningKey(create: .none)) != nil
            done.signal()
        }
        guard done.wait(timeout: .now() + 5) == .success else { return false }
        return box.ok
    }()
}

extension Trait where Self == EnclaveSerialized {
    static var enclaveSerialized: Self { Self() }
}

/// Runs `body` and returns the thrown `SafeskiError`, or nil if nothing (or something else) was thrown.
func safeskiError(_ body: () throws -> Void) -> SafeskiError? {
    do { try body(); return nil } catch { return error as? SafeskiError }
}

func posixMode(_ url: URL) throws -> Int {
    let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attrs[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

func sha256Hex(_ s: String) -> String { Data(SHA256.hash(data: Data(s.utf8))).hexString }

extension CallerIdentity {
    /// A plausible unix-socket peer: the owning user running some tool.
    static func testUnix(path: String? = "/usr/bin/tool", uid: uid_t = getuid(), pid: pid_t = 4242) -> CallerIdentity {
        var c = CallerIdentity(transport: "unix")
        c.uid = uid; c.gid = getgid(); c.pid = pid; c.path = path
        return c
    }
}
