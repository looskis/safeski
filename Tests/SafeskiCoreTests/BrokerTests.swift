import Darwin
import Foundation
import Testing
@testable import SafeskiCore

/// In-process agent + broker on temp sockets. The broker runs as the current user, so the agent
/// is told to trust forwarded identities from this uid via SAFESKI_BROKER_TRUST_UID (test-only).
@Test func brokerForwardsCallsWithForwardedIdentity() throws {
    // Short paths: sun_path is 104 bytes.
    let base = "/tmp/ssk-bt-\(getpid())"
    try? FileManager.default.removeItem(atPath: base)
    try FileManager.default.createDirectory(atPath: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(atPath: base) }

    setenv("SAFESKI_BROKER_TRUST_UID", "\(getuid())", 1)
    defer { unsetenv("SAFESKI_BROKER_TRUST_UID") }

    // Agent (headless) on its own home + runtime dir.
    let paths = SafeskiPaths(root: URL(fileURLWithPath: "\(base)/home"))
    setenv("SAFESKI_RUNTIME_DIR", "\(base)/run", 1)
    defer { unsetenv("SAFESKI_RUNTIME_DIR") }
    let agent = try AgentServer(paths: paths, interactive: false)
    try agent.start()
    defer { agent.stop() }
    let agentSock = paths.agentSocket.path
    #expect(UnixSocketClient.isListening(path: agentSock))

    // Registry + broker.
    let registry = BrokerRegistry(dir: "\(base)/reg")
    try registry.create()
    try registry.register(uid: getuid(), socketPath: agentSock)
    #expect(try registry.lookup(uid: getuid()) == agentSock)
    let broker = BrokerServer(socketPath: "\(base)/b.sock", registryDir: registry.dir, allowNonRoot: true)
    broker.log = { _ in }
    try broker.start()
    defer { broker.stop() }
    #expect(UnixSocketClient.isListening(path: broker.socketPath))

    // Through the broker: whoami carries the forwarded identity with transport "broker".
    let viaBroker = RemoteBackend(socketPath: broker.socketPath, brokerUser: "\(getuid())")
    let who = try viaBroker.whoami()
    #expect(who.transport == "broker")
    #expect(who.uid == getuid())
    #expect(who.pid == getpid())
    #expect(who.path == CallerIdentity.resolvePath(pid: getpid()))

    // status is served by the agent (same process here, so pid matches) and the socket is the agent's.
    // StatusResult needs a device record (Secure Enclave identity key).
    _ = try agent.service.store.initialize(name: "broker-test")
    let st = try viaBroker.status()
    #expect(st.socket == agentSock)
    #expect(st.pid == Int(getpid()))

    // The agent audited nothing for whoami/status, but a secret lookup through the broker is
    // audited with the forwarded caller.
    _ = try? viaBroker.getSecret("nope", purpose: nil)
    let last = try agent.service.audit.tail(1).last
    #expect(last?.caller?.transport == "broker")
    #expect(last?.caller?.pid == getpid())

    // Default user (empty) resolves to the caller's own uid.
    let own = RemoteBackend(socketPath: broker.socketPath, brokerUser: "")
    #expect(try own.whoami().uid == getuid())

    // Unknown target user: not_found.
    let missing = RemoteBackend(socketPath: broker.socketPath, brokerUser: "4000000000")
    #expect(throws: SafeskiError.notFound("no agent registered for uid 4000000000")) { try missing.whoami() }

    // A registry entry whose file is owned by another uid is not trusted. We cannot chown as a
    // normal user, so check the symlink rejection path instead.
    symlink(registry.entryPath(uid: getuid()), registry.entryPath(uid: 4000000001))
    #expect(throws: SafeskiError.self) { try registry.lookup(uid: 4000000001) }
    unlink(registry.entryPath(uid: 4000000001))

    // First frame that is not _broker.connect is rejected by the broker.
    let bad = RPCClient(socketPath: broker.socketPath)
    #expect(throws: SafeskiError.self) { try bad.call(RPCMethod.whoami) }

    // Direct hello to the agent from an untrusted uid is refused (the agent then still serves the
    // peer's real identity on later frames).
    unsetenv("SAFESKI_BROKER_TRUST_UID")
    var forged = CallerIdentity(transport: "broker"); forged.uid = 0; forged.path = "/forged"
    let direct = RPCClient(socketPath: agentSock, connectHello: try BrokerProtocol.helloRequest(caller: forged))
    #expect(throws: SafeskiError.denied("_broker.hello is only accepted from the root broker")) { try direct.call(RPCMethod.whoami) }
    let plain = RPCClient(socketPath: agentSock)
    #expect(try plain.call(RPCMethod.whoami, as: CallerIdentity.self).transport == "unix")

    // A hello that is not the first frame is treated as an unknown method, not an identity change.
    setenv("SAFESKI_BROKER_TRUST_UID", "\(getuid())", 1)
    _ = try plain.call(RPCMethod.whoami)
    #expect(throws: SafeskiError.self) { try plain.call(BrokerProtocol.helloMethod, params: try JSONValue(["caller": forged])) }
    #expect(try plain.call(RPCMethod.whoami, as: CallerIdentity.self).transport == "unix")

    registry.unregister(uid: getuid())
    #expect(registry.list().isEmpty)
}

@Test func brokerProtocolForcesTransport() throws {
    var c = CallerIdentity(transport: "local"); c.uid = 7; c.tokenName = "t"
    let req = try BrokerProtocol.helloRequest(caller: c)
    #expect(req.method == BrokerProtocol.helloMethod)
    let back = try BrokerProtocol.forwardedIdentity(from: req.params)
    #expect(back.transport == "broker")
    #expect(back.uid == 7)
    #expect(back.tokenName == nil)
    #expect(throws: SafeskiError.self) { try BrokerProtocol.forwardedIdentity(from: .object([:])) }
    #expect(try BrokerRegistry.resolveUser("501") == 501)
    #expect(try BrokerRegistry.resolveUser("root") == 0)
    #expect(throws: SafeskiError.self) { try BrokerRegistry.resolveUser("no-such-user-xyz") }
}
