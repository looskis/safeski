import CryptoKit
import Foundation

// MARK: - JSON encoders that keep URLs readable (no "\/" escaping)

public extension JSONEncoder {
    /// Compact, sorted, slashes unescaped. Used for JWT segments and wire bodies.
    static var oidcCompact: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }
    /// Pretty, sorted, slashes unescaped. Used for files and human output.
    static var oidcPretty: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        return e
    }
}

public extension JSONValue {
    var compactJSON: String {
        (try? JSONEncoder.oidcCompact.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? "null"
    }
    var prettyJSON: String {
        (try? JSONEncoder.oidcPretty.encode(self)).map { String(decoding: $0, as: UTF8.self) } ?? "null"
    }
}

// MARK: - JWS compact serialization (ES256 only)

/// A decoded JWT: header, claims, and the raw pieces needed to verify it.
public struct JWT: Equatable {
    public var header: [String: JSONValue]
    public var claims: [String: JSONValue]
    public var signature: Data
    /// `base64url(header) + "." + base64url(payload)`, the bytes that were signed.
    public var signingInput: String

    public var kid: String? { header["kid"]?.stringValue }
    public var alg: String? { header["alg"]?.stringValue }
    public var issuer: String? { claims["iss"]?.stringValue }
    public var subject: String? { claims["sub"]?.stringValue }
    public var audience: String? { claims["aud"]?.stringValue }
    public var expiration: Date? { claims["exp"]?.doubleValue.map { Date(timeIntervalSince1970: $0) } }
    public var issuedAt: Date? { claims["iat"]?.doubleValue.map { Date(timeIntervalSince1970: $0) } }

    public static let reservedClaims: Set<String> = ["iss", "sub", "aud", "iat", "nbf", "exp", "jti"]

    /// Build the compact serialization: header and claims are encoded with sorted keys, then
    /// `sign` receives the signing input and must return the raw 64-byte r||s ES256 signature.
    public static func encode(header: [String: JSONValue], claims: [String: JSONValue],
                              sign: (Data) throws -> Data) throws -> String {
        let h = Base64URL.encode(try JSONEncoder.oidcCompact.encode(JSONValue.object(header)))
        let p = Base64URL.encode(try JSONEncoder.oidcCompact.encode(JSONValue.object(claims)))
        let input = "\(h).\(p)"
        let sig = try sign(Data(input.utf8))
        guard sig.count == 64 else { throw SafeskiError.invalidFormat("ES256 signature must be 64 bytes (r||s), got \(sig.count)") }
        return "\(input).\(Base64URL.encode(sig))"
    }

    /// Parse a compact JWT without verifying it.
    public static func decode(_ compact: String) throws -> JWT {
        let parts = compact.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw SafeskiError.invalidFormat("JWT must have 3 dot-separated segments, got \(parts.count)") }
        guard let hd = Base64URL.decode(String(parts[0])), let pd = Base64URL.decode(String(parts[1])),
              let sd = Base64URL.decode(String(parts[2])) else {
            throw SafeskiError.invalidFormat("JWT segments are not valid base64url")
        }
        guard let header = try? JSONDecoder().decode(JSONValue.self, from: hd).objectValue else {
            throw SafeskiError.invalidFormat("JWT header is not a JSON object")
        }
        guard let claims = try? JSONDecoder().decode(JSONValue.self, from: pd).objectValue else {
            throw SafeskiError.invalidFormat("JWT payload is not a JSON object")
        }
        return JWT(header: header, claims: claims, signature: sd, signingInput: "\(parts[0]).\(parts[1])")
    }

    /// Verify an ES256 signature against a P-256 public key.
    public func verify(with publicKey: P256.Signing.PublicKey) -> Bool {
        guard alg == "ES256", let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
        return publicKey.isValidSignature(sig, for: Data(signingInput.utf8))
    }

    /// Verify signature and time window. Returns a human-readable failure reason, or nil when valid.
    public func validate(with publicKey: P256.Signing.PublicKey, now: Date = Date(), skew: TimeInterval = 60) -> String? {
        guard verify(with: publicKey) else { return "signature does not verify" }
        if let exp = expiration, exp.addingTimeInterval(skew) < now { return "expired at \(ISO8601DateFormatter().string(from: exp))" }
        if let nbf = claims["nbf"]?.doubleValue, Date(timeIntervalSince1970: nbf).addingTimeInterval(-skew) > now { return "not yet valid (nbf)" }
        return nil
    }
}

// MARK: - Minting

/// How the issuer reaches keys: through a `Backend` (CLI), a `Service` + caller (agent RPC),
/// or a bare `Store` (tests). Closures keep SafeskiCore free of a dependency on the CLI.
public struct OIDCKeyAccess {
    public var getKey: (String) throws -> KeySummary
    public var listKeys: () throws -> [KeySummary]
    public var sign: (SignParams) throws -> Data

    public init(getKey: @escaping (String) throws -> KeySummary, listKeys: @escaping () throws -> [KeySummary],
                sign: @escaping (SignParams) throws -> Data) {
        self.getKey = getKey; self.listKeys = listKeys; self.sign = sign
    }

    public init(backend: Backend) {
        self.init(getKey: { try backend.getKey($0) }, listKeys: { try backend.listKeys() }, sign: { try backend.sign($0) })
    }

    public init(service: Service, caller: CallerIdentity) {
        self.init(getKey: { try service.getKey($0, caller: caller) }, listKeys: { try service.listKeys(caller: caller) },
                  sign: { try service.sign($0, caller: caller) })
    }

    /// Direct store access with no policy or audit. Tests only.
    public init(store: Store) {
        self.init(getKey: { try store.loadKey($0).summary }, listKeys: { try store.listKeys().map(\.summary) },
                  sign: { try store.sign(key: $0.key, data: $0.data, isDigest: $0.digest) })
    }
}

/// Parameters for `oidc.token` (RPC) and `OIDCIssuer.mint`.
public struct TokenRequest: Codable, Equatable {
    public var aud: String
    /// Literal subject, or the name of an `[oidc.subjects]` template. nil = the `default` template.
    public var sub: String?
    public var ttl: TimeInterval?
    public var claims: [String: JSONValue]?
    /// Override the configured key name.
    public var key: String?

    public init(aud: String, sub: String? = nil, ttl: TimeInterval? = nil, claims: [String: JSONValue]? = nil, key: String? = nil) {
        self.aud = aud; self.sub = sub; self.ttl = ttl; self.claims = claims; self.key = key
    }
}

public struct MintedToken: Codable, Equatable {
    public var jwt: String
    public var kid: String
    public var key: String
    public var iss: String
    public var sub: String
    public var aud: String
    public var iat: Int
    public var exp: Int
    public var jti: String

    public var expiration: Date { Date(timeIntervalSince1970: TimeInterval(exp)) }
}

/// Mints ES256 JWTs with an enclave-signing key. Every signature goes through `OIDCKeyAccess.sign`
/// with purpose `oidc:<aud>`, so policy, approval and audit apply exactly as for `safeski sign`.
public final class OIDCIssuer {
    public let config: OIDCConfig
    public let access: OIDCKeyAccess
    public let deviceID: String
    public let deviceName: String
    /// Called after a successful mint (the agent records an `oidc.token` audit entry here).
    public var onMint: ((MintedToken, TokenRequest) -> Void)?
    /// Injectable clock for tests.
    public var now: () -> Date = { Date() }

    public init(config: OIDCConfig, access: OIDCKeyAccess, deviceID: String, deviceName: String) {
        self.config = config; self.access = access; self.deviceID = deviceID; self.deviceName = deviceName
    }

    /// Load the signing key's public half, checking it is an enclave P-256 signing key.
    public func publicKey(named name: String? = nil) throws -> (summary: KeySummary, key: P256.Signing.PublicKey) {
        let n = name ?? config.key
        let k: KeySummary
        do { k = try access.getKey(n) }
        catch let e as SafeskiError {
            if case .notFound = e { throw SafeskiError.notFound("OIDC key '\(n)'; create it with `safeski oidc setup` or `safeski keygen \(n)`") }
            throw e
        }
        guard k.kind == .enclaveSigning else { throw SafeskiError.unsupported("OIDC key '\(n)' must be enclave-signing (P-256), got \(k.kind.rawValue)") }
        let pk = try P256.Signing.PublicKey(x963Representation: k.publicKey)
        return (k, pk)
    }

    public func mint(_ req: TokenRequest) throws -> MintedToken {
        let iss = try config.requireIssuer()
        let aud = req.aud.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !aud.isEmpty else { throw SafeskiError.invalidFormat("aud is required") }
        let ttl = req.ttl ?? config.defaultTTL
        guard ttl > 0, ttl <= OIDCConfig.maxTTL else { throw SafeskiError.invalidFormat("ttl must be 1...\(Int(OIDCConfig.maxTTL)) seconds") }
        if let k = req.key { try Names.validate(k) }
        let keyName = req.key ?? config.key
        let (summary, pk) = try publicKey(named: keyName)
        let kid = pk.jwkThumbprint
        let sub = config.subject(req.sub, deviceID: deviceID, deviceName: deviceName, key: summary.name)
        let iat = Int(now().timeIntervalSince1970)
        let exp = iat + Int(ttl)
        var jtiBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, jtiBytes.count, &jtiBytes)
        let jti = Base64URL.encode(Data(jtiBytes))

        var claims: [String: JSONValue] = [:]
        for (k, v) in req.claims ?? [:] {
            guard !JWT.reservedClaims.contains(k) else { throw SafeskiError.invalidFormat("claim '\(k)' is reserved") }
            claims[k] = v
        }
        claims["iss"] = .string(iss)
        claims["sub"] = .string(sub)
        claims["aud"] = .string(aud)
        claims["iat"] = .number(Double(iat))
        claims["nbf"] = .number(Double(iat))
        claims["exp"] = .number(Double(exp))
        claims["jti"] = .string(jti)
        let header: [String: JSONValue] = ["alg": .string("ES256"), "typ": .string("JWT"), "kid": .string(kid)]

        let jwt = try JWT.encode(header: header, claims: claims) { input in
            try access.sign(SignParams(key: summary.name, data: input, digest: false, purpose: "oidc:\(aud)"))
        }
        let minted = MintedToken(jwt: jwt, kid: kid, key: summary.name, iss: iss, sub: sub, aud: aud, iat: iat, exp: exp, jti: jti)
        onMint?(minted, req)
        return minted
    }

    /// JWKS for the configured key plus any enclave-signing key labeled `oidc = "true"`.
    public func jwks() throws -> JSONValue {
        let primary = try publicKey().summary
        return OIDCDiscovery.jwks(keys: try access.listKeys(), primary: primary)
    }

    public func discovery() throws -> JSONValue {
        OIDCDiscovery.configuration(issuer: try config.requireIssuer())
    }

    /// Find the local key whose JWK thumbprint matches `kid`.
    public func key(forKid kid: String) throws -> (summary: KeySummary, key: P256.Signing.PublicKey)? {
        for k in try access.listKeys() where k.kind == .enclaveSigning {
            if let pk = try? P256.Signing.PublicKey(x963Representation: k.publicKey), pk.jwkThumbprint == kid { return (k, pk) }
        }
        return nil
    }
}
