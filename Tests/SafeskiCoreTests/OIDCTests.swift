import CryptoKit
import Foundation
import Testing
@testable import SafeskiCore

// MARK: - fixtures

/// A throwaway safeski home with a device identity and an enclave-signing key named `oidc`.
/// Uses the real Secure Enclave (no software fallback exists), so these tests need Apple silicon.
struct OIDCFixture {
    let paths: SafeskiPaths
    let store: Store
    let device: DeviceIdentity
    let key: KeyRecord

    init(keyName: String = "oidc", labels: [String: String] = [:]) throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("safeski-oidc-test-\(UUID().uuidString)")
        paths = SafeskiPaths(root: root)
        store = Store(paths: paths)
        device = try store.initialize(name: "test-mac")
        key = try store.createKey(name: keyName, kind: .enclaveSigning, access: .none, labels: labels)
    }

    func cleanup() { try? FileManager.default.removeItem(at: paths.root) }

    func issuer(_ toml: String = "[oidc]\nissuer = \"https://oidc.example.com/test-mac\"\n") throws -> OIDCIssuer {
        let cfg = try OIDCConfig(policy: try Policy.parse(toml))
        return OIDCIssuer(config: cfg, access: OIDCKeyAccess(store: store), deviceID: device.deviceID, deviceName: device.name)
    }

    var publicKey: P256.Signing.PublicKey {
        get throws { try P256.Signing.PublicKey(x963Representation: key.publicKey) }
    }
}

// MARK: - config

@Test func oidcConfigParsesPolicySection() throws {
    let doc = try Policy.parse("""
    [defaults]
    approve = "never"
    [oidc]
    issuer = "https://oidc.example.com/mbp/"
    key = "idp"
    default_ttl = 900
    listen = "127.0.0.1:7866"
    [oidc.subjects]
    default = "device:{device_id}"
    ci = "ci:{device_name}:{key}"
    """)
    let cfg = try OIDCConfig(policy: doc)
    #expect(cfg.isConfigured)
    #expect(cfg.issuer == "https://oidc.example.com/mbp")  // trailing slash stripped
    #expect(cfg.key == "idp")
    #expect(cfg.defaultTTL == 900)
    #expect(cfg.listen == "127.0.0.1:7866")
    #expect(cfg.subjects["ci"] == "ci:{device_name}:{key}")
    #expect(cfg.subject(nil, deviceID: "abc", deviceName: "mbp", key: "idp") == "device:abc")
    #expect(cfg.subject("ci", deviceID: "abc", deviceName: "mbp", key: "idp") == "ci:mbp:idp")
    #expect(cfg.subject("repo:org/x", deviceID: "abc", deviceName: "mbp", key: "idp") == "repo:org/x")
    #expect(OIDCConfig.providerPath(issuer: cfg.issuer!) == "oidc.example.com/mbp")
    let (h, p) = try OIDCConfig.parseListen(":9000")
    #expect(h == "127.0.0.1" && p == 9000)
}

@Test func oidcConfigDefaultsAndValidation() throws {
    let empty = try OIDCConfig(policy: try Policy.parse("[defaults]\napprove = \"once\"\n"))
    #expect(!empty.isConfigured)
    #expect(empty.key == "oidc")
    #expect(empty.defaultTTL == 3600)
    #expect(throws: SafeskiError.self) { try empty.requireIssuer() }
    #expect(throws: SafeskiError.self) { try OIDCConfig(policy: try Policy.parse("[oidc]\nissuer = \"not a url\"\n")) }
    #expect(throws: SafeskiError.self) { try OIDCConfig(policy: try Policy.parse("[oidc]\nissuer = \"https://x.example\"\ndefault_ttl = 0\n")) }
    #expect(throws: SafeskiError.self) { try OIDCConfig(policy: try Policy.parse("[oidc]\nissuer = \"https://x.example\"\nlisten = \"nope\"\n")) }
}

// MARK: - JWT minting with a real enclave key

@Test func mintedJWTVerifiesWithCryptoKit() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    let issuer = try fx.issuer()
    let fixedNow = Date(timeIntervalSince1970: 1_800_000_000)
    issuer.now = { fixedNow }

    let t = try issuer.mint(TokenRequest(aud: "sts.amazonaws.com", ttl: 600, claims: ["repo": .string("org/app"), "n": .number(3)]))
    let pk = try fx.publicKey

    // kid is the RFC 7638 thumbprint of the signing key.
    #expect(t.kid == pk.jwkThumbprint)
    #expect(t.key == "oidc")
    #expect(t.iss == "https://oidc.example.com/test-mac")
    #expect(t.sub == "device:\(fx.device.deviceID)")
    #expect(t.aud == "sts.amazonaws.com")
    #expect(t.iat == 1_800_000_000)
    #expect(t.exp == 1_800_000_600)

    // Three base64url segments; signature verifies over header.payload.
    let parts = t.jwt.split(separator: ".")
    #expect(parts.count == 3)
    let sig = try #require(Base64URL.decode(String(parts[2])))
    #expect(sig.count == 64)
    let ecdsa = try P256.Signing.ECDSASignature(rawRepresentation: sig)
    #expect(pk.isValidSignature(ecdsa, for: Data("\(parts[0]).\(parts[1])".utf8)))

    let decoded = try JWT.decode(t.jwt)
    #expect(decoded.header == ["alg": .string("ES256"), "typ": .string("JWT"), "kid": .string(t.kid)])
    #expect(decoded.claims["iss"]?.stringValue == t.iss)
    #expect(decoded.claims["sub"]?.stringValue == t.sub)
    #expect(decoded.claims["aud"]?.stringValue == "sts.amazonaws.com")
    #expect(decoded.claims["iat"]?.intValue == t.iat)
    #expect(decoded.claims["nbf"]?.intValue == t.iat)
    #expect(decoded.claims["exp"]?.intValue == t.exp)
    #expect(decoded.claims["jti"]?.stringValue == t.jti)
    #expect(decoded.claims["repo"]?.stringValue == "org/app")
    #expect(decoded.claims["n"]?.intValue == 3)
    #expect(decoded.verify(with: pk))
    #expect(decoded.validate(with: pk, now: fixedNow) == nil)
    #expect(decoded.validate(with: pk, now: fixedNow.addingTimeInterval(700)) != nil)   // expired

    // The slash in the issuer is not escaped inside the payload.
    let payload = try #require(Base64URL.decode(String(parts[1])))
    #expect(String(decoding: payload, as: UTF8.self).contains("https://oidc.example.com/test-mac"))

    // A different key must not verify it.
    let other = P256.Signing.PrivateKey().publicKey
    #expect(!decoded.verify(with: other))

    // Tampering with the payload breaks verification.
    var tampered = decoded
    tampered.signingInput = String(parts[0]) + "." + Base64URL.encode(Data("{\"sub\":\"evil\"}".utf8))
    #expect(!tampered.verify(with: pk))

    // Local kid lookup finds the key.
    let found = try #require(try issuer.key(forKid: t.kid))
    #expect(found.summary.name == "oidc")
    #expect(try issuer.key(forKid: "nope") == nil)
}

@Test func mintRejectsBadRequests() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    let issuer = try fx.issuer()
    #expect(throws: SafeskiError.self) { try issuer.mint(TokenRequest(aud: "")) }
    #expect(throws: SafeskiError.self) { try issuer.mint(TokenRequest(aud: "x", ttl: 0)) }
    #expect(throws: SafeskiError.self) { try issuer.mint(TokenRequest(aud: "x", ttl: 1_000_000)) }
    #expect(throws: SafeskiError.self) { try issuer.mint(TokenRequest(aud: "x", claims: ["iss": .string("spoof")])) }
    #expect(throws: SafeskiError.self) { try issuer.mint(TokenRequest(aud: "x", key: "missing")) }
    // No issuer configured.
    let unconfigured = try fx.issuer("[defaults]\napprove = \"once\"\n")
    #expect(throws: SafeskiError.self) { try unconfigured.mint(TokenRequest(aud: "x")) }
}

@Test func mintSignsWithPurposeAndSubjectTemplate() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    var purposes: [String] = []
    let cfg = try OIDCConfig(policy: try Policy.parse("[oidc]\nissuer = \"https://i.example\"\n[oidc.subjects]\nci = \"ci:{device_name}\"\n"))
    let access = OIDCKeyAccess(getKey: { try fx.store.loadKey($0).summary }, listKeys: { try fx.store.listKeys().map(\.summary) },
                               sign: { p in purposes.append(p.purpose ?? ""); return try fx.store.sign(key: p.key, data: p.data, isDigest: p.digest) })
    let issuer = OIDCIssuer(config: cfg, access: access, deviceID: fx.device.deviceID, deviceName: fx.device.name)
    var minted: [MintedToken] = []
    issuer.onMint = { m, _ in minted.append(m) }
    let t = try issuer.mint(TokenRequest(aud: "api://AzureADTokenExchange", sub: "ci"))
    #expect(t.sub == "ci:test-mac")
    #expect(purposes == ["oidc:api://AzureADTokenExchange"])
    #expect(minted.count == 1 && minted[0].jti == t.jti)
    #expect(t.exp - t.iat == 3600)
}

// MARK: - JWKS / discovery

@Test func jwksAndDiscoveryShape() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    // A second key labeled for publication, and a third that is not.
    let successor = try fx.store.createKey(name: "oidc-next", kind: .enclaveSigning, access: .none, labels: ["oidc": "true"])
    _ = try fx.store.createKey(name: "unrelated", kind: .enclaveSigning, access: .none)
    _ = try fx.store.createKey(name: "ed", kind: .softwareEd25519, access: .none, labels: ["oidc": "true"])  // wrong kind, skipped
    let issuer = try fx.issuer()

    let jwks = try issuer.jwks()
    let keys = try #require(jwks["keys"]?.arrayValue)
    #expect(keys.count == 2)
    let first = try #require(keys[0].objectValue)
    let pk = try fx.publicKey
    #expect(first["kty"]?.stringValue == "EC")
    #expect(first["crv"]?.stringValue == "P-256")
    #expect(first["use"]?.stringValue == "sig")
    #expect(first["alg"]?.stringValue == "ES256")
    #expect(first["kid"]?.stringValue == pk.jwkThumbprint)
    #expect(first["x"]?.stringValue == Base64URL.encode(pk.rawRepresentation.prefix(32)))
    #expect(first["y"]?.stringValue == Base64URL.encode(pk.rawRepresentation.suffix(32)))
    #expect(first["d"] == nil)
    let successorPK = try P256.Signing.PublicKey(x963Representation: successor.publicKey)
    #expect(keys[1]["kid"]?.stringValue == successorPK.jwkThumbprint)

    let disc = try issuer.discovery()
    #expect(disc["issuer"]?.stringValue == "https://oidc.example.com/test-mac")
    #expect(disc["jwks_uri"]?.stringValue == "https://oidc.example.com/test-mac/.well-known/jwks.json")
    #expect(disc["id_token_signing_alg_values_supported"]?.stringArray == ["ES256"])
    #expect(disc["response_types_supported"]?.stringArray == ["id_token"])
    #expect(disc["subject_types_supported"]?.stringArray == ["public"])
    #expect(disc["claims_supported"]?.stringArray?.contains("sub") == true)

    // Publish writes both well-known files with unescaped URLs.
    let site = fx.paths.root.appendingPathComponent("site")
    let files = try OIDCDiscovery.publish(configuration: disc, jwks: jwks, to: site)
    #expect(files.count == 3)
    let conf = String(decoding: try Data(contentsOf: site.appendingPathComponent(".well-known/openid-configuration")), as: UTF8.self)
    #expect(conf.contains("\"jwks_uri\" : \"https://oidc.example.com/test-mac/.well-known/jwks.json\""))
    #expect(!conf.contains("\\/"))
    let published = try JSONDecoder().decode(JSONValue.self, from: try Data(contentsOf: site.appendingPathComponent(".well-known/jwks.json")))
    #expect(published == jwks)
}

@Test func httpServerServesDiscoveryAndJWKS() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    let issuer = try fx.issuer()
    let server = OIDCHTTPServer(host: "127.0.0.1", port: 0, handler: OIDCHTTPServer.routes(issuer: { issuer }))
    try server.start()
    defer { server.stop() }
    #expect(server.port != 0)

    func get(_ path: String, method: String = "GET") throws -> (Int, String, Data) {
        var req = URLRequest(url: URL(string: server.url + path)!)
        req.httpMethod = method
        let sem = DispatchSemaphore(value: 0)
        var out: (Int, String, Data) = (0, "", Data())
        URLSession.shared.dataTask(with: req) { d, r, _ in
            let h = r as? HTTPURLResponse
            out = (h?.statusCode ?? 0, h?.value(forHTTPHeaderField: "Content-Type") ?? "", d ?? Data())
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 10)
        return out
    }

    let (s1, ct1, b1) = try get("/.well-known/openid-configuration")
    #expect(s1 == 200 && ct1 == "application/json")
    #expect(try JSONDecoder().decode(JSONValue.self, from: b1) == (try issuer.discovery()))

    let (s2, _, b2) = try get("/.well-known/jwks.json")
    #expect(s2 == 200)
    #expect(try JSONDecoder().decode(JSONValue.self, from: b2) == (try issuer.jwks()))

    let (s3, _, _) = try get("/jwks.json?x=1")
    #expect(s3 == 200)
    let (s4, _, _) = try get("/nope")
    #expect(s4 == 404)
    let (s5, _, _) = try get("/.well-known/jwks.json", method: "POST")
    #expect(s5 == 405)
    let (s6, _, b6) = try get("/healthz", method: "HEAD")
    #expect(s6 == 200 && b6.isEmpty)
}

// MARK: - AWS

let cannedAssumeRoleXML = """
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>device:0123456789abcdef</SubjectFromWebIdentityToken>
    <Audience>sts.amazonaws.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/test/safeski-0123</Arn>
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:safeski-0123</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8AP7sD...EXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2026-10-01T12:34:56Z</Expiration>
      <AccessKeyId>ASIACLKWSDQRAOEXAMPLE</AccessKeyId>
    </Credentials>
    <Provider>oidc.example.com/test-mac</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>
"""

@Test func awsXMLParsingAndCredentialProcessOutput() throws {
    let creds = try AWSFederation.parseAssumeRoleResponse(Data(cannedAssumeRoleXML.utf8))
    #expect(creds.accessKeyId == "ASIACLKWSDQRAOEXAMPLE")
    #expect(creds.secretAccessKey == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY")
    #expect(creds.sessionToken == "AQoDYXdzEE0a8AP7sD...EXAMPLE")
    #expect(creds.expiration == ISO8601DateFormatter().date(from: "2026-10-01T12:34:56Z"))
    #expect(creds.assumedRoleArn == "arn:aws:sts::123456789012:assumed-role/test/safeski-0123")
    #expect(creds.subjectFromWebIdentityToken == "device:0123456789abcdef")

    let out = creds.credentialProcessJSON
    #expect(out["Version"]?.intValue == 1)
    #expect(out["AccessKeyId"]?.stringValue == "ASIACLKWSDQRAOEXAMPLE")
    #expect(out["SecretAccessKey"]?.stringValue == creds.secretAccessKey)
    #expect(out["SessionToken"]?.stringValue == creds.sessionToken)
    #expect(out["Expiration"]?.stringValue == "2026-10-01T12:34:56Z")
    #expect(out.compactJSON.contains("\"Version\":1"))

    let errXML = """
    <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type>
    <Code>InvalidIdentityToken</Code><Message>Couldn't retrieve verification key from your identity provider</Message></Error>
    <RequestId>x</RequestId></ErrorResponse>
    """
    #expect(throws: AWSFederation.STSError(code: "InvalidIdentityToken", message: "Couldn't retrieve verification key from your identity provider")) {
        try AWSFederation.parseAssumeRoleResponse(Data(errXML.utf8))
    }
    #expect(throws: SafeskiError.self) { try AWSFederation.parseAssumeRoleResponse(Data("<nope/>".utf8)) }
}

@Test func awsDryRunRequestConstruction() throws {
    let req = AWSFederation.assumeRoleRequest(roleArn: "arn:aws:iam::123456789012:role/test", sessionName: "safeski-abc",
                                              token: "eyJ.a+b/c.sig", durationSeconds: 3600)
    #expect(req.method == "POST")
    #expect(req.url == "https://sts.amazonaws.com/")
    #expect(req.headers.contains { $0.0 == "Content-Type" && $0.1.hasPrefix("application/x-www-form-urlencoded") })
    let body = try #require(req.bodyString)
    #expect(body == "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ftest&RoleSessionName=safeski-abc&WebIdentityToken=eyJ.a%2Bb%2Fc.sig&DurationSeconds=3600")
    #expect(req.rendered.hasPrefix("POST https://sts.amazonaws.com/\n"))
    #expect(req.rendered.contains("WebIdentityToken=eyJ.a%2Bb%2Fc.sig"))
    #expect(AWSFederation.assumeRoleRequest(roleArn: "r", sessionName: "s", token: "t", durationSeconds: 900, region: "eu-west-1").url == "https://sts.eu-west-1.amazonaws.com/")
    #expect(AWSFederation.sessionName(nil, deviceID: "abc") == "safeski-abc")
    #expect(AWSFederation.sessionName("bad name!", deviceID: "x") == "bad-name-")

    let trust = AWSFederation.trustPolicy(issuer: "https://oidc.example.com/mbp", accountID: "123456789012", subject: "device:abc")
    let stmt = try #require(trust["Statement"]?[0])
    #expect(stmt["Principal"]?["Federated"]?.stringValue == "arn:aws:iam::123456789012:oidc-provider/oidc.example.com/mbp")
    #expect(stmt["Condition"]?["StringEquals"]?["oidc.example.com/mbp:aud"]?.stringValue == "sts.amazonaws.com")
    #expect(stmt["Condition"]?["StringEquals"]?["oidc.example.com/mbp:sub"]?.stringValue == "device:abc")
    #expect(AWSFederation.createProviderCommand(issuer: "https://oidc.example.com/mbp").contains("--url https://oidc.example.com/mbp --client-id-list sts.amazonaws.com"))
}

// MARK: - GCP

@Test func gcpExecutableFormatAndConfig() throws {
    let exp = Date(timeIntervalSince1970: 1_800_000_600)
    let out = GCPFederation.executableResponse(idToken: "eyJ.x.y", expiration: exp)
    #expect(out["version"]?.intValue == 1)
    #expect(out["success"]?.boolValue == true)
    #expect(out["token_type"]?.stringValue == "urn:ietf:params:oauth:token-type:jwt")
    #expect(out["id_token"]?.stringValue == "eyJ.x.y")
    #expect(out["expiration_time"]?.intValue == 1_800_000_600)
    #expect(out.compactJSON == "{\"expiration_time\":1800000600,\"id_token\":\"eyJ.x.y\",\"success\":true,\"token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\"version\":1}")
    let err = GCPFederation.executableError(code: "denied", message: "no")
    #expect(err["success"]?.boolValue == false && err["code"]?.stringValue == "denied")

    let aud = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"
    let cfg = GCPFederation.externalAccountConfig(audience: aud, serviceAccount: "sa@proj.iam.gserviceaccount.com",
                                                  command: "/usr/local/bin/safeski oidc gcp-executable --audience \(aud)")
    #expect(cfg["type"]?.stringValue == "external_account")
    #expect(cfg["audience"]?.stringValue == aud)
    #expect(cfg["subject_token_type"]?.stringValue == "urn:ietf:params:oauth:token-type:jwt")
    #expect(cfg["token_url"]?.stringValue == "https://sts.googleapis.com/v1/token")
    #expect(cfg["service_account_impersonation_url"]?.stringValue == "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@proj.iam.gserviceaccount.com:generateAccessToken")
    #expect(cfg["credential_source"]?["executable"]?["command"]?.stringValue?.hasSuffix("gcp-executable --audience \(aud)") == true)
    #expect(cfg["credential_source"]?["executable"]?["timeout_millis"]?.intValue == 30000)
    #expect(GCPFederation.externalAccountConfig(audience: aud, serviceAccount: nil, command: "c")["service_account_impersonation_url"] == nil)
    #expect(!cfg.prettyJSON.contains("\\/"))
    #expect(throws: SafeskiError.self) { try GCPFederation.validateAudience("projects/1") }
    try GCPFederation.validateAudience(aud)
}

@Test func gcpDryRunRequestConstructionAndParsing() throws {
    let aud = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"
    let req = GCPFederation.stsRequest(audience: aud, token: "eyJ.x.y")
    #expect(req.method == "POST" && req.url == "https://sts.googleapis.com/v1/token")
    #expect(req.headers.contains { $0.0 == "Content-Type" && $0.1 == "application/json" })
    let body = try JSONDecoder().decode(JSONValue.self, from: try #require(req.body))
    #expect(body["grantType"]?.stringValue == "urn:ietf:params:oauth:grant-type:token-exchange")
    #expect(body["audience"]?.stringValue == aud)
    #expect(body["subjectTokenType"]?.stringValue == "urn:ietf:params:oauth:token-type:jwt")
    #expect(body["requestedTokenType"]?.stringValue == "urn:ietf:params:oauth:token-type:access_token")
    #expect(body["scope"]?.stringValue == "https://www.googleapis.com/auth/cloud-platform")
    #expect(body["subjectToken"]?.stringValue == "eyJ.x.y")
    #expect(req.bodyString?.contains("\\/") == false)

    let imp = GCPFederation.impersonateRequest(serviceAccount: "sa@p.iam.gserviceaccount.com", federatedToken: "fed")
    #expect(imp.url == "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken")
    #expect(imp.headers.contains { $0.0 == "Authorization" && $0.1 == "Bearer fed" })
    #expect(imp.bodyString == "{\"lifetime\":\"3600s\",\"scope\":[\"https://www.googleapis.com/auth/cloud-platform\"]}")

    let sts = try GCPFederation.parseSTSResponse(Data("{\"access_token\":\"ya29.x\",\"expires_in\":3599,\"token_type\":\"Bearer\",\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\"}".utf8))
    #expect(sts.accessToken == "ya29.x" && sts.expiresIn == 3599)
    #expect(sts.json["access_token"]?.stringValue == "ya29.x")
    let impTok = try GCPFederation.parseImpersonationResponse(Data("{\"accessToken\":\"ya29.sa\",\"expireTime\":\"2030-01-01T00:00:00Z\"}".utf8))
    #expect(impTok.accessToken == "ya29.sa" && impTok.expireTime != nil)
    #expect(throws: SafeskiError.self) {
        try GCPFederation.parseSTSResponse(Data("{\"error\":\"invalid_grant\",\"error_description\":\"bad token\"}".utf8))
    }
}

// MARK: - Azure

@Test func azureDryRunRequestConstruction() throws {
    #expect(AzureFederation.tokenEndpoint(tenant: "t") == "https://login.microsoftonline.com/t/oauth2/v2.0/token")
    let req = AzureFederation.tokenRequest(tenant: "t", clientID: "c", scope: "https://graph.microsoft.com/.default", assertion: "eyJ.x.y")
    #expect(req.method == "POST" && req.url == "https://login.microsoftonline.com/t/oauth2/v2.0/token")
    #expect(req.headers.contains { $0.0 == "Content-Type" && $0.1 == "application/x-www-form-urlencoded" })
    #expect(req.bodyString == "client_id=c&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&grant_type=client_credentials&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJ.x.y")
    let tok = try AzureFederation.parseTokenResponse(Data("{\"token_type\":\"Bearer\",\"expires_in\":3599,\"access_token\":\"eyJ0\"}".utf8))
    #expect(tok["access_token"]?.stringValue == "eyJ0")
    #expect(throws: SafeskiError.self) {
        try AzureFederation.parseTokenResponse(Data("{\"error\":\"invalid_client\",\"error_description\":\"AADSTS700211\"}".utf8))
    }
}

/// End to end: a minted token slotted into each cloud's request without sending anything.
@Test func dryRunWithRealTokenForAllClouds() throws {
    let fx = try OIDCFixture()
    defer { fx.cleanup() }
    let issuer = try fx.issuer()

    let aws = try issuer.mint(TokenRequest(aud: AWSFederation.defaultAudience))
    let awsReq = AWSFederation.assumeRoleRequest(roleArn: "arn:aws:iam::123456789012:role/test", sessionName: AWSFederation.sessionName(nil, deviceID: fx.device.deviceID),
                                                 token: aws.jwt, durationSeconds: 3600)
    #expect(awsReq.bodyString?.contains("WebIdentityToken=\(aws.jwt)") == true)   // JWT chars are all unreserved

    let gaud = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x"
    let gcp = try issuer.mint(TokenRequest(aud: gaud))
    #expect(try JWT.decode(gcp.jwt).audience == gaud)
    let gcpReq = GCPFederation.stsRequest(audience: gaud, token: gcp.jwt)
    #expect(try JSONDecoder().decode(JSONValue.self, from: gcpReq.body!)["subjectToken"]?.stringValue == gcp.jwt)

    let az = try issuer.mint(TokenRequest(aud: AzureFederation.defaultAudience, sub: "my-fed-subject", ttl: AzureFederation.defaultAssertionTTL))
    let azReq = AzureFederation.tokenRequest(tenant: "t", clientID: "c", scope: "https://graph.microsoft.com/.default", assertion: az.jwt)
    #expect(azReq.bodyString?.hasSuffix("&client_assertion=\(az.jwt)") == true)
    let azJWT = try JWT.decode(az.jwt)
    #expect(azJWT.subject == "my-fed-subject")
    #expect(azJWT.audience == "api://AzureADTokenExchange")
    #expect(azJWT.verify(with: try fx.publicKey))
}
