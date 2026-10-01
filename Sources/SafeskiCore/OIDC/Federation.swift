import Foundation

// MARK: - HTTP request spec (dry-run renderable, synchronously sendable)

/// An HTTP request we are about to make. Built first so `--dry-run` can print exactly what would be
/// sent; `send()` performs it with URLSession, synchronously.
public struct HTTPRequestSpec: Equatable {
    public var method: String
    public var url: String
    public var headers: [(String, String)]
    public var body: Data?

    public init(method: String, url: String, headers: [(String, String)] = [], body: Data? = nil) {
        self.method = method; self.url = url; self.headers = headers; self.body = body
    }

    public static func == (a: HTTPRequestSpec, b: HTTPRequestSpec) -> Bool {
        a.method == b.method && a.url == b.url && a.body == b.body && a.headers.map { "\($0.0): \($0.1)" } == b.headers.map { "\($0.0): \($0.1)" }
    }

    public var bodyString: String? { body.map { String(decoding: $0, as: UTF8.self) } }

    /// Request as it would appear on the wire (headers + body), for `--dry-run`.
    public var rendered: String {
        var s = "\(method) \(url)\n"
        for (k, v) in headers { s += "\(k): \(v)\n" }
        if let b = body {
            s += "Content-Length: \(b.count)\n\n"
            s += String(decoding: b, as: UTF8.self) + "\n"
        }
        return s
    }

    public var json: JSONValue {
        var o: [String: JSONValue] = ["method": .string(method), "url": .string(url),
                                      "headers": .object(Dictionary(headers.map { ($0.0, JSONValue.string($0.1)) }, uniquingKeysWith: { a, _ in a }))]
        if let b = bodyString { o["body"] = .string(b) }
        return .object(o)
    }

    public struct Reply {
        public var status: Int
        public var headers: [String: String]
        public var body: Data
        public var bodyString: String { String(decoding: body, as: UTF8.self) }
    }

    /// Perform the request. Blocks the calling thread.
    public func send(timeout: TimeInterval = 30) throws -> Reply {
        guard let u = URL(string: url) else { throw SafeskiError.invalidFormat("bad URL \(url)") }
        var req = URLRequest(url: u, timeoutInterval: timeout)
        req.httpMethod = method
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = body
        let sem = DispatchSemaphore(value: 0)
        var result: Result<Reply, Error> = .failure(SafeskiError.io("no response"))
        let task = URLSession.shared.dataTask(with: req) { data, resp, err in
            if let err { result = .failure(SafeskiError.io("\(method) \(url): \(err.localizedDescription)")) }
            else if let http = resp as? HTTPURLResponse {
                var hs: [String: String] = [:]
                for (k, v) in http.allHeaderFields { hs[String(describing: k).lowercased()] = String(describing: v) }
                result = .success(Reply(status: http.statusCode, headers: hs, body: data ?? Data()))
            } else { result = .failure(SafeskiError.io("\(method) \(url): non-HTTP response")) }
            sem.signal()
        }
        task.resume()
        sem.wait()
        return try result.get()
    }
}

public enum FormEncoding {
    /// RFC 3986 percent-encoding of everything but unreserved characters (what AWS SigV4-free
    /// query APIs and OAuth token endpoints expect).
    public static func encode(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }
    public static func body(_ fields: [(String, String)]) -> String {
        fields.map { "\(encode($0.0))=\(encode($0.1))" }.joined(separator: "&")
    }
}

// MARK: - AWS

public enum AWSFederation {
    public static let defaultAudience = "sts.amazonaws.com"
    public static let apiVersion = "2011-06-15"

    public static func endpoint(region: String?) -> String {
        if let r = region, !r.isEmpty { return "https://sts.\(r).amazonaws.com/" }
        return "https://sts.amazonaws.com/"
    }

    /// Session names must match [\w+=,.@-]{2,64}.
    public static func sessionName(_ requested: String?, deviceID: String) -> String {
        var s = requested ?? "safeski-\(deviceID)"
        s = String(s.unicodeScalars.map { c -> Character in
            let ok = (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || "+=,.@-_".unicodeScalars.contains(c)
            return ok ? Character(c) : "-"
        })
        if s.count < 2 { s = "safeski" }
        return String(s.prefix(64))
    }

    /// `AssumeRoleWithWebIdentity` as a POST form (identical semantics to the GET form; keeps the JWT
    /// out of the URL).
    public static func assumeRoleRequest(roleArn: String, sessionName: String, token: String, durationSeconds: Int, region: String? = nil) -> HTTPRequestSpec {
        let fields: [(String, String)] = [
            ("Action", "AssumeRoleWithWebIdentity"), ("Version", apiVersion),
            ("RoleArn", roleArn), ("RoleSessionName", sessionName),
            ("WebIdentityToken", token), ("DurationSeconds", String(durationSeconds)),
        ]
        return HTTPRequestSpec(method: "POST", url: endpoint(region: region),
                               headers: [("Content-Type", "application/x-www-form-urlencoded; charset=utf-8"), ("Accept", "application/xml")],
                               body: Data(FormEncoding.body(fields).utf8))
    }

    public struct Credentials: Codable, Equatable {
        public var accessKeyId: String
        public var secretAccessKey: String
        public var sessionToken: String
        public var expiration: Date
        public var assumedRoleArn: String?
        public var subjectFromWebIdentityToken: String?

        /// The JSON an AWS `credential_process` must print.
        public var credentialProcessJSON: JSONValue {
            .object([
                "Version": .number(1),
                "AccessKeyId": .string(accessKeyId),
                "SecretAccessKey": .string(secretAccessKey),
                "SessionToken": .string(sessionToken),
                "Expiration": .string(ISO8601DateFormatter().string(from: expiration)),
            ])
        }
    }

    public struct STSError: Error, LocalizedError, Equatable {
        public var code: String
        public var message: String
        public var errorDescription: String? { "AWS STS \(code): \(message)" }
    }

    /// Parse the AssumeRoleWithWebIdentity XML response (or an ErrorResponse).
    public static func parseAssumeRoleResponse(_ xml: Data) throws -> Credentials {
        let p = XMLCollector(xml)
        if let code = p.first("Error/Code") {
            throw STSError(code: code, message: p.first("Error/Message") ?? "")
        }
        guard let ak = p.first("Credentials/AccessKeyId"), let sk = p.first("Credentials/SecretAccessKey"),
              let st = p.first("Credentials/SessionToken"), let expS = p.first("Credentials/Expiration") else {
            throw SafeskiError.invalidFormat("STS response is missing Credentials: \(String(decoding: xml.prefix(400), as: UTF8.self))")
        }
        let f = ISO8601DateFormatter()
        var exp = f.date(from: expS)
        if exp == nil { f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]; exp = f.date(from: expS) }
        guard let expiration = exp else { throw SafeskiError.invalidFormat("STS Expiration '\(expS)' is not ISO-8601") }
        return Credentials(accessKeyId: ak, secretAccessKey: sk, sessionToken: st, expiration: expiration,
                           assumedRoleArn: p.first("AssumedRoleUser/Arn"), subjectFromWebIdentityToken: p.first("SubjectFromWebIdentityToken"))
    }

    public static func createProviderCommand(issuer: String, audience: String = defaultAudience) -> String {
        "aws iam create-open-id-connect-provider --url \(issuer) --client-id-list \(audience)"
    }

    /// IAM role trust policy for the safeski provider. Modern IAM validates the issuer's TLS
    /// certificate against trusted root CAs, so no thumbprint is needed.
    public static func trustPolicy(issuer: String, accountID: String, audience: String = defaultAudience, subject: String) -> JSONValue {
        let p = OIDCConfig.providerPath(issuer: issuer)
        return .object([
            "Version": .string("2012-10-17"),
            "Statement": .array([.object([
                "Effect": .string("Allow"),
                "Principal": .object(["Federated": .string("arn:aws:iam::\(accountID):oidc-provider/\(p)")]),
                "Action": .string("sts:AssumeRoleWithWebIdentity"),
                "Condition": .object(["StringEquals": .object([
                    "\(p):aud": .string(audience),
                    "\(p):sub": .string(subject),
                ])]),
            ])]),
        ])
    }

    public static func awsConfigSnippet(profile: String, command: String) -> String {
        """
        [profile \(profile)]
        credential_process = \(command)
        """
    }
}

/// Collects text content keyed by "Parent/Child" element suffix. Enough for STS responses.
final class XMLCollector: NSObject, XMLParserDelegate {
    private var stack: [String] = []
    private var text = ""
    private(set) var values: [String: [String]] = [:]

    init(_ data: Data) {
        super.init()
        let p = XMLParser(data: data)
        p.delegate = self
        p.parse()
    }

    func first(_ suffix: String) -> String? {
        // Match the full path ending in `suffix` (e.g. "Credentials/AccessKeyId").
        for (path, vals) in values where path == suffix || path.hasSuffix("/" + suffix) {
            if let v = vals.first { return v }
        }
        return nil
    }

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
        stack.append(name); text = ""
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !t.isEmpty { values[stack.joined(separator: "/"), default: []].append(t) }
        stack.removeLast(); text = ""
    }
}

// MARK: - GCP

public enum GCPFederation {
    public static let stsURL = "https://sts.googleapis.com/v1/token"
    public static let cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"
    public static let subjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

    public static func validateAudience(_ a: String) throws {
        guard a.hasPrefix("//iam.googleapis.com/projects/"), a.contains("/workloadIdentityPools/"), a.contains("/providers/") else {
            throw SafeskiError.invalidFormat("GCP audience must look like //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/POOL/providers/PROVIDER")
        }
    }

    /// Token exchange at the Security Token Service.
    public static func stsRequest(audience: String, token: String, scope: String = cloudPlatformScope) -> HTTPRequestSpec {
        let body: JSONValue = .object([
            "grantType": .string("urn:ietf:params:oauth:grant-type:token-exchange"),
            "audience": .string(audience),
            "scope": .string(scope),
            "requestedTokenType": .string("urn:ietf:params:oauth:token-type:access_token"),
            "subjectToken": .string(token),
            "subjectTokenType": .string(subjectTokenType),
        ])
        return HTTPRequestSpec(method: "POST", url: stsURL, headers: [("Content-Type", "application/json"), ("Accept", "application/json")],
                               body: Data(body.compactJSON.utf8))
    }

    public static func impersonationURL(serviceAccount: String) -> String {
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/\(serviceAccount):generateAccessToken"
    }

    /// Exchange the federated STS token for a service-account access token.
    public static func impersonateRequest(serviceAccount: String, federatedToken: String, scope: String = cloudPlatformScope, lifetime: Int = 3600) -> HTTPRequestSpec {
        let body: JSONValue = .object(["scope": .array([.string(scope)]), "lifetime": .string("\(lifetime)s")])
        return HTTPRequestSpec(method: "POST", url: impersonationURL(serviceAccount: serviceAccount),
                               headers: [("Authorization", "Bearer \(federatedToken)"), ("Content-Type", "application/json"), ("Accept", "application/json")],
                               body: Data(body.compactJSON.utf8))
    }

    public struct AccessToken: Codable, Equatable {
        public var accessToken: String
        public var expiresIn: Int?
        public var expireTime: Date?
        public var tokenType: String = "Bearer"

        public var json: JSONValue {
            var o: [String: JSONValue] = ["access_token": .string(accessToken), "token_type": .string(tokenType)]
            if let e = expiresIn { o["expires_in"] = .number(Double(e)) }
            if let t = expireTime { o["expire_time"] = .string(ISO8601DateFormatter().string(from: t)) }
            return .object(o)
        }
    }

    public static func parseSTSResponse(_ data: Data) throws -> AccessToken {
        let v = try parseJSON(data, context: "STS")
        guard let at = v["access_token"]?.stringValue else { throw SafeskiError.invalidFormat("GCP STS response has no access_token") }
        return AccessToken(accessToken: at, expiresIn: v["expires_in"]?.intValue, expireTime: nil, tokenType: v["token_type"]?.stringValue ?? "Bearer")
    }

    public static func parseImpersonationResponse(_ data: Data) throws -> AccessToken {
        let v = try parseJSON(data, context: "generateAccessToken")
        guard let at = v["accessToken"]?.stringValue else { throw SafeskiError.invalidFormat("generateAccessToken response has no accessToken") }
        let exp = v["expireTime"]?.stringValue.flatMap { ISO8601DateFormatter().date(from: $0) }
        return AccessToken(accessToken: at, expiresIn: exp.map { Int($0.timeIntervalSinceNow) }, expireTime: exp)
    }

    static func parseJSON(_ data: Data, context: String) throws -> JSONValue {
        guard let v = try? JSONDecoder().decode(JSONValue.self, from: data) else {
            throw SafeskiError.invalidFormat("GCP \(context): non-JSON response: \(String(decoding: data.prefix(400), as: UTF8.self))")
        }
        if let e = v["error"] {
            let msg = e["message"]?.stringValue ?? e.stringValue ?? e.compactJSON
            throw SafeskiError.denied("GCP \(context): \(msg)" + (v["error_description"]?.stringValue.map { " - \($0)" } ?? ""))
        }
        return v
    }

    /// Output of an executable-sourced credential (what google-auth libraries run and parse).
    public static func executableResponse(idToken: String, expiration: Date) -> JSONValue {
        .object([
            "version": .number(1), "success": .bool(true),
            "token_type": .string(subjectTokenType),
            "id_token": .string(idToken),
            "expiration_time": .number(Double(Int(expiration.timeIntervalSince1970))),
        ])
    }

    public static func executableError(code: String, message: String) -> JSONValue {
        .object(["version": .number(1), "success": .bool(false), "code": .string(code), "message": .string(message)])
    }

    /// The `external_account` credential file pointing at `safeski oidc gcp-executable`.
    public static func externalAccountConfig(audience: String, serviceAccount: String?, command: String, timeoutMillis: Int = 30000) -> JSONValue {
        var o: [String: JSONValue] = [
            "type": .string("external_account"),
            "audience": .string(audience),
            "subject_token_type": .string(subjectTokenType),
            "token_url": .string(stsURL),
            "credential_source": .object(["executable": .object([
                "command": .string(command),
                "timeout_millis": .number(Double(timeoutMillis)),
            ])]),
        ]
        if let sa = serviceAccount { o["service_account_impersonation_url"] = .string(impersonationURL(serviceAccount: sa)) }
        return .object(o)
    }
}

// MARK: - Azure

public enum AzureFederation {
    public static let clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    /// The audience Entra ID expects on tokens from an external IdP configured as a federated
    /// identity credential.
    public static let defaultAudience = "api://AzureADTokenExchange"
    /// Client assertions should be short-lived.
    public static let defaultAssertionTTL: TimeInterval = 600

    public static func tokenEndpoint(tenant: String) -> String {
        "https://login.microsoftonline.com/\(tenant)/oauth2/v2.0/token"
    }

    /// client_credentials grant authenticated with a safeski JWT as the client assertion.
    public static func tokenRequest(tenant: String, clientID: String, scope: String, assertion: String) -> HTTPRequestSpec {
        let fields: [(String, String)] = [
            ("client_id", clientID), ("scope", scope), ("grant_type", "client_credentials"),
            ("client_assertion_type", clientAssertionType), ("client_assertion", assertion),
        ]
        return HTTPRequestSpec(method: "POST", url: tokenEndpoint(tenant: tenant),
                               headers: [("Content-Type", "application/x-www-form-urlencoded"), ("Accept", "application/json")],
                               body: Data(FormEncoding.body(fields).utf8))
    }

    /// Returns the token JSON as Entra returned it (token_type, expires_in, access_token, ...).
    public static func parseTokenResponse(_ data: Data) throws -> JSONValue {
        guard let v = try? JSONDecoder().decode(JSONValue.self, from: data) else {
            throw SafeskiError.invalidFormat("Azure: non-JSON response: \(String(decoding: data.prefix(400), as: UTF8.self))")
        }
        if let e = v["error"]?.stringValue {
            throw SafeskiError.denied("Azure \(e): \(v["error_description"]?.stringValue ?? "")")
        }
        guard v["access_token"]?.stringValue != nil else { throw SafeskiError.invalidFormat("Azure response has no access_token") }
        return v
    }
}
