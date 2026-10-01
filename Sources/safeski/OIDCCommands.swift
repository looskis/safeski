import ArgumentParser
import CryptoKit
import Foundation
import SafeskiCore

/// `safeski oidc`: the Secure Enclave as a local OpenID provider, and token exchange for AWS / GCP /
/// Azure workload identity federation.
struct OIDCCmd: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "oidc",
        abstract: "Mint enclave-signed OIDC tokens and exchange them for short-lived cloud credentials.",
        discussion: """
        safeski acts as an OpenID identity provider: tokens are ES256 JWTs signed by an enclave key, \
        and the matching JWKS + discovery documents are published so clouds can verify them. \
        Configure the [oidc] section of policy.toml first (see `safeski oidc setup`).
        """,
        subcommands: [Setup.self, Token.self, Decode.self, Jwks.self, Discovery.self, Publish.self,
                      Aws.self, Gcp.self, GcpExecutable.self, Azure.self])
}

// MARK: - shared helpers

enum OIDCHelper {
    /// Config from this machine's policy.toml (same file the agent reads).
    static func config() throws -> OIDCConfig {
        try OIDCConfig(policy: try Policy.load(from: SafeskiPaths.default.policy))
    }

    static func issuer(_ g: GlobalOptions) throws -> (backend: Backend, issuer: OIDCIssuer) {
        let backend = try g.backend()
        let status = try backend.status()
        let iss = OIDCIssuer(config: try config(), access: OIDCKeyAccess(backend: backend),
                             deviceID: status.deviceID, deviceName: status.deviceName)
        if let local = backend as? LocalBackend {
            // In-process: record the mint ourselves (the agent does this in OIDCFrontend).
            iss.onMint = { minted, _ in
                _ = try? local.service.audit.append(action: "oidc.token", resource: minted.key, outcome: "allow", caller: local.caller, detail: [
                    "aud": .string(minted.aud), "sub": .string(minted.sub), "kid": .string(minted.kid),
                    "jti": .string(minted.jti), "exp": .number(Double(minted.exp)),
                ])
            }
        }
        return (backend, iss)
    }

    /// Mint through the agent's `oidc.token` when one is running (so the agent's policy, approval
    /// cache and audit apply and the caller shows up as this process), else in-process.
    static func mint(_ g: GlobalOptions, _ req: TokenRequest) throws -> MintedToken {
        let (backend, issuer) = try issuer(g)
        if backend.isRemote {
            do { return try backend.call(OIDCFrontend.tokenMethod, params: try JSONValue(req)).decode(MintedToken.self) }
            catch let e as SafeskiError {
                // Older agent without the OIDC frontend: fall back to signing through keys.sign.
                guard case .rpc(let m) = e, m.contains("unknown method") else { throw e }
            }
        }
        return try issuer.mint(req)
    }

    static func ttl(_ s: String?) throws -> TimeInterval? {
        guard let s else { return nil }
        if let n = Double(s) { return n }
        guard let d = parseDuration(s) else { throw ValidationError("bad ttl '\(s)' (use seconds or 30s/15m/1h/1d)") }
        return d
    }

    /// `k=v` is a string claim; `k:=<json>` is raw JSON (numbers, bools, arrays, objects).
    static func claims(_ specs: [String]) throws -> [String: JSONValue]? {
        guard !specs.isEmpty else { return nil }
        var out: [String: JSONValue] = [:]
        for spec in specs {
            let key: String
            let value: JSONValue
            if let r = spec.range(of: ":=") {
                key = String(spec[..<r.lowerBound])
                guard let v = try? JSONDecoder().decode(JSONValue.self, from: Data(spec[r.upperBound...].utf8)) else {
                    throw ValidationError("claim '\(key)': value after := is not JSON")
                }
                value = v
            } else if let eq = spec.firstIndex(of: "=") {
                key = String(spec[..<eq])
                value = .string(String(spec[spec.index(after: eq)...]))
            } else {
                throw ValidationError("claim '\(spec)' must be k=v or k:=json")
            }
            guard !key.isEmpty else { throw ValidationError("claim name cannot be empty in '\(spec)'") }
            out[key] = value
        }
        return out
    }

    static var selfPath: String {
        CallerIdentity.resolvePath(pid: getpid()) ?? URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
    }

    static func shellQuote(_ s: String) -> String {
        if s.range(of: "^[A-Za-z0-9_./:=@%+-]+$", options: .regularExpression) != nil { return s }
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func printDryRun(_ req: HTTPRequestSpec, json: Bool, note: String? = nil) {
        if json { print(req.json.prettyJSON); return }
        print("# dry run: request not sent")
        if let n = note { print("# \(n)") }
        print(req.rendered)
    }

    static func stderr(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }
}

// MARK: - setup

extension OIDCCmd {
    struct Setup: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Create the OIDC signing key and print (or write) the policy.toml [oidc] block.")
        @Option(help: "Public HTTPS URL where you will host the discovery documents (AWS requires HTTPS).") var issuer: String?
        @Option(help: "Name of the enclave-signing key to create/use.") var key: String = OIDCConfig.defaultKeyName
        @Option(help: "Access policy for a newly created key: none, user-presence, biometry-any, biometry-current-set, device-passcode.")
        var access: AccessPolicy = .none
        @Option(help: "Local discovery server address, or 'off'.") var listen: String = "127.0.0.1:7866"
        @Flag(help: "Append the [oidc] block to policy.toml if there is none yet.") var write = false
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let b = try g.backend()
            let existing = try? b.getKey(key)
            let summary: KeySummary
            if let e = existing {
                guard e.kind == .enclaveSigning else { Output.fail("key '\(key)' exists but is \(e.kind.rawValue); OIDC needs enclave-signing") }
                summary = e
                print("key '\(key)' already exists (\(e.access.rawValue))")
            } else {
                summary = try b.createKey(CreateKeyParams(name: key, kind: .enclaveSigning, access: access, comment: "safeski OIDC signing key"))
                print("created enclave-signing key '\(key)' (access: \(access.rawValue))")
            }
            if let j = OIDCDiscovery.jwk(for: summary), let kid = j["kid"]?.stringValue { print("kid: \(kid)") }

            let current = try OIDCHelper.config()
            let deviceSlug = try b.status().deviceName.lowercased().replacingOccurrences(of: " ", with: "-")
            let iss = try issuer.map { try OIDCConfig.normalizeIssuer($0) } ?? current.issuer ?? "https://oidc.example.com/\(deviceSlug)"
            let block = OIDCConfig.sampleTOML(issuer: iss, key: key, listen: listen == "off" ? nil : listen)
            let policyURL = SafeskiPaths.default.policy
            if write {
                guard !current.isConfigured else { Output.fail("policy.toml already has an [oidc] section; edit it by hand: \(policyURL.path)") }
                var text = FileIO.exists(policyURL) ? String(decoding: try FileIO.read(policyURL), as: UTF8.self) : PolicyDocument.defaultTOML
                if !text.hasSuffix("\n") { text += "\n" }
                text += "\n" + block + "\n"
                try FileIO.writePrivate(Data(text.utf8), to: policyURL)
                print("wrote [oidc] block to \(policyURL.path)")
                if issuer == nil { print("edit `issuer` to the HTTPS URL where you will host the discovery documents") }
            } else {
                print("\nadd this to \(policyURL.path)" + (current.isConfigured ? " (an [oidc] section already exists; merge by hand)" : " (or re-run with --write)") + ":\n")
                print(block)
            }
            print("\nnext: safeski oidc publish --dir ./site   # then host ./site at the issuer URL")
            if b.isRemote { print("      safeski policy reload               # the agent picks up listen/issuer on restart") }
        }
    }
}

// MARK: - token / decode

extension OIDCCmd {
    struct Token: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Mint an ES256 JWT signed by the enclave key.")
        @Option(help: "Audience (aud) claim, e.g. sts.amazonaws.com.") var aud: String
        @Option(help: "Subject: a literal, or the name of an [oidc.subjects] template. Default: the 'default' template or device:<id>.") var sub: String?
        @Option(help: "Lifetime: seconds or 30s/15m/1h. Default: [oidc].default_ttl.") var ttl: String?
        @Option(name: .long, parsing: .singleValue, help: "Extra claim: k=v (string) or k:=json. Repeatable.") var claim: [String] = []
        @Option(help: "Sign with this key instead of [oidc].key.") var key: String?
        @Flag(help: "Print only the compact JWT (default when stdout is not a terminal).") var raw = false
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let req = TokenRequest(aud: aud, sub: sub, ttl: try OIDCHelper.ttl(ttl), claims: try OIDCHelper.claims(claim), key: key)
            let t = try OIDCHelper.mint(g, req)
            if g.json { print(try JSONValue(t).prettyJSON); return }
            print(t.jwt)
            // Interactive use gets a one-line summary on stderr; pipes and --raw get only the JWT.
            if !raw, isatty(STDOUT_FILENO) == 1 {
                OIDCHelper.stderr("iss=\(t.iss) sub=\(t.sub) aud=\(t.aud) kid=\(t.kid) exp=\(ISO8601DateFormatter().string(from: t.expiration))")
            }
        }
    }

    struct Decode: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Pretty-print a JWT's header and claims and verify it against local keys.")
        @Argument(help: "Compact JWT, or - to read it from stdin.") var jwt: String = "-"
        @Flag(help: "Only check structure; skip signature verification.") var noVerify = false
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let compact = jwt == "-" ? String(decoding: Output.readAllStdin(), as: UTF8.self) : jwt
            let t = try JWT.decode(compact)
            var verdict = "skipped"
            var keyName: String?
            var ok = true
            if !noVerify {
                let (_, issuer) = try OIDCHelper.issuer(g)
                if let kid = t.kid, let (k, pk) = try issuer.key(forKid: kid) {
                    keyName = k.name
                    if let why = t.validate(with: pk) { verdict = "INVALID: \(why)"; ok = false }
                    else { verdict = "valid" }
                } else {
                    verdict = "unknown kid \(t.kid ?? "(none)"): no local enclave-signing key has that thumbprint"; ok = false
                }
            }
            if g.json {
                var o: [String: JSONValue] = ["header": .object(t.header), "claims": .object(t.claims), "signature": .string(verdict), "valid": .bool(ok)]
                if let k = keyName { o["key"] = .string(k) }
                print(JSONValue.object(o).prettyJSON)
            } else {
                print("header:")
                print(JSONValue.object(t.header).prettyJSON)
                print("claims:")
                print(JSONValue.object(t.claims).prettyJSON)
                let f = ISO8601DateFormatter()
                if let exp = t.expiration {
                    let left = Int(exp.timeIntervalSinceNow)
                    print("expires:   \(f.string(from: exp)) (\(left >= 0 ? "in \(left)s" : "\(-left)s ago"))")
                }
                print("signature: \(verdict)" + (keyName.map { " (key '\($0)')" } ?? ""))
            }
            if !ok { throw ExitCode(1) }
        }
    }
}

// MARK: - jwks / discovery / publish

extension OIDCCmd {
    struct Jwks: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the JWKS for the OIDC key (plus keys labeled oidc=\"true\").")
        @OptionGroup var g: GlobalOptions
        func run() throws { print(try OIDCHelper.issuer(g).issuer.jwks().prettyJSON) }
    }

    struct Discovery: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print the OpenID discovery document (openid-configuration).")
        @OptionGroup var g: GlobalOptions
        func run() throws { print(try OIDCHelper.issuer(g).issuer.discovery().prettyJSON) }
    }

    struct Publish: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Write the discovery + JWKS documents to a directory for static hosting at the issuer URL.")
        @Option(help: "Output directory (files go under <dir>/.well-known/).") var dir: String
        @Option(help: "AWS account ID, used to fill in the trust-policy snippet.") var awsAccount: String = "123456789012"
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let (_, issuer) = try OIDCHelper.issuer(g)
            let iss = try issuer.config.requireIssuer()
            let out = URL(fileURLWithPath: (dir as NSString).expandingTildeInPath)
            let files = try OIDCDiscovery.publish(configuration: try issuer.discovery(), jwks: try issuer.jwks(), to: out)
            if g.json { print(JSONValue.array(files.map { .string($0.path) }).prettyJSON); return }
            for f in files { print("wrote \(f.path)") }
            if !iss.hasPrefix("https://") { OIDCHelper.stderr("warning: issuer \(iss) is not https; AWS and GCP will reject it") }
            let p = OIDCConfig.providerPath(issuer: iss)
            let host = String(p.split(separator: "/", maxSplits: 1).first ?? "")
            let prefix = p.contains("/") ? String(p[p.index(after: p.firstIndex(of: "/")!)...]) + "/" : ""
            let sub = issuer.config.subject(nil, deviceID: issuer.deviceID, deviceName: issuer.deviceName, key: issuer.config.key)
            print("""

            Host \(out.path) so that these URLs resolve (both must return application/json over HTTPS):
              \(iss)/.well-known/openid-configuration
              \(iss)/.well-known/jwks.json

            S3 + CloudFront / static site:
              aws s3 sync \(OIDCHelper.shellQuote(out.path)) s3://YOUR-BUCKET/\(prefix) --content-type application/json
            GitHub Pages:
              copy the files into the Pages repo for \(host) (keep the .well-known directory; add an empty .nojekyll file)

            AWS: create the IAM OIDC provider (no thumbprint needed; IAM validates the TLS chain):
              \(AWSFederation.createProviderCommand(issuer: iss))
            AWS: role trust policy (adjust aud/sub to your rules):
            \(AWSFederation.trustPolicy(issuer: iss, accountID: awsAccount, subject: sub).prettyJSON)

            GCP: gcloud iam workload-identity-pools providers create-oidc PROVIDER --location=global --workload-identity-pool=POOL \\
                   --issuer-uri=\(iss) --allowed-audiences=AUDIENCE --attribute-mapping=google.subject=assertion.sub
            Azure: on the app registration add a federated credential with issuer \(iss), subject \(sub), audience \(AzureFederation.defaultAudience)

            Re-run `safeski oidc publish` whenever the key changes.
            """)
        }
    }
}

// MARK: - AWS

extension OIDCCmd {
    struct Aws: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "AssumeRoleWithWebIdentity; prints AWS credential_process JSON.",
                                                        discussion: "Use as `credential_process` in ~/.aws/config (see --print-config). Every call mints a fresh enclave-signed token.")
        @Option(help: "IAM role to assume.") var roleArn: String
        @Option(help: "RoleSessionName (default safeski-<device id>).") var sessionName: String?
        @Option(help: "Credential lifetime in seconds (900...43200, bounded by the role's max).") var duration: Int = 3600
        @Option(help: "STS region for a regional endpoint (default: global sts.amazonaws.com).") var region: String?
        @Option(help: "Token audience; must match the provider's client ID list.") var aud: String = AWSFederation.defaultAudience
        @Option(help: "Subject (literal or [oidc.subjects] name).") var sub: String?
        @Option(help: "Token lifetime (seconds or 15m).") var ttl: String?
        @Flag(help: "Print the request instead of sending it.") var dryRun = false
        @Flag(help: "Print a ~/.aws/config snippet for this role and exit.") var printConfig = false
        @Option(help: "Profile name for --print-config.") var profile: String = "safeski"
        @OptionGroup var g: GlobalOptions

        func run() throws {
            guard roleArn.hasPrefix("arn:aws:iam::"), roleArn.contains(":role/") else { throw ValidationError("--role-arn must look like arn:aws:iam::ACCOUNT:role/NAME") }
            guard (900...43200).contains(duration) else { throw ValidationError("--duration must be 900...43200") }
            if printConfig {
                var cmd = "\(OIDCHelper.shellQuote(OIDCHelper.selfPath)) oidc aws --role-arn \(OIDCHelper.shellQuote(roleArn))"
                if let s = sessionName { cmd += " --session-name \(OIDCHelper.shellQuote(s))" }
                if duration != 3600 { cmd += " --duration \(duration)" }
                if let r = region { cmd += " --region \(r)" }
                print(AWSFederation.awsConfigSnippet(profile: profile, command: cmd))
                print("\n# then: AWS_PROFILE=\(profile) aws sts get-caller-identity")
                return
            }
            let t = try OIDCHelper.mint(g, TokenRequest(aud: aud, sub: sub, ttl: try OIDCHelper.ttl(ttl)))
            let (_, issuer) = try OIDCHelper.issuer(g)
            let req = AWSFederation.assumeRoleRequest(roleArn: roleArn, sessionName: AWSFederation.sessionName(sessionName, deviceID: issuer.deviceID),
                                                      token: t.jwt, durationSeconds: duration, region: region)
            if dryRun { OIDCHelper.printDryRun(req, json: g.json, note: "token sub=\(t.sub) aud=\(t.aud) kid=\(t.kid)"); return }
            let reply = try req.send()
            let creds: AWSFederation.Credentials
            do { creds = try AWSFederation.parseAssumeRoleResponse(reply.body) }
            catch let e as AWSFederation.STSError { Output.fail("\(e.errorDescription ?? "STS error") (HTTP \(reply.status))") }
            print(creds.credentialProcessJSON.prettyJSON)
            if let arn = creds.assumedRoleArn { OIDCHelper.stderr("assumed \(arn) until \(ISO8601DateFormatter().string(from: creds.expiration))") }
        }
    }
}

// MARK: - GCP

extension OIDCCmd {
    struct Gcp: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Exchange a token at the GCP STS for an access token (optionally impersonating a service account).")
        @Option(help: "Workload identity provider: //iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/POOL/providers/PROVIDER") var audience: String
        @Option(help: "Service account email to impersonate via generateAccessToken.") var serviceAccount: String?
        @Option(help: "OAuth scope.") var scope: String = GCPFederation.cloudPlatformScope
        @Option(help: "Subject (literal or [oidc.subjects] name).") var sub: String?
        @Option(help: "Token lifetime (seconds or 15m).") var ttl: String?
        @Flag(help: "Print the request(s) instead of sending.") var dryRun = false
        @Option(help: "Write an external_account credential file that runs `safeski oidc gcp-executable`, then exit.") var writeConfig: String?
        @OptionGroup var g: GlobalOptions

        func run() throws {
            try GCPFederation.validateAudience(audience)
            if let path = writeConfig {
                var cmd = "\(OIDCHelper.shellQuote(OIDCHelper.selfPath)) oidc gcp-executable --audience \(OIDCHelper.shellQuote(audience))"
                if let s = sub { cmd += " --sub \(OIDCHelper.shellQuote(s))" }
                let cfg = GCPFederation.externalAccountConfig(audience: audience, serviceAccount: serviceAccount, command: cmd)
                let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
                try FileIO.writePrivate(Data((cfg.prettyJSON + "\n").utf8), to: url)
                print("wrote \(url.path)")
                print("""
                use it with:
                  export GOOGLE_APPLICATION_CREDENTIALS=\(OIDCHelper.shellQuote(url.path))
                  export GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1   # client libraries refuse executables without this
                  gcloud auth login --cred-file=\(OIDCHelper.shellQuote(url.path))
                """)
                return
            }
            let t = try OIDCHelper.mint(g, TokenRequest(aud: audience, sub: sub, ttl: try OIDCHelper.ttl(ttl)))
            let sts = GCPFederation.stsRequest(audience: audience, token: t.jwt, scope: scope)
            if dryRun {
                OIDCHelper.printDryRun(sts, json: g.json, note: "token sub=\(t.sub) aud=\(t.aud) kid=\(t.kid)")
                if let sa = serviceAccount {
                    let imp = GCPFederation.impersonateRequest(serviceAccount: sa, federatedToken: "<federated access token from STS>", scope: scope)
                    if g.json { print(imp.json.prettyJSON) } else { print("# then, with the STS access token:"); print(imp.rendered) }
                }
                return
            }
            let reply = try sts.send()
            var token = try GCPFederation.parseSTSResponse(reply.body)
            if let sa = serviceAccount {
                let r2 = try GCPFederation.impersonateRequest(serviceAccount: sa, federatedToken: token.accessToken, scope: scope).send()
                token = try GCPFederation.parseImpersonationResponse(r2.body)
            }
            print(token.json.prettyJSON)
        }
    }

    struct GcpExecutable: ParsableCommand {
        static let configuration = CommandConfiguration(commandName: "gcp-executable",
                                                        abstract: "Executable-sourced credential: prints the JSON GCP client libraries expect from credential_source.executable.")
        @Option(help: "Workload identity provider audience (default: $GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE, which the client library sets).") var audience: String?
        @Option(help: "Subject (literal or [oidc.subjects] name).") var sub: String?
        @Option(help: "Token lifetime (seconds or 15m).") var ttl: String?
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let env = ProcessInfo.processInfo.environment
            guard let aud = audience ?? env["GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"], !aud.isEmpty else {
                print(GCPFederation.executableError(code: "missing_audience", message: "pass --audience or set GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE").compactJSON)
                throw ExitCode(1)
            }
            do {
                let t = try OIDCHelper.mint(g, TokenRequest(aud: aud, sub: sub, ttl: try OIDCHelper.ttl(ttl)))
                let out = GCPFederation.executableResponse(idToken: t.jwt, expiration: t.expiration)
                if let file = env["GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"], !file.isEmpty {
                    try? FileIO.writePrivate(Data(out.compactJSON.utf8), to: URL(fileURLWithPath: file))
                }
                print(out.compactJSON)
            } catch {
                let msg = (error as? SafeskiError)?.errorDescription ?? error.localizedDescription
                print(GCPFederation.executableError(code: (error as? SafeskiError)?.code ?? "error", message: msg).compactJSON)
                throw ExitCode(1)
            }
        }
    }
}

// MARK: - Azure

extension OIDCCmd {
    struct Azure: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "client_credentials with a safeski JWT as the client assertion (Entra ID federated identity credential).",
                                                        discussion: "On the app registration, add a federated credential whose issuer is [oidc].issuer, whose subject matches --sub, and whose audience matches --aud.")
        @Option(help: "Tenant ID or domain.") var tenant: String
        @Option(help: "Application (client) ID.") var clientId: String
        @Option(help: "Scope, e.g. https://graph.microsoft.com/.default or https://management.azure.com/.default.") var scope: String
        @Option(help: "Subject (literal or [oidc.subjects] name); must equal the federated credential's subject.") var sub: String?
        @Option(help: "Assertion audience; Entra federated credentials expect api://AzureADTokenExchange. Pass the token endpoint URL for certificate-style assertions.")
        var aud: String = AzureFederation.defaultAudience
        @Option(help: "Assertion lifetime (default 10m).") var ttl: String?
        @Flag(help: "Print the request instead of sending it.") var dryRun = false
        @OptionGroup var g: GlobalOptions

        func run() throws {
            let endpoint = AzureFederation.tokenEndpoint(tenant: tenant)
            let audience = aud == "token-endpoint" ? endpoint : aud
            let t = try OIDCHelper.mint(g, TokenRequest(aud: audience, sub: sub, ttl: try OIDCHelper.ttl(ttl) ?? AzureFederation.defaultAssertionTTL))
            let req = AzureFederation.tokenRequest(tenant: tenant, clientID: clientId, scope: scope, assertion: t.jwt)
            if dryRun { OIDCHelper.printDryRun(req, json: g.json, note: "assertion sub=\(t.sub) aud=\(t.aud) kid=\(t.kid)"); return }
            let reply = try req.send()
            print(try AzureFederation.parseTokenResponse(reply.body).prettyJSON)
        }
    }
}
