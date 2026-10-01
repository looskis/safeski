# safeski scope

safeski makes the Mac Secure Enclave the root of trust for every credential on the machine, and
brokers access to those credentials for shells, AI agents, containers, other macOS users, and apps.

## What the enclave gives you

- Keys are **P-256 only**: ECDSA sign, ECDH, ECIES. No RSA, no Ed25519, no AES, no "store this token".
- **Capacity is unlimited.** The enclave wraps a key with a device-bound secret and hands back a blob;
  safeski stores the blob as a file and passes it back for every operation.
- Keys are **device-bound and non-exportable**. No backup, no migration. Design for one key per device
  plus rotation and re-enrollment, never for restore.
- Biometric binding is per key: `none`, `user-presence`, `biometry-any`, `biometry-current-set`,
  `device-passcode`. The prompt is raised by the calling process, so it needs a GUI session.
- A plain, ad-hoc-signed CLI can use the enclave when the wrapped blob lives in a file. Only the
  keychain-backed route needs an Apple Developer identity. safeski never uses the keychain.

## Two tiers, stated honestly

| Tier | What | Guarantee |
|---|---|---|
| Enclave keys | SSH auth, git signing, JWTs, PKCS#11, mTLS later | Private key never leaves hardware, even from root |
| Secrets | API tokens, .env values, passwords | Encrypted at rest under an enclave key; released in plaintext to an authorized caller under policy, or injected by the proxy so the caller never sees it |

## Consumers

| Consumer | Needs | Transport | Identified by |
|---|---|---|---|
| ssh, git over ssh | sign | SSH agent protocol on a unix socket | peer pid + code signature |
| git commit signing | sign | same socket, `gpg.format=ssh` | same |
| AI agents (Claude Code etc.) | secrets, occasionally sign | `safeski run`, `safeski secret get`, the secretless proxy | parent process, path, uid, approval |
| Docker, OrbStack, Apple `container` | secrets, ssh | socket bind-mounted into the VM | session token |
| Native apps, OpenSSL, Java, VPNs | sign | PKCS#11 module over the agent socket | code signature |
| Other macOS users | any | root broker socket | uid, forwarded identity |
| Cloud (AWS, GCP, Azure) | short-lived credentials | OIDC federation with enclave-signed JWTs | issuer + audience |

## Approved scope

### Original slices
1. **v0 CLI.** `init`, `keygen`, `sign`, `verify`, `secret set/get/ls/rm/import/export`, `run --`, policy
   file, hash-chained audit log, device identity. Direct enclave calls, same user.
2. **v1 LaunchAgent.** Per-user agent in the GUI session: RPC unix socket with peer code-signature
   identification, approval broker with caching over LocalAuthentication, SSH agent frontend, audit
   head signing, `safeski agent install`.
3. **v2 root broker.** System LaunchDaemon owning `/var/run/safeski/broker.sock`, forwarding to the
   owning user's agent with the real caller's identity, so cross-user policy and prompts work.

### Ocean bets (1–4)
1. **Secretless proxy.** Route-based local HTTP proxy: the agent gets a session URL, safeski injects
   the credential, enforces per-route request rules, counts budget, streams responses, audits.
2. **OIDC federation.** Enclave-signed ES256 JWTs, JWKS/discovery publishing, exchange for AWS, GCP,
   and Azure credentials. No long-lived cloud keys on the Mac.
3. **Sync-ready keystore.** Multi-recipient envelopes keyed by device id, device enrollment with
   signed records, `device reshare`. Transport for sync is deferred; the format is ready.
4. **PKCS#11 module.** Dynamic library presenting enclave keys as a token to OpenSSL, OpenSC, Java,
   ssh-keygen -D, VPN clients. No Apple account needed, unlike CryptoTokenKit.

### Deferred (documented, not built)
CryptoTokenKit and passkey providers (need a signed app bundle), Managed Device Attestation via MDM,
threshold signing across devices, TPM/YubiKey/KMS backends, sync transport, menu bar UI, PAM module,
supply-chain signing integrations, central policy server.

## Architecture

```
safeski (one binary)
├── SafeskiCore               library
│   ├── Enclave/              P-256 enclave keys, access control, encodings
│   ├── Store/                device identity, keys, secrets, envelopes (files under ~/.safeski)
│   ├── Policy/               policy.toml parser, caller rules, approval modes
│   ├── Identity/             peer uid/pid/path/code-signature from unix sockets
│   ├── Approval/             approval cache + LocalAuthentication prompts
│   ├── Audit/                hash-chained JSONL, head signed by the device key
│   ├── RPC/                  length-prefixed JSON over unix sockets; server, client, framing
│   ├── Service.swift         the policy-enforcing facade every frontend calls
│   ├── SSHAgent/             ssh-agent protocol frontend
│   ├── Proxy/                secretless HTTP proxy
│   ├── OIDC/                 JWT, JWKS, cloud federation
│   └── Broker/               root broker
├── safeski                   CLI + `agent start` daemon entry point
├── SafeskiPKCS11             libsafeski-pkcs11.dylib
└── clients/                  python, node, shell clients for containers
```

Every operation flows: caller identity → policy decision → approval (cached, prompt, biometric) →
audit → enclave. Frontends never touch the store directly; they call `Service`.
