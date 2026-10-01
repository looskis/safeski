# safeski

Secure Enclave-backed keys and secrets for your shell, AI agents, containers, other users, and
apps, on macOS. One ad-hoc-signed binary, no Apple Developer account, no keychain.

- **Enclave keys** for SSH, git commit signing, JWTs, and PKCS#11. The private key never leaves
  the hardware, even from root.
- **Secrets** (API keys, tokens) encrypted at rest under an enclave key, released only to callers
  that policy allows, with Touch ID or a prompt when you want one.
- **Secretless proxy**: point Claude Code or any SDK at a local URL and safeski injects the
  credential per request, enforces per-route rules, counts budget, streams, and audits. The agent
  never holds the key.
- **OIDC federation**: enclave-signed ES256 JWTs exchanged for short-lived AWS, GCP, and Azure
  credentials. No long-lived cloud keys on the Mac.
- **Containers and other users**: bind-mount the socket into Docker or OrbStack with a revocable
  token; a root broker routes other macOS users to the owner's agent, prompts included.
- **Audit**: hash-chained log, head signed by the device's enclave identity key.

See [SCOPE.md](SCOPE.md) for what the enclave can and cannot do and why there are two tiers.

## Quick start

```bash
scripts/install.sh                 # builds, installs to ~/.local/bin, installs the LaunchAgent
safeski init
eval "$(safeski agent env)"        # SAFESKI_SOCKET and SSH_AUTH_SOCK
safeski keygen github --access biometry-any --comment you@example.com
safeski ssh setup                  # ~/.ssh/config snippet + git signing commands
printf '%s' "$ANTHROPIC_API_KEY" | safeski secret set ANTHROPIC_API_KEY
safeski run -s ANTHROPIC_API_KEY -- claude          # inject as an env var, or:
safeski proxy run --route anthropic -- claude       # never hand the key to the agent at all
safeski audit tail
```

Policy lives in `~/.safeski/policy.toml`. `safeski whoami` shows how the agent sees your shell so
you can write rules against it. See [docs/policy.md](docs/policy.md).

## How it fits together

```
 ssh / git ───ssh-agent socket───▶┐
 claude / scripts ───RPC socket──▶│  agent (per user, GUI session)
 OpenSSL / Java ───PKCS#11 dylib─▶│   policy → approval → audit → enclave
 SDKs ───proxy session URL───────▶│   secretless proxy, OIDC issuer
 containers ───socket + token────▶│
 other users ───root broker──────▶┘
```

Every operation flows through `Service`: identify the caller (uid, pid, executable, code
signature, parent, or token), evaluate first-match rules, run approval (silent, cached prompt,
every time, or biometric), append to the audit log, then touch the enclave.

## Commands

| Area | Commands |
|---|---|
| Device | `init`, `status`, `whoami`, `device show|enroll|ls|rm|reshare` |
| Keys | `keygen`, `keys`, `pubkey`, `sign`, `verify` |
| Secrets | `secret set|get|ls|rm|import|export`, `run -s NAME -- cmd` |
| Agent | `agent start|install|uninstall|status|env` |
| Policy, audit | `policy show|check|reload|path`, `audit tail|verify`, `token create|ls|rm` |
| SSH, git | `ssh keys|setup|allowed-signers|env` |
| Proxy | `proxy status|routes|session create|session ls|session revoke|run` |
| OIDC | `oidc setup|token|decode|jwks|discovery|publish|aws|gcp|gcp-executable|azure` |
| PKCS#11 | `pkcs11 path|test|setup` |
| Broker | `broker start|install|status|uninstall` |
| Containers | `docker env|run|compose-snippet|ssh-env` |

## Docs

- [SCOPE.md](SCOPE.md): enclave facts, the two tiers, consumers, approved and deferred scope
- [docs/policy.md](docs/policy.md): policy file reference
- [docs/threat-model.md](docs/threat-model.md): what it does and does not protect against
- [docs/broker.md](docs/broker.md): cross-user access
- [docs/containers.md](docs/containers.md): Docker, OrbStack, Apple container, and the Linux clients
- [clients/README.md](clients/README.md): python, node, and shell clients

## Building

Swift 6.4 and the Xcode Command Line Tools are enough; no Xcode needed.

```bash
swift build -c release
swift test
make build sign install PREFIX=~/.local
```

Tests use Swift Testing. `Package.swift` points the compiler at the Command Line Tools' Testing
macro plugin, which the toolchain does not load on its own.

## Key facts about the enclave

- P-256 only. SSH keys are `ecdsa-sha2-nistp256`; Ed25519 keys are software keys stored as
  envelopes encrypted to the enclave.
- Keys are device-bound and non-exportable. Enroll a second device (`safeski device enroll`) if
  you need secrets and software keys to survive a lost Mac. Enclave keys do not.
- Prompts need a GUI session. The agent runs as a per-user LaunchAgent for that reason; the root
  broker only forwards.
