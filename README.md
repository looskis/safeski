# safeski

**Put the Mac's Secure Enclave in front of every credential on the machine.** SSH keys, git
signing keys, API tokens, and cloud credentials live behind the chip, and each use goes through
policy, an optional Touch ID prompt, and an audit log. One ad-hoc-signed binary, no Apple
Developer account, no keychain.

```bash
git clone https://github.com/looskis/safeski && cd safeski
scripts/install.sh                                  # build, install to ~/.local/bin, start the agent
safeski init
safeski keygen github --access biometry-any         # an SSH key that never leaves the enclave
printf '%s' "$ANTHROPIC_API_KEY" | safeski secret set ANTHROPIC_API_KEY
safeski proxy run --route anthropic -- claude       # Claude Code calls the API without ever holding the key
```

The last line needs an `anthropic` route in the policy file; see [Secrets for agents and scripts](#secrets-for-agents-and-scripts).

## What it is

`safeski` is a per-user agent plus a CLI. The agent owns a set of keys and secrets and decides,
per caller, who may use which one.

- **Enclave keys** for SSH, git commit signing, JWTs, and PKCS#11. The private key never leaves
  the hardware, even from root.
- **Secrets** (API keys, tokens, `.env` values) encrypted at rest under an enclave key and
  released only to callers that policy allows.
- **Secretless proxy.** Point Claude Code or any SDK at a local session URL. safeski injects the
  credential per request, enforces per-route rules and budgets, streams responses, and audits.
  The agent process never sees the key.
- **OIDC federation.** Enclave-signed ES256 JWTs exchanged for short-lived AWS, GCP, and Azure
  credentials, so no long-lived cloud keys sit on the Mac.
- **Containers and other users.** Bind-mount the socket into Docker or OrbStack with a revocable
  token. A root broker routes other macOS users to the owner's agent, and the owner gets the prompt.
- **Audit.** A hash-chained log whose head is signed by the device's enclave identity key.

Callers are identified by what the kernel and the Security framework report: uid, pid,
executable path, code-signing identifier, Team ID, and parent process. `safeski whoami` prints
exactly what the agent sees for your shell, which is the easiest way to write a rule.

## Status

v0.1.0. New, and not independently audited. Treat it as a tool to evaluate, not yet one to bet
production credentials on.

| Verified on a real Mac (Apple silicon) | Not yet exercised |
|---|---|
| Enclave keygen, signing, envelopes, policy, audit chain | Live AWS, GCP, and Azure token exchange (request construction is tested; `--dry-run` prints it) |
| SSH agent with `ssh-add`, `ssh-keygen -Y sign/verify`, signed git commits | The broker as a real root LaunchDaemon (tested end to end as a normal user) |
| Proxy header injection, rule denies, budgets, incremental SSE streaming | Socket mounts inside Docker, OrbStack, or Apple `container` (clients tested on the host) |
| PKCS#11 against OpenSC `pkcs11-tool`, OpenSSL verification, `ssh-keygen -D` | OpenSSL pkcs11-provider and Java SunPKCS11 |

See [docs/threat-model.md](docs/threat-model.md) for what it does and does not protect against.

## Install

Requires macOS 14+ on Apple silicon and the Xcode Command Line Tools with Swift 6. Full Xcode is
not needed. Intel Macs with a T2 chip have a Secure Enclave too, but are untested.

```bash
git clone https://github.com/looskis/safeski && cd safeski
scripts/install.sh                 # or: make build sign install PREFIX=~/.local
safeski init
eval "$(safeski agent env)"        # SAFESKI_SOCKET and SSH_AUTH_SOCK; add to your shell profile
```

`scripts/install.sh` installs a per-user LaunchAgent. It has to run in your GUI session, because
that is the only place macOS will show a Touch ID or approval prompt. A Homebrew formula for
[looskis/homebrew-tap](https://github.com/looskis/homebrew-tap) will follow the first tagged release.

## Use

### SSH and git signing

```bash
safeski keygen github --access biometry-any --comment you@example.com
safeski ssh setup                  # prints the ~/.ssh/config snippet and the git signing commands
safeski ssh keys                   # public keys to paste into GitHub
```

Enclave keys are P-256, so SSH keys are `ecdsa-sha2-nistp256`. Ed25519 keys are available as
software keys stored as envelopes encrypted to the enclave (`--kind software-ed25519`).

### Secrets for agents and scripts

```bash
safeski secret import .env                          # or: safeski secret set NAME
safeski run -s ANTHROPIC_API_KEY -- claude          # inject as an environment variable
safeski proxy run --route anthropic -- claude       # or keep the key out of the process entirely
```

The proxy is the stronger option wherever the consumer accepts a base-URL override. Routes,
injected headers, request rules, and budgets are declared in the policy file:

```toml
[proxy.routes.anthropic]
upstream = "https://api.anthropic.com"
env = "ANTHROPIC_BASE_URL"
headers = { "x-api-key" = "secret:ANTHROPIC_API_KEY" }
rules = [ { methods = ["POST"], path = "/v1/messages", approve = "never" } ]
budget = { requests = 1000, per = "1h" }
```

### Policy

Policy lives in `~/.safeski/policy.toml` and reloads when the file changes. Rules are first
match wins, and a resource with rules denies anyone who matches none of them.

```toml
[keys.github]
rules = [
  { path = "/usr/bin/ssh", approve = "never" },
  { parent = "**/git", approve = "never" },
]

[secrets.ANTHROPIC_API_KEY]
rules = [
  { parent = "**/claude", approve = "once", ttl = 3600 },
  { token = "docker-dev", approve = "never" },
]
```

Approval modes are `never` (silent), `once` (ask, then cache per caller), `always`, `touchid`,
and `deny`. Full reference: [docs/policy.md](docs/policy.md).

### Cloud credentials

```bash
safeski oidc setup --issuer https://oidc.example.com/my-mac --write
safeski oidc publish --dir ./site          # discovery + JWKS to host on S3 or GitHub Pages
safeski oidc aws --role-arn arn:aws:iam::123456789012:role/dev --print-config
```

### Containers, PKCS#11, other users

```bash
eval "$(safeski token create docker-dev --expires 7d --export)"
safeski docker run --token docker-dev -- docker run --rm -it python:3-alpine sh

safeski pkcs11 setup               # OpenSSL, pkcs11-tool, Java, and ssh configuration
safeski broker install             # prints the sudo steps for cross-user access
```

Python, Node, and shell clients for use inside containers are in [clients/](clients/README.md).

## How it fits together

```
 ssh / git ───ssh-agent socket───▶┐
 claude / scripts ───RPC socket──▶│  agent (per user, GUI session)
 OpenSSL / Java ───PKCS#11 dylib─▶│   policy → approval → audit → enclave
 SDKs ───proxy session URL───────▶│   secretless proxy, OIDC issuer
 containers ───socket + token────▶│
 other users ───root broker──────▶┘
```

Every frontend calls the same `Service` layer: identify the caller, evaluate rules, run approval,
append to the audit log, then touch the enclave. Nothing reaches the keystore any other way.

The enclave only holds P-256 keys and they cannot be exported or backed up. Secrets and software
keys are envelopes with one recipient per enrolled device, so `safeski device enroll` on a second
Mac lets them survive a lost machine. Enclave keys do not survive it; rotate those.

## Commands

| Area | Commands |
|---|---|
| Device | `init`, `status`, `whoami`, `device show\|enroll\|ls\|rm\|reshare` |
| Keys | `keygen`, `keys`, `pubkey`, `sign`, `verify` |
| Secrets | `secret set\|get\|ls\|rm\|import\|export`, `run -s NAME -- cmd` |
| Agent | `agent start\|install\|uninstall\|status\|env` |
| Policy, audit | `policy show\|check\|reload\|path`, `audit tail\|verify`, `token create\|ls\|rm` |
| SSH, git | `ssh keys\|setup\|allowed-signers\|env` |
| Proxy | `proxy status\|routes\|session create\|session ls\|session revoke\|run` |
| OIDC | `oidc setup\|token\|decode\|jwks\|discovery\|publish\|aws\|gcp\|gcp-executable\|azure` |
| PKCS#11 | `pkcs11 path\|test\|setup` |
| Broker | `broker start\|install\|status\|uninstall` |
| Containers | `docker env\|run\|compose-snippet\|ssh-env` |

## Docs

- [SCOPE.md](SCOPE.md): what the enclave can and cannot do, the two tiers, built and deferred scope
- [docs/policy.md](docs/policy.md): policy file reference
- [docs/threat-model.md](docs/threat-model.md): trust boundaries and known weak spots
- [docs/broker.md](docs/broker.md): cross-user access
- [docs/containers.md](docs/containers.md): Docker, OrbStack, Apple `container`, and the Linux-side clients

## Development

```bash
swift build
swift test                          # full suite needs a Mac with a Secure Enclave
SAFESKI_DISABLE_ENCLAVE=1 swift test   # reproduces CI, where no enclave exists: those tests skip
```

Tests use Swift Testing. On a Command Line Tools-only Mac, `Package.swift` points the compiler at
the Testing macro plugin, which that toolchain does not load on its own. For manual testing, set
`SAFESKI_HOME` and `SAFESKI_RUNTIME_DIR` to scratch directories so `~/.safeski` is never touched;
keep the runtime path short, since unix socket paths are limited to 104 bytes.

---

Part of [Looskis](https://github.com/looskis): open-source tools for Apple silicon.
