# Policy reference

Policy lives in `~/.safeski/policy.toml` (or `$SAFESKI_HOME/policy.toml`). The agent reloads it
whenever the file's modification time changes; `safeski policy reload` forces it. `safeski policy
check` parses and reports errors. `safeski policy show` prints the parsed tree as JSON.

## How a request is decided

1. The agent identifies the caller from the unix socket: uid, pid, executable path, code-signing
   identifier, Team ID, signature validity, parent executable, and best-effort argv. `safeski whoami`
   prints exactly what the agent sees for your shell, which is the easiest way to write a rule.
2. If the request carries a token (`SAFESKI_TOKEN` or the `token` field), the caller becomes that
   token and loses its code identity: token callers match only `token = "..."` rules.
3. The resource's rules are evaluated **first match wins**. A rule matches when every attribute it
   lists matches the caller.
4. The matched rule's `approve` mode decides: `never` allows silently, `deny` refuses, `once` asks
   the user and caches the answer for `ttl` seconds per caller and resource, `always` asks every
   time, `touchid` requires biometrics every time.
5. If the resource has rules but none matched, the request is denied. If it has no rules, the
   defaults apply, except that the owning user's in-process CLI (`--local`, or no agent running) is
   allowed without prompting.
6. The outcome is appended to the audit log before the enclave does any work.

Enclave access control (`access = "biometry-any"` and friends) is separate and is enforced by the
hardware on every use, regardless of policy.

## Sections

```toml
[defaults]
approve = "once"               # never | once | always | touchid | deny
ttl = 300                      # seconds an approval stays cached
deny_unmatched = false         # true: resources with no rules are denied for non-local callers
require_valid_signature = false # true: reject callers whose code signature fails validation

[keys.github-ssh]
access = "biometry-any"        # informational; set at keygen time
rules = [
  { path = "/usr/bin/ssh", approve = "never" },
  { path = "/usr/bin/git", approve = "never" },
  { parent = "**/claude", approve = "once", ttl = 3600 },
]

[secrets.ANTHROPIC_API_KEY]
rules = [
  { parent = "**/claude", approve = "once", ttl = 3600, comment = "Claude Code" },
  { token = "docker-dev", approve = "never" },
  { team_id = "ABCDE12345", approve = "always" },
]

[secrets."*"]                  # fallback rules for any secret without its own table
rules = [ { uid = 501, approve = "once" } ]

[tokens.docker-dev]            # written by `safeski token create docker-dev --expires 7d`
hash = "<sha256 of the token>"
expires = "2026-10-07T00:00:00Z"
```

### Rule attributes

| Attribute | Matches |
|---|---|
| `path` | executable path of the caller; globs: `*` within a path segment, `**` across segments, `?` one char, `~` expands |
| `parent` | the caller's parent executable, or for interpreters (node, python, ruby, bun, deno) the script in argv[1]; same globs |
| `team_id` | Apple Team ID from the code signature |
| `signing_id` | code-signing identifier (bundle id, or the binary name for ad-hoc signatures) |
| `uid` | numeric uid |
| `token` | the name of a token from `[tokens]` |
| `approve` | overrides `[defaults].approve` for this rule |
| `ttl` | overrides `[defaults].ttl` for this rule |

A rule with no matching attributes matches everyone. Use that as the last rule to set a default
for a resource.

### Tokens

Tokens are for callers that cannot be identified by peer credentials: processes inside containers,
and anything reached through a relay. `safeski token create NAME` prints the token once and stores
only its SHA-256 in `[tokens.NAME]`. A token can do only what rules naming it allow, and can never
create, write, or delete keys or secrets.

## Other sections

Modules read their own sections from the same file: `[proxy]` for the secretless proxy, `[oidc]`
for the identity provider, `[broker]` for cross-user access. See their docs.
