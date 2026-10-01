# Threat model

## What safeski protects against

- **Credential files on disk.** No plaintext tokens, no `~/.ssh/id_*` private keys, no `.env`
  files. Every secret is an AES-GCM envelope whose key is wrapped to an enclave key. Every signing
  key is either an enclave key (wrapped blob, device-bound) or a software key stored as such an
  envelope.
- **Exfiltration of signing keys.** Enclave keys cannot be exported, even by root, even by reading
  the blob: the blob is only useful to the enclave on this device.
- **Unrestricted use by a compromised or over-eager process.** Every use goes through policy keyed
  on the caller's code identity, parent, uid, or token; prompts and biometric binding put a human in
  the loop; the proxy lets an AI agent call an API without ever holding the token.
- **Silent use.** The audit log is hash-chained and its head is periodically signed by the device
  identity key, so deletions and edits are detectable.
- **A compromised container.** Containers authenticate with revocable, expiring tokens that can only
  do what rules explicitly grant.

## What it does not protect against

- **A compromised GUI session acting as the user.** If malware runs as you, in your session, it can
  make the same requests you can. Policy and prompts raise the bar (a biometric-bound key still needs
  your finger) but a process that can read your screen and inject input can approve prompts.
- **Secrets after release.** Tier-2 secrets handed to a process are plaintext in that process. Use
  the proxy wherever the consumer supports a base-URL override so the secret never leaves safeski.
- **Device loss without re-enrollment.** Enclave keys die with the device. Software keys and secrets
  survive only if another enrolled device holds the envelopes.
- **Root on the host, fully.** Root can read envelopes and blobs, but cannot use enclave keys bound to
  biometrics without the user, and cannot extract key material. Root can read the vault key's blob and
  decrypt secrets whose vault access policy is `none`. Choose `--vault-access biometry-any` at `init`
  if that matters to you; every secret read will then prompt.
- **Kernel or enclave vulnerabilities.** Out of scope.

## Trust boundaries

```
 caller process ──unix socket──▶ agent (user session) ──▶ enclave
                 peer uid/pid/code-sig      policy + approval + audit

 container ──bind-mounted socket + token──▶ agent
 other user ──broker (root)──forwarded identity──▶ owner's agent ──▶ prompt on owner's screen
 AI agent ──session URL──▶ proxy ──injects secret──▶ upstream API
```

The agent trusts: the kernel's peer credentials, the Security framework's code-signature verdict,
`LocalAuthentication`, and the policy file (0600, owned by the user). It trusts the broker's
forwarded identity only when the peer is uid 0.

## Known weak spots

- Interpreted callers (node, python) are identified by the interpreter's signature plus the script
  path in argv, which a same-user process can forge. Prefer `approve = "once"` with a short ttl for
  those, or route them through the proxy with a session.
- `approve = "once"` caches by caller key, not by pid. A new process with the same path inherits
  the cached approval until ttl expires. Use `always` for anything sensitive.
- The policy file is reloaded on change; protecting it is the user's responsibility (it is 0600).
