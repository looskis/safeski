# The broker: cross-user access

Each user's agent runs in that user's GUI session (it has to: Touch ID and approval
prompts only work there) and listens on a `0600` socket in the user's runtime dir. Another
macOS user, or a system service, cannot reach it. The **broker** is a root LaunchDaemon
that owns a world-connectable socket and forwards each connection to the right user's
agent, telling the agent who the real caller is. The broker audits nothing; the owner's
agent audits every request with the forwarded identity and applies the owner's policy, so
the owner gets the approval prompt (in their session) for the other user's request.

```
alice's shell ──▶ /var/run/safeski/broker.sock (root broker)
                     │ 1. LOCAL_PEERCRED/PEERPID/PEERTOKEN: uid 502, pid, path, code signature
                     │ 2. hello {"method":"_broker.connect","params":{"user":"bob"}}
                     │ 3. registry /var/run/safeski/agents/501 -> /Users/bob/.safeski/run/agent.sock
                     ▼
                  bob's agent  ◀── 4. {"method":"_broker.hello","params":{"caller":{uid:502,...,"transport":"broker"}}}
                                   5. frames pumped both ways; bob's policy + prompts + audit apply
```

## Protocol

* Client → broker, first frame: `{"id":0,"method":"_broker.connect","params":{"user":"<uid or name>"}}`.
  `user` is optional and defaults to the caller's own uid. The broker replies
  `{"id":0,"result":{"uid":N}}` or an error (`not_found` when that user has no running
  agent; `denied` when the registry entry is untrusted). After that the connection is a
  transparent pipe to the agent.
* Broker → agent, first frame: `{"id":0,"method":"_broker.hello","params":{"caller":{...}}}`
  where `caller` is the real peer's `CallerIdentity` (uid, gid, pid, path, signingID,
  teamID, signatureValid, commandLine, parentPath) with `transport = "broker"`. The agent
  only accepts this from uid 0 (plus `SAFESKI_BROKER_TRUST_UID`, see testing) and replies
  `{"id":0,"result":true}`; any other peer gets `denied`. A `_broker.hello` that is not the
  first frame is an unknown method. The forwarded transport is always forced to `broker`,
  so a forwarded identity can never look like `unix` or `local`.
* The CLI uses this automatically: `SAFESKI_USER=bob safeski secret get X` goes through
  the broker to bob's agent. With no `SAFESKI_USER`, if your own agent socket is not
  reachable but the broker is, the CLI reaches your own agent through the broker; if the
  broker knows no agent for you it falls back to in-process (`--local`) mode.

## Registry

`/var/run/safeski/agents/<uid>` is a `0644` file containing the agent socket path, written
by each user's agent at start (`BrokerFrontend`) and removed at stop. The directory is
`1777` (sticky) so every user can write only their own entry. The broker trusts an entry
only if it is a regular file (no symlinks) **owned by that uid** and the socket it names is
owned by that uid too. `safeski broker status` lists entries and whether each agent is up.

## Policy

Rules match the forwarded identity, so an owner can write in `policy.toml`:

```toml
[secrets.SHARED_DEPLOY_KEY]
rules = [
  { uid = 502, path = "/usr/local/bin/deploy", approve = "once", ttl = 3600 },
  { uid = 502, approve = "deny" },
]
```

`require_valid_signature = true` applies to `broker` callers exactly as to `unix` ones. Owner
only operations (`audit.tail`, `policy.reload`, key/secret creation and deletion) stay owner
only: a broker caller with a different uid is refused regardless of policy.

## Install (never done automatically)

```
safeski broker install --out dev.safeski.broker.plist   # prints the plist + the sudo steps
sudo mkdir -p /usr/local/libexec/safeski
sudo install -m 0755 -o root -g wheel "$(which safeski)" /usr/local/libexec/safeski/safeski
sudo mkdir -p -m 0755 /var/run/safeski && sudo mkdir -p /var/run/safeski/agents && sudo chmod 1777 /var/run/safeski/agents
sudo install -m 0644 -o root -g wheel dev.safeski.broker.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.safeski.broker.plist
safeski agent uninstall && safeski agent install    # re-register with the broker
safeski broker status
```

`safeski broker uninstall` prints the matching teardown. The plist runs
`safeski broker start` as root with `KeepAlive`; `broker start` recreates
`/var/run/safeski` (0755) and `agents` (1777) on every start, since `/var/run` is cleared at
boot.

## Environment

| Variable | Read by | Meaning |
|---|---|---|
| `SAFESKI_USER` | CLI | Route through the broker to this user's agent (uid or name). Error if the broker is down. |
| `SAFESKI_BROKER_SOCKET` | CLI, `broker start/status` | Broker socket (default `/var/run/safeski/broker.sock`). |
| `SAFESKI_BROKER_REGISTRY` | agent, `broker start/status` | Registry dir (default `/var/run/safeski/agents`). |
| `SAFESKI_BROKER_TRUST_UID` | agent | **Test only.** Also accept `_broker.hello` from this uid, so a non-root broker can be exercised. Never set this on a real agent. |

## Testing without root

```
export SAFESKI_HOME=/tmp/ssk-home SAFESKI_RUNTIME_DIR=/tmp/ssk-brk
export SAFESKI_BROKER_SOCKET=/tmp/ssk-brk/broker.sock SAFESKI_BROKER_REGISTRY=/tmp/ssk-brk/reg
mkdir -p $SAFESKI_BROKER_REGISTRY
SAFESKI_BROKER_TRUST_UID=$(id -u) safeski agent start --headless &
safeski broker start --allow-non-root --socket $SAFESKI_BROKER_SOCKET --registry $SAFESKI_BROKER_REGISTRY &
SAFESKI_USER=$(id -u) safeski whoami        # transport: broker
```

`Tests/SafeskiCoreTests/BrokerTests.swift` does the same in-process.
