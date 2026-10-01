# Containers

Docker Desktop, OrbStack, colima and Apple's `container` run Linux VMs. A unix socket on
the Mac can be bind-mounted into a container (Docker Desktop and OrbStack forward unix
sockets through the VM), so the agent socket is reachable from inside. What does **not**
survive the VM boundary is the peer credential: every connection arrives from the VM's
proxy, not from the real process. Container callers therefore authenticate with a
**safeski token**, and policy rules match on `token = "NAME"`.

## 1. Create a token and grant it rules

```sh
eval "$(safeski token create docker-dev --expires 7d --export)"   # sets SAFESKI_TOKEN in this shell
```

`safeski token create NAME` appends `[tokens.NAME]` (the SHA-256 of the token) to
`policy.toml` and prints the token **once**; with `--export` it prints
`export SAFESKI_TOKEN=ssk_...` ready for `eval`. safeski never stores the token value, so the
value must come from your shell (`SAFESKI_TOKEN`) or `--token-value` whenever a command needs it.

Then grant it something, e.g. in `policy.toml`:

```toml
[secrets.ANTHROPIC_API_KEY]
rules = [{ token = "docker-dev", approve = "never" }]

[keys.deploy]
rules = [{ token = "docker-dev", approve = "once", ttl = 3600 }]   # prompts you on the Mac once per hour
```

A token with no matching rule is denied (`no rule for token docker-dev on secret '...'`),
and a token that is unknown or expired is rejected before policy runs.

## 2. Run the container

```sh
safeski docker env --token docker-dev
#  -v /Users/me/.safeski/run/agent.sock:/run/safeski/agent.sock -e SAFESKI_SOCKET=/run/safeski/agent.sock -e SAFESKI_TOKEN=ssk_...

docker run $(safeski docker env --token docker-dev) -v $PWD/clients/python:/c python:3-alpine python3 /c/safeski.py get ANTHROPIC_API_KEY
# or let safeski inject the flags:
safeski docker run --token docker-dev -- docker run --rm -v $PWD/clients/python:/c python:3-alpine python3 /c/safeski.py get ANTHROPIC_API_KEY
```

`safeski docker env` warns if the token is not in `policy.toml` or has no rules. Options:
`--socket` (host socket, default `$SAFESKI_SOCKET` or the agent's runtime socket),
`--container-socket` (default `/run/safeski/agent.sock`), `--token-value`.

`safeski docker compose-snippet` prints the `volumes:`/`environment:` block for
docker-compose; it references `${SAFESKI_TOKEN}` so the token still comes from your shell.

## 3. Inside the container

No Swift needed. `clients/` has dependency-free clients (see `clients/README.md`):

```sh
python3 safeski.py get ANTHROPIC_API_KEY        # Python stdlib
node safeski.js get ANTHROPIC_API_KEY           # Node, no deps
safeski-get ANTHROPIC_API_KEY                   # POSIX sh wrapper
```

They read `SAFESKI_SOCKET` and `SAFESKI_TOKEN` and speak the agent's framed JSON RPC
(4-byte big-endian length + JSON, `{"id","method","params","token"}`).

Inside the container `safeski whoami` style calls report `transport: token`,
`token: docker-dev`; the audit log on the Mac records the same.

## SSH agent forwarding

Docker Desktop (and OrbStack) forward the **host's** `SSH_AUTH_SOCK` to a magic path:

```sh
eval "$(safeski agent env)"       # SSH_AUTH_SOCK now points at safeski's ssh socket
safeski docker ssh-env
#  -v /run/host-services/ssh-auth.sock:/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent
```

so `ssh`/`git` inside the container use enclave keys through the normal SSH agent protocol,
with approvals on the Mac. For colima / Apple `container`, mount the ssh socket directly
(`-v ~/.safeski/run/ssh.sock:/ssh-agent`). SSH-agent connections are identified as the VM
proxy, so write policy for them by `path` of the proxy or by using the token path for
secrets.

## Security notes

* The socket inside the container gives access to **everything the token is allowed**;
  treat `SAFESKI_TOKEN` like a credential (short `--expires`, one token per project, `safeski token rm`).
* Keep `approve = "once"` or `"always"` on anything sensitive so container use still
  prompts on the Mac.
* `docker run -e SAFESKI_TOKEN=...` makes the value visible in `docker inspect`; prefer
  `--env-file` or compose `${SAFESKI_TOKEN}` when that matters.
