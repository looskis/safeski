# safeski clients (no Swift required)

Small, dependency-free clients for the agent's RPC socket. They are meant for Linux
containers that have the Mac agent socket bind-mounted in, but they work anywhere the
socket is reachable.

| Client | File | Needs |
|---|---|---|
| Python | `python/safeski.py` | Python 3 stdlib |
| Node | `node/safeski.js` | Node 14+ (`net` module), CommonJS |
| Shell | `shell/safeski-get` | POSIX sh + python3 (or node) |

All read `SAFESKI_SOCKET` (default `/run/safeski/agent.sock`) and `SAFESKI_TOKEN`.
Inside a container the token is **required**: unix peer credentials do not survive the
VM boundary, so the agent identifies the caller by its token and applies policy rules
like `{ token = "docker-dev", approve = "never" }`. See `docs/containers.md`.

## Protocol

One unix stream connection; each message is a 4-byte big-endian length followed by JSON.

```
-> {"id":1,"method":"secrets.get","params":{"name":"API_KEY"},"token":"ssk_..."}
<- {"id":1,"result":{"value":"<base64>","contentType":"text"}}
<- {"id":1,"error":{"code":"denied","message":"..."}}
```

Methods used by the clients: `status`, `whoami`, `secrets.list`, `secrets.get`,
`keys.list`, `keys.get`, `keys.sign` (`{"key","data":<base64>,"digest":bool,"purpose"?}` ->
`{"signature":<base64 raw r||s>}`). Binary fields are base64.

## Python

```python
from safeski import Client
c = Client()                                  # or Client(socket="/path", token="ssk_...")
print(c.get_secret("ANTHROPIC_API_KEY").decode())
sig = c.sign("deploy", open("artifact.tar", "rb").read())
print(c.list_keys(), c.status())
```

CLI: `python3 safeski.py get NAME`, `sign KEY FILE|- [--digest]`, `status`, `keys`, `secrets`, `whoami`.

## Node

```js
const { Client } = require('./safeski');
const c = new Client();
const key = (await c.getSecret('ANTHROPIC_API_KEY')).toString();
const sig = await c.sign('deploy', fs.readFileSync('artifact.tar'));
c.close();
```

CLI: `node safeski.js get NAME`, `sign KEY FILE|-`, `status`, `keys`, `secrets`, `whoami`.

## Shell

`safeski-get NAME [PURPOSE]` prints the secret; it execs the Python client (or Node as a
fallback). Example in a Dockerfile:

```dockerfile
COPY clients/python/safeski.py clients/shell/safeski-get /usr/local/bin/
RUN chmod +x /usr/local/bin/safeski-get
```

then `export API_KEY="$(safeski-get API_KEY)"` at runtime.
