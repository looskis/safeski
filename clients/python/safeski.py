#!/usr/bin/env python3
"""safeski client for Linux containers (and anywhere else without the Swift CLI).

Stdlib only. Talks the agent's RPC protocol over a unix socket:
4-byte big-endian length prefix + JSON {"id", "method", "params", "token"}.

    from safeski import Client
    c = Client()                       # SAFESKI_SOCKET / SAFESKI_TOKEN from the environment
    c.get_secret("ANTHROPIC_API_KEY")  # -> bytes
    c.sign("deploy", b"payload")       # -> raw r||s signature bytes
    c.list_keys(); c.status()

CLI:  python3 safeski.py get NAME | sign KEY FILE | status | keys | whoami
"""
import base64
import json
import os
import socket
import struct
import sys

DEFAULT_SOCKET = "/run/safeski/agent.sock"


class SafeskiError(Exception):
    def __init__(self, code, message):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


class Client(object):
    def __init__(self, socket=None, token=None, timeout=120.0):
        self.socket_path = socket or os.environ.get("SAFESKI_SOCKET") or DEFAULT_SOCKET
        self.token = token if token is not None else os.environ.get("SAFESKI_TOKEN")
        self.timeout = timeout
        self._sock = None
        self._next_id = 1

    # -- transport -------------------------------------------------------

    def _connect(self):
        if self._sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.socket_path)
            self._sock = s
        return self._sock

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                self.close()
                raise SafeskiError("rpc", "agent closed connection")
            buf += chunk
        return buf

    def call(self, method, params=None):
        """Raw RPC call. Returns the decoded `result`; raises SafeskiError on an `error`."""
        s = self._connect()
        req = {"id": self._next_id, "method": method, "params": params or {}}
        self._next_id += 1
        if self.token:
            req["token"] = self.token
        body = json.dumps(req, separators=(",", ":")).encode("utf-8")
        s.sendall(struct.pack(">I", len(body)) + body)
        (n,) = struct.unpack(">I", self._read_exact(4))
        resp = json.loads(self._read_exact(n).decode("utf-8"))
        if resp.get("error"):
            e = resp["error"]
            raise SafeskiError(e.get("code", "rpc"), e.get("message", ""))
        return resp.get("result")

    # -- API ---------------------------------------------------------------

    def status(self):
        return self.call("status")

    def whoami(self):
        return self.call("whoami")

    def get_secret(self, name, purpose=None):
        params = {"name": name}
        if purpose:
            params["purpose"] = purpose
        r = self.call("secrets.get", params)
        return base64.b64decode(r["value"])

    def list_secrets(self):
        return self.call("secrets.list")

    def list_keys(self):
        return self.call("keys.list")

    def get_key(self, name):
        return self.call("keys.get", {"name": name})

    def public_key(self, name):
        """Public key bytes (X9.63 for P-256 enclave keys, raw 32 bytes for Ed25519/X25519)."""
        return base64.b64decode(self.get_key(name)["publicKey"])

    def sign(self, key, data, digest=False, purpose=None):
        params = {"key": key, "data": base64.b64encode(data).decode("ascii"), "digest": bool(digest)}
        if purpose:
            params["purpose"] = purpose
        r = self.call("keys.sign", params)
        return base64.b64decode(r["signature"])



def _main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write(__doc__)
        return 2
    cmd, args = argv[1], argv[2:]
    c = Client()
    try:
        if cmd == "get":
            if not args:
                sys.stderr.write("usage: safeski.py get NAME [PURPOSE]\n"); return 2
            sys.stdout.buffer.write(c.get_secret(args[0], args[1] if len(args) > 1 else None))
            if sys.stdout.isatty():
                sys.stdout.write("\n")
        elif cmd == "sign":
            if len(args) < 2:
                sys.stderr.write("usage: safeski.py sign KEY FILE|- [--digest]\n"); return 2
            data = sys.stdin.buffer.read() if args[1] == "-" else open(args[1], "rb").read()
            sys.stdout.write(base64.b64encode(c.sign(args[0], data, digest="--digest" in args)).decode("ascii") + "\n")
        elif cmd == "status":
            print(json.dumps(c.status(), indent=2, sort_keys=True))
        elif cmd == "whoami":
            print(json.dumps(c.whoami(), indent=2, sort_keys=True))
        elif cmd == "keys":
            for k in c.list_keys():
                print("%s\t%s\t%s" % (k["name"], k["kind"], k["access"]))
        elif cmd == "secrets":
            for s in c.list_secrets():
                print("%s\t%s" % (s["name"], s["contentType"]))
        else:
            sys.stderr.write("unknown command %r\n" % cmd); return 2
    except SafeskiError as e:
        sys.stderr.write("safeski: %s\n" % e)
        return 1
    except (OSError, socket.error) as e:
        sys.stderr.write("safeski: cannot reach agent at %s: %s\n" % (c.socket_path, e))
        return 1
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
