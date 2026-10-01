#!/usr/bin/env node
'use strict';
/**
 * safeski client for Linux containers (and anywhere else without the Swift CLI).
 *
 * No dependencies. Talks the agent's RPC protocol over a unix socket:
 * 4-byte big-endian length prefix + JSON {id, method, params, token}.
 *
 *   const { Client } = require('./safeski');
 *   const c = new Client();                       // SAFESKI_SOCKET / SAFESKI_TOKEN from env
 *   const key = await c.getSecret('ANTHROPIC_API_KEY');   // Buffer
 *   const sig = await c.sign('deploy', Buffer.from('payload'));  // Buffer (raw r||s)
 *   await c.listKeys(); await c.status(); c.close();
 *
 * CLI:  node safeski.js get NAME | sign KEY FILE | status | keys | whoami
 */
const net = require('net');
const fs = require('fs');

const DEFAULT_SOCKET = '/run/safeski/agent.sock';

class SafeskiError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
    this.rpcMessage = message;
  }
}

class Client {
  constructor({ socket, token, timeout } = {}) {
    this.socketPath = socket || process.env.SAFESKI_SOCKET || DEFAULT_SOCKET;
    this.token = token !== undefined ? token : process.env.SAFESKI_TOKEN;
    this.timeout = timeout || 120000;
    this._sock = null;
    this._nextId = 1;
    this._buf = Buffer.alloc(0);
    this._pending = [];   // resolve/reject pairs in request order (requests are serialized)
  }

  _connect() {
    if (this._sock) return Promise.resolve(this._sock);
    return new Promise((resolve, reject) => {
      const s = net.createConnection(this.socketPath);
      s.setTimeout(this.timeout);
      s.once('connect', () => { this._sock = s; resolve(s); });
      s.once('error', (e) => { if (!this._sock) reject(e); else this._fail(e); });
      s.on('timeout', () => this._fail(new SafeskiError('rpc', 'timeout')));
      s.on('close', () => { this._sock = null; this._fail(new SafeskiError('rpc', 'agent closed connection')); });
      s.on('data', (d) => this._onData(d));
    });
  }

  _fail(err) {
    const p = this._pending; this._pending = [];
    for (const { reject } of p) reject(err);
  }

  _onData(d) {
    this._buf = Buffer.concat([this._buf, d]);
    while (this._buf.length >= 4) {
      const n = this._buf.readUInt32BE(0);
      if (this._buf.length < 4 + n) return;
      const body = this._buf.subarray(4, 4 + n).toString('utf8');
      this._buf = this._buf.subarray(4 + n);
      const waiter = this._pending.shift();
      if (!waiter) continue;
      let resp;
      try { resp = JSON.parse(body); } catch (e) { waiter.reject(new SafeskiError('rpc', 'bad frame')); continue; }
      if (resp.error) waiter.reject(new SafeskiError(resp.error.code || 'rpc', resp.error.message || ''));
      else waiter.resolve(resp.result === undefined ? null : resp.result);
    }
  }

  /** Raw RPC call. Resolves with `result`; rejects with SafeskiError on `error`. */
  async call(method, params) {
    const s = await this._connect();
    const req = { id: this._nextId++, method, params: params || {} };
    if (this.token) req.token = this.token;
    const body = Buffer.from(JSON.stringify(req), 'utf8');
    const header = Buffer.alloc(4); header.writeUInt32BE(body.length, 0);
    return new Promise((resolve, reject) => {
      this._pending.push({ resolve, reject });
      s.write(Buffer.concat([header, body]));
    });
  }

  close() { if (this._sock) { this._sock.destroy(); this._sock = null; } }

  status() { return this.call('status'); }
  whoami() { return this.call('whoami'); }
  listSecrets() { return this.call('secrets.list'); }
  listKeys() { return this.call('keys.list'); }
  getKey(name) { return this.call('keys.get', { name }); }
  async publicKey(name) { return Buffer.from((await this.getKey(name)).publicKey, 'base64'); }
  async getSecret(name, purpose) {
    const params = { name }; if (purpose) params.purpose = purpose;
    const r = await this.call('secrets.get', params);
    return Buffer.from(r.value, 'base64');
  }
  async sign(key, data, digest = false, purpose) {
    const params = { key, data: Buffer.from(data).toString('base64'), digest: !!digest };
    if (purpose) params.purpose = purpose;
    const r = await this.call('keys.sign', params);
    return Buffer.from(r.signature, 'base64');
  }
}

module.exports = { Client, SafeskiError, DEFAULT_SOCKET };

async function main(argv) {
  const [cmd, ...args] = argv;
  if (!cmd || cmd === '-h' || cmd === '--help') {
    process.stderr.write('usage: safeski.js get NAME [PURPOSE] | sign KEY FILE|- [--digest] | status | keys | secrets | whoami\n');
    return 2;
  }
  const c = new Client();
  try {
    if (cmd === 'get') {
      if (!args[0]) { process.stderr.write('usage: safeski.js get NAME [PURPOSE]\n'); return 2; }
      process.stdout.write(await c.getSecret(args[0], args[1]));
      if (process.stdout.isTTY) process.stdout.write('\n');
    } else if (cmd === 'sign') {
      if (args.length < 2) { process.stderr.write('usage: safeski.js sign KEY FILE|- [--digest]\n'); return 2; }
      const data = args[1] === '-' ? fs.readFileSync(0) : fs.readFileSync(args[1]);
      process.stdout.write((await c.sign(args[0], data, args.includes('--digest'))).toString('base64') + '\n');
    } else if (cmd === 'status' || cmd === 'whoami') {
      console.log(JSON.stringify(await c.call(cmd), null, 2));
    } else if (cmd === 'keys') {
      for (const k of await c.listKeys()) console.log(`${k.name}\t${k.kind}\t${k.access}`);
    } else if (cmd === 'secrets') {
      for (const s of await c.listSecrets()) console.log(`${s.name}\t${s.contentType}`);
    } else {
      process.stderr.write(`unknown command ${cmd}\n`); return 2;
    }
    return 0;
  } catch (e) {
    process.stderr.write(e instanceof SafeskiError ? `safeski: ${e.message}\n` : `safeski: cannot reach agent at ${c.socketPath}: ${e.message}\n`);
    return 1;
  } finally {
    c.close();
  }
}

if (require.main === module) main(process.argv.slice(2)).then((code) => process.exit(code));
