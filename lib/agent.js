'use strict';

// Agent identity: an AI agent authenticates with a key it holds (RFC 7523 private_key_jwt), gets
// its own token (client credentials), asks a person to let it act for them (OpenID CIBA), and
// exchanges a person's token for one that names both (RFC 8693). The private key never leaves the
// process; only signed, short-lived assertions do.

const crypto = require('crypto');
const fs = require('fs');
const { createDiscovery } = require('./discovery');
const { JoseError, signingAlgorithm, signCompact, thumbprint } = require('./jose');

const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

// The platform refuses an assertion that claims to live longer than five minutes.
const MAX_ASSERTION_LIFETIME = 300;

/** A refusal from an AuthFI endpoint. Branch on `error`, the OAuth error code, never on the text. */
class AgentAuthError extends Error {
  constructor(error, description, status) {
    super(error ? (description ? `${error}: ${description}` : error) : description);
    this.name = 'AgentAuthError';
    this.error = error || null;
    this.description = description || null;
    this.status = status;
  }
}

function keyError(e) {
  return new AgentAuthError('invalid_key', e.message, 400);
}

/** The JWK with every private member removed. */
function publicMembers(jwk) {
  const { d, p, q, dp, dq, qi, oth, k, ...pub } = jwk; // eslint-disable-line no-unused-vars
  return pub;
}

/**
 * An agent's signing key: Ed25519 (EdDSA), P-256 (ES256) or RSA 2048-4096 (PS256). The key type
 * decides the algorithm, as it does on the platform.
 */
class AgentKey {
  /** @param {crypto.KeyObject} privateKey @param {string} kid the kid registered with the public key */
  constructor(privateKey, kid) {
    try {
      this.alg = signingAlgorithm(privateKey);
    } catch (e) {
      throw e instanceof JoseError ? keyError(e) : e;
    }
    if (!kid || typeof kid !== 'string' || !kid.trim()) {
      throw new AgentAuthError('invalid_key', 'kid is required: it is the key id registered with the public key', 400);
    }
    Object.defineProperty(this, '_key', { value: privateKey, enumerable: false });
    this.kid = kid.trim();
  }

  /** Generates a key. Its kid defaults to the RFC 7638 thumbprint of the public key. */
  static generate(alg = 'EdDSA', { kid } = {}) {
    let pair;
    if (alg === 'EdDSA') pair = crypto.generateKeyPairSync('ed25519');
    else if (alg === 'ES256') pair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    else if (alg === 'PS256') pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    else throw new AgentAuthError('invalid_key', `Cannot generate ${alg}: use EdDSA, ES256 or PS256`, 400);
    const pub = pair.publicKey.export({ format: 'jwk' });
    return new AgentKey(pair.privateKey, kid || thumbprint(pub));
  }

  /** Loads a PKCS#8 (or SEC1 / PKCS#1) private key PEM. An encrypted key is refused. */
  static fromPem(pem, { kid } = {}) {
    const text = Buffer.isBuffer(pem) ? pem.toString('utf8') : String(pem || '');
    if (!/-----BEGIN ([A-Z]+ )?PRIVATE KEY-----/.test(text)) {
      const head = (text.match(/-----BEGIN ([A-Z0-9 ]+)-----/) || [])[1];
      throw new AgentAuthError('invalid_key', head
        ? `The agent key must be a private key PEM, but this is a ${head}`
        : 'The agent key is not a PEM private key', 400);
    }
    let key;
    try {
      key = crypto.createPrivateKey({ key: text, format: 'pem' });
    } catch (e) {
      throw new AgentAuthError('invalid_key', `The agent key is not a usable private key (an encrypted key is not supported): ${e.message}`, 400);
    }
    return new AgentKey(key, kid);
  }

  /** Loads a private JWK. Its own kid is used unless one is given. */
  static fromJwk(jwk, { kid } = {}) {
    const j = typeof jwk === 'string' ? JSON.parse(jwk) : jwk;
    if (!j || typeof j !== 'object' || !j.d) {
      throw new AgentAuthError('invalid_key', 'This JWK has no private component; signing needs the private key the agent holds', 400);
    }
    let key;
    try {
      key = crypto.createPrivateKey({ key: j, format: 'jwk' });
    } catch (e) {
      throw new AgentAuthError('invalid_key', `The JWK is not a usable private key: ${e.message}`, 400);
    }
    return new AgentKey(key, kid || j.kid);
  }

  /** Loads a key from a file holding a PEM or a private JWK. A file is the way to hold one. */
  static fromFile(path, { kid } = {}) {
    const raw = fs.readFileSync(path, 'utf8');
    if (!raw.trim()) throw new AgentAuthError('invalid_key', `The agent key file ${path} is empty`, 400);
    return raw.trimStart().startsWith('{') ? AgentKey.fromJwk(raw, { kid }) : AgentKey.fromPem(raw, { kid });
  }

  /** The public JWK to register. The only half of the key that ever leaves the process. */
  publicJwk() {
    const jwk = publicMembers(crypto.createPublicKey(this._key).export({ format: 'jwk' }));
    return { ...jwk, kid: this.kid, alg: this.alg, use: 'sig' };
  }

  /** The RFC 7638 thumbprint of the public key. */
  thumbprint() {
    return thumbprint(this.publicJwk());
  }

  /** The private key as PKCS#8 PEM, for writing to a 0600 file at bootstrap. */
  privatePem() {
    return this._key.export({ type: 'pkcs8', format: 'pem' });
  }

  /**
   * One RFC 7523 client assertion: iss and sub are the agent, aud the token endpoint, a fresh jti,
   * and a lifetime of at most five minutes (the platform refuses longer).
   */
  clientAssertion(agentId, audience, { lifetime = MAX_ASSERTION_LIFETIME } = {}) {
    if (!agentId) throw new AgentAuthError('invalid_request', 'agentId is required for a client assertion', 400);
    if (!audience) throw new AgentAuthError('invalid_request', 'audience is required for a client assertion', 400);
    if (!(lifetime > 0 && lifetime <= MAX_ASSERTION_LIFETIME)) {
      throw new AgentAuthError('invalid_request', `assertion lifetime must be 1 to ${MAX_ASSERTION_LIFETIME} seconds`, 400);
    }
    const iat = Math.floor(Date.now() / 1000);
    return signCompact(
      { alg: this.alg, typ: 'JWT', kid: this.kid },
      { iss: agentId, sub: agentId, aud: audience, jti: crypto.randomUUID(), iat, exp: iat + Math.floor(lifetime) },
      this.alg,
      this._key,
    );
  }

  toJSON() {
    return { kid: this.kid, alg: this.alg };
  }
}

/** Decodes a JWT's payload without verifying it, for the caller's information only. */
function unverifiedClaims(token) {
  try {
    return JSON.parse(Buffer.from(String(token).split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return {};
  }
}

/** When a token response's token expires: expires_in, else the token's own exp. */
function expiryOf(body) {
  if (Number(body.expires_in) > 0) return Date.now() + Number(body.expires_in) * 1000;
  const exp = Number(unverifiedClaims(body.access_token).exp);
  return exp > 0 ? exp * 1000 : Date.now();
}

function headersOf(input, init) {
  const headers = new Headers(typeof Request !== 'undefined' && input instanceof Request ? input.headers : undefined);
  new Headers(init && init.headers).forEach((v, k) => headers.set(k, v));
  return headers;
}

function urlOf(input) {
  return new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url);
}

/**
 * A fetch that sets `Authorization: Bearer <token>` from `source` on every request, so a long run
 * always sends a current token. It refuses to send the token to an origin not in `origins`, and it
 * removes x-api-key, which the AI gateway does not read.
 */
function bearerFetch(source, origins, baseFetch) {
  return async (input, init = {}) => {
    const url = urlOf(input);
    if (!origins.includes(url.origin)) {
      throw new AgentAuthError('invalid_target', `Refusing to send the AuthFI token to ${url.origin}; it is for ${origins.join(', ')}`, 0);
    }
    const headers = headersOf(input, init);
    headers.set('authorization', `Bearer ${await source.token()}`);
    headers.delete('x-api-key');
    return (baseFetch || globalThis.fetch)(input, { ...init, headers });
  };
}

/**
 * A token an agent holds for a person: `sub` is the person and `act.sub` the agent. A token from a
 * token exchange is renewed by exchanging again; a CIBA token cannot be, because only the person can
 * consent again.
 */
class DelegatedToken {
  constructor(body, { renew, origins, fetch: baseFetch, refreshSkew }) {
    this._set(body);
    Object.defineProperty(this, '_renew', { value: renew, enumerable: false });
    Object.defineProperty(this, '_skew', { value: refreshSkew, enumerable: false });
    this.fetch = bearerFetch(this, origins, baseFetch);
  }

  _set(body) {
    Object.defineProperty(this, 'accessToken', { value: body.access_token, enumerable: false, writable: true, configurable: true });
    this.expiresAt = expiryOf(body);
    this.scope = body.scope || null;
    this.issuedTokenType = body.issued_token_type || null;
    this.claims = unverifiedClaims(body.access_token);
  }

  /** The current token, renewed first when it is close to expiry and can be renewed. */
  async token() {
    if (Date.now() < this.expiresAt - this._skew * 1000) return this.accessToken;
    if (!this._renew) {
      if (Date.now() < this.expiresAt) return this.accessToken;
      throw new AgentAuthError('expired_token', 'This delegated token has expired; ask the person to approve again', 400);
    }
    if (!this._inflight) {
      Object.defineProperty(this, '_inflight', {
        value: this._renew().then((body) => { this._set(body); return this.accessToken; })
          .finally(() => { this._inflight = null; }),
        enumerable: false, writable: true, configurable: true,
      });
    }
    return this._inflight;
  }

  toJSON() {
    return { expiresAt: this.expiresAt, scope: this.scope, sub: this.claims.sub, act: this.claims.act };
  }
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(signal.reason || new Error('aborted'));
    const t = setTimeout(() => { if (signal) signal.removeEventListener('abort', onAbort); resolve(); }, ms);
    function onAbort() { clearTimeout(t); reject(signal.reason || new Error('aborted')); }
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * An agent's identity at one AuthFI project.
 *
 *   const agent = new AgentAuth({
 *     issuer: 'https://acme.authfi.io',
 *     agentId: 'agt_...',
 *     key: AgentKey.fromFile('/run/secrets/agent-key.pem', { kid: 'k1' }),
 *   });
 *   const token = await agent.token();
 *
 * Every endpoint comes from the project's authorization-server metadata. There is no default
 * issuer: an agent that guessed one would send its signed assertion to another project.
 */
class AgentAuth {
  constructor({ agentId, key, issuer, resource, fetch: baseFetch, refreshSkew = 60, allowedOrigins = [], onDeprecation } = {}) {
    if (!agentId || typeof agentId !== 'string') throw new AgentAuthError('invalid_request', 'agentId is required', 400);
    if (!(key instanceof AgentKey)) {
      throw new AgentAuthError('invalid_key', 'key must be an AgentKey: an agent authenticates with a key it holds, never a secret', 400);
    }
    if (!issuer) throw new AgentAuthError('invalid_request', 'issuer is required: the origin of the project this agent belongs to', 400);
    this.agentId = agentId.trim();
    this.key = key;
    this.resource = resource || null;
    this.refreshSkew = refreshSkew;
    this._fetch = baseFetch || null;
    this._discovery = createDiscovery({ issuer, fetch: baseFetch });
    this.issuer = this._discovery.issuer;
    this._origins = [new URL(this.issuer).origin, ...allowedOrigins.map((o) => new URL(o).origin)];
    this._onDeprecation = onDeprecation || null;
    this._warned = new Set();
    this._tokens = new Map(); // resource -> {accessToken, expiresAt, capabilities, scope}
    this._inflight = new Map();
    /** A fetch that sends this agent's own token, refreshed as needed. */
    this.fetch = bearerFetch(this, this._origins, baseFetch);
  }

  /**
   * Builds an agent from the environment: AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KEY_FILE
   * (preferred) or AUTHFI_AGENT_PRIVATE_KEY, AUTHFI_AGENT_KID, and optionally AUTHFI_AGENT_RESOURCE.
   */
  static fromEnv(env = process.env, overrides = {}) {
    const kid = env.AUTHFI_AGENT_KID || undefined;
    let key;
    if (env.AUTHFI_AGENT_KEY_FILE) key = AgentKey.fromFile(env.AUTHFI_AGENT_KEY_FILE, { kid });
    else if (env.AUTHFI_AGENT_PRIVATE_KEY) {
      process.emitWarning('AUTHFI_AGENT_PRIVATE_KEY puts a private key in the environment, where child processes and crash dumps see it; mount it as a file and set AUTHFI_AGENT_KEY_FILE', { code: 'AUTHFI_KEY_IN_ENV' });
      key = AgentKey.fromPem(env.AUTHFI_AGENT_PRIVATE_KEY, { kid });
    } else {
      throw new AgentAuthError('invalid_key', 'No agent key: set AUTHFI_AGENT_KEY_FILE to the path of the agent\'s private key', 400);
    }
    return new AgentAuth({
      issuer: env.AUTHFI_ISSUER,
      agentId: env.AUTHFI_AGENT_ID,
      resource: env.AUTHFI_AGENT_RESOURCE || undefined,
      key,
      ...overrides,
    });
  }

  /** The project's authorization-server metadata, checked against what this agent needs. */
  async metadata() {
    const meta = await this._discovery.metadata();
    const methods = meta.token_endpoint_auth_methods_supported;
    if (Array.isArray(methods) && !methods.includes('private_key_jwt')) {
      throw new AgentAuthError('unsupported_auth_method', `${this.issuer} does not accept private_key_jwt (it advertises ${methods.join(', ')})`, 400);
    }
    const algs = meta.token_endpoint_auth_signing_alg_values_supported;
    if (Array.isArray(algs) && !algs.includes(this.key.alg)) {
      throw new AgentAuthError('unsupported_alg', `${this.issuer} does not accept ${this.key.alg} assertions (it advertises ${algs.join(', ')})`, 400);
    }
    if (!meta.token_endpoint) throw new AgentAuthError('server_error', `${this.issuer} publishes no token_endpoint`, 502);
    return meta;
  }

  async _requireGrant(grant, what) {
    const meta = await this.metadata();
    if (Array.isArray(meta.grant_types_supported) && !meta.grant_types_supported.includes(grant)) {
      throw new AgentAuthError('unsupported_grant_type', `${this.issuer} does not offer ${what}`, 400);
    }
    return meta;
  }

  _reportDeprecation(url, res) {
    const deprecation = res.headers.get('deprecation');
    if (!deprecation || this._warned.has(url)) return;
    this._warned.add(url);
    const info = { url, deprecation, link: res.headers.get('link'), sunset: res.headers.get('sunset') };
    if (this._onDeprecation) this._onDeprecation(info);
    else process.emitWarning(`${url} is deprecated (${deprecation})${info.link ? `; successor: ${info.link}` : ''}`, { code: 'AUTHFI_DEPRECATED_ENDPOINT' });
  }

  async _post(url, form) {
    const doFetch = this._fetch || globalThis.fetch;
    let res;
    try {
      res = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams(Object.entries(form).filter(([, v]) => v !== undefined && v !== null && v !== '')).toString(),
      });
    } catch (e) {
      throw new AgentAuthError(null, `Request to ${url} failed: ${e.message}`, 0);
    }
    this._reportDeprecation(url, res);
    const text = await res.text();
    let body = {};
    try { body = text ? JSON.parse(text) : {}; } catch { body = {}; }
    if (!res.ok) {
      if (body && typeof body.error === 'string') throw new AgentAuthError(body.error, body.error_description, res.status);
      throw new AgentAuthError(null, `${url} answered HTTP ${res.status}`, res.status);
    }
    return body;
  }

  _assertion(audience) {
    return { client_id: this.agentId, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: this.key.clientAssertion(this.agentId, audience) };
  }

  async _mint(resource) {
    const meta = await this.metadata();
    const body = await this._post(meta.token_endpoint, {
      grant_type: 'client_credentials',
      ...this._assertion(meta.token_endpoint),
      resource,
    });
    if (!body.access_token) throw new AgentAuthError('server_error', 'The token endpoint returned no access_token', 502);
    const entry = {
      accessToken: body.access_token,
      expiresAt: expiryOf(body),
      capabilities: Array.isArray(body.capabilities) ? body.capabilities : [],
      scope: body.scope || null,
    };
    this._tokens.set(resource || '', entry);
    return entry;
  }

  /**
   * The agent's own access token (client credentials, private_key_jwt), cached and minted again
   * `refreshSkew` seconds before it expires. Concurrent callers share one request. A refusal is
   * thrown as AgentAuthError and not retried: a fresh assertion for a refused key is refused too.
   */
  async token({ resource, force = false } = {}) {
    const r = resource || this.resource || '';
    const cached = this._tokens.get(r);
    if (!force && cached && Date.now() < cached.expiresAt - this.refreshSkew * 1000) return cached.accessToken;
    if (!this._inflight.has(r)) {
      this._inflight.set(r, this._mint(r || undefined).finally(() => this._inflight.delete(r)));
    }
    return (await this._inflight.get(r)).accessToken;
  }

  /** The capability names granted to this agent, as returned with its token. */
  async capabilities({ resource } = {}) {
    await this.token({ resource });
    return [...this._tokens.get(resource || this.resource || '').capabilities];
  }

  /** `{ Authorization: 'Bearer ...' }` with a current token. */
  async authHeader(opts) {
    return { Authorization: `Bearer ${await this.token(opts)}` };
  }

  /**
   * Asks a person to let this agent act for them (OpenID CIBA). The person approves on their own
   * device, reading `bindingMessage`; the agent never sees their credentials. Returns the CIBA
   * response: auth_req_id (treat it as a secret), expires_in, interval.
   */
  async requestUserApproval({ loginHint, bindingMessage, scope, requestedExpiry } = {}) {
    if (!loginHint) throw new AgentAuthError('invalid_request', 'loginHint is required: the person to ask', 400);
    const meta = await this._requireGrant(CIBA_GRANT_TYPE, 'CIBA');
    if (!meta.backchannel_authentication_endpoint) {
      throw new AgentAuthError('unsupported_grant_type', `${this.issuer} publishes no backchannel_authentication_endpoint`, 400);
    }
    return this._post(meta.backchannel_authentication_endpoint, {
      ...this._assertion(meta.token_endpoint),
      login_hint: loginHint,
      binding_message: bindingMessage,
      scope,
      requested_expiry: requestedExpiry ? String(Math.floor(requestedExpiry)) : undefined,
    });
  }

  /**
   * Waits for the person's decision without blocking the event loop, then returns the delegated
   * token. Only authorization_pending and slow_down keep it waiting; access_denied, expired_token
   * and invalid_grant are decisions and are thrown at once.
   */
  async awaitUserToken(approval, { timeout, signal, resource, sleep: wait = sleep } = {}) {
    const authReqId = typeof approval === 'string' ? approval : approval && approval.auth_req_id;
    if (!authReqId) throw new AgentAuthError('invalid_request', 'No auth_req_id to wait for', 400);
    let interval = Math.max(1, Number((approval && approval.interval) || 5)) * 1000;
    const limit = timeout || Number((approval && approval.expires_in) || 300) * 1000;
    const deadline = Date.now() + limit;
    const meta = await this.metadata();
    for (;;) {
      await wait(interval, signal);
      try {
        const body = await this._post(meta.token_endpoint, {
          grant_type: CIBA_GRANT_TYPE,
          auth_req_id: authReqId,
          // A fresh assertion every poll: the platform refuses a jti it has seen.
          ...this._assertion(meta.token_endpoint),
          resource: resource || this.resource,
        });
        return new DelegatedToken(body, { renew: null, origins: this._origins, fetch: this._fetch, refreshSkew: this.refreshSkew });
      } catch (e) {
        if (!(e instanceof AgentAuthError)) throw e;
        if (e.error === 'slow_down') interval += 5000;
        else if (e.error !== 'authorization_pending') throw e;
      }
      if (Date.now() + interval > deadline) {
        throw new AgentAuthError('authorization_pending', `The person had not decided within ${Math.round(limit / 1000)} s; the request may still be open`, 408);
      }
    }
  }

  /** requestUserApproval, then awaitUserToken. */
  async tokenAsUser({ loginHint, bindingMessage, scope, requestedExpiry, timeout, signal, resource } = {}) {
    const approval = await this.requestUserApproval({ loginHint, bindingMessage, scope, requestedExpiry });
    return this.awaitUserToken(approval, { timeout, signal, resource });
  }

  /**
   * Exchanges a person's token for one this agent holds for them (RFC 8693): sub is the person and
   * act.sub this agent. The project must have granted this agent delegation for that person.
   *
   * The agent's own token is the actor_token and is its credential here. The request carries no
   * client_id or assertion on purpose: the project's token endpoint hands any request from an
   * agent client to the agent service, which serves client credentials and CIBA only.
   */
  async exchangeToken({ subjectToken, subjectTokenType = ACCESS_TOKEN_TYPE, resource, scope } = {}) {
    if (!subjectToken) throw new AgentAuthError('invalid_request', 'subjectToken is required: the token of the person to act for', 400);
    const meta = await this._requireGrant(TOKEN_EXCHANGE_GRANT_TYPE, 'token exchange');
    const exchange = async () => {
      const body = await this._post(meta.token_endpoint, {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        subject_token: subjectToken,
        subject_token_type: subjectTokenType,
        actor_token: await this.token(),
        actor_token_type: ACCESS_TOKEN_TYPE,
        resource: resource || this.resource,
        scope,
      });
      if (!body.access_token) throw new AgentAuthError('server_error', 'The token endpoint returned no access_token', 502);
      return body;
    };
    return new DelegatedToken(await exchange(), { renew: exchange, origins: this._origins, fetch: this._fetch, refreshSkew: this.refreshSkew });
  }

  toJSON() {
    return { issuer: this.issuer, agentId: this.agentId, key: this.key.toJSON() };
  }
}

module.exports = {
  AgentKey,
  AgentAuth,
  AgentAuthError,
  DelegatedToken,
  CLIENT_ASSERTION_TYPE,
  CIBA_GRANT_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
  ACCESS_TOKEN_TYPE,
  MAX_ASSERTION_LIFETIME,
};
