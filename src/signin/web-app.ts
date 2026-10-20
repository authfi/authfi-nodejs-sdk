import { base64url, randomBytes, sha256, utf8 } from '../core/bytes.js';
import { SingleFlight } from '../core/cache.js';
import {
  ConfigurationError,
  NotSupportedError,
  OAuthError,
  SignInError,
  StepUpRequired,
  TransportError,
} from '../core/errors.js';
import {
  applyClientAuth,
  GRANT,
  oauthErrorOf,
  requestToken,
  type ClientAuth,
  type TokenResponse,
} from '../core/oauth.js';
import { coreOf, type AuthFI, type Core } from '../core/project.js';
import { Secret } from '../core/secret.js';
import { BaseTokenSource, checkSendTo, type TokenOptions, type TokenSource } from '../core/token-source.js';
import { TokenSet, type TokenStore } from '../core/token-set.js';
import { contextOf, jsonOf } from '../core/transport.js';
import { checkOrigin } from '../core/urls.js';
import { verifyIdToken, type IdTokenClaims } from './id-token.js';
import { importStateKey, PendingSignIn, PENDING_LIFETIME_MS, sameString } from './pending.js';

/** How `af.webApp()` is configured. */
export interface WebAppOptions {
  /** The app's client id. */
  readonly clientId: string;
  /** The app's client secret; leave it out for a public client (PKCE alone). */
  readonly clientSecret?: Secret | undefined;
  /** The callback URL registered for the app, exactly. */
  readonly redirectUri: string;
  /** 32 random bytes in base64, which encrypt the pending sign-in. */
  readonly stateKey: Secret;
  /** `client_secret_basic` (default) or `client_secret_post`. */
  readonly authMethod?: 'client_secret_basic' | 'client_secret_post' | undefined;
  /** The `acr` values to sign in with again when the platform asks for a step-up. */
  readonly stepUpAcrValues?: readonly string[] | undefined;
}

/** What `startSignIn` asks for. */
export interface SignInRequest {
  /** Defaults to `openid profile email`. */
  readonly scope?: readonly string[] | undefined;
  /** Ask for a stronger sign-in, such as `urn:authfi:acr:mfa`. */
  readonly acrValues?: readonly string[] | undefined;
  /** The longest time since the person last signed in, in seconds. */
  readonly maxAge?: number | undefined;
  readonly loginHint?: string | undefined;
  /** `login` signs in again; `consent` asks for consent again. */
  readonly prompt?: 'login' | 'consent' | undefined;
  readonly signal?: AbortSignal | undefined;
}

/** A finished sign-in: the tokens and who signed in. */
export interface SignedIn {
  readonly tokens: TokenSet;
  readonly user: IdTokenClaims;
}

/** What the userinfo endpoint releases. */
export interface UserInfo {
  readonly sub: string;
  readonly email: string | undefined;
  readonly emailVerified: boolean | undefined;
  readonly name: string | undefined;
  readonly claims: Readonly<Record<string, unknown>>;
}

/** A callback as the browser brought it: the URL, its query, or its parameters. */
export type SignInCallback = string | URL | URLSearchParams | Readonly<Record<string, string | undefined>>;

const DEFAULT_SCOPE = ['openid', 'profile', 'email'] as const;
const REFRESH_SKEW_MS = 60_000;

function callbackParams(callback: SignInCallback): URLSearchParams {
  if (callback instanceof URLSearchParams) return callback;
  if (callback instanceof URL) return callback.searchParams;
  if (typeof callback === 'string') {
    const query = callback.includes('?') ? callback.slice(callback.indexOf('?') + 1) : callback;
    return new URLSearchParams(query.split('#')[0]);
  }
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(callback)) if (v !== undefined) out.set(k, v);
  return out;
}

/**
 * Signs people in to a server-rendered app with the authorization code flow and PKCE, the pattern
 * the OAuth browser-apps guidance recommends. Made by `af.webApp()`.
 *
 * @example
 * const web = af.webApp({ clientId: 'app_…', clientSecret, redirectUri: 'https://app.example.com/callback', stateKey });
 * // GET /login
 * const pending = await web.startSignIn();
 * res.cookie('authfi_pending', await pending.dump(), { httpOnly: true, secure: true, sameSite: 'lax' });
 * res.redirect(pending.url);
 * // GET /callback
 * const { tokens, user } = await web.finishSignIn(req.originalUrl, await web.loadPending(req.cookies.authfi_pending));
 */
export class WebApp {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly #af: AuthFI;
  readonly #core: Core;
  readonly #auth: ClientAuth;
  readonly #key: Promise<CryptoKey>;
  readonly #aad: Uint8Array<ArrayBuffer>;
  readonly #stepUp: readonly string[];
  readonly #refreshes = new SingleFlight<string, TokenSet>();

  /** Use `af.webApp()`. */
  constructor(af: AuthFI, options: WebAppOptions) {
    if (typeof options.clientId !== 'string' || options.clientId === '')
      throw new ConfigurationError('clientId is required');
    let redirect: URL;
    try {
      redirect = new URL(options.redirectUri);
    } catch {
      throw new ConfigurationError('redirectUri must be the absolute callback URL registered for the app');
    }
    checkOrigin(redirect.origin, 'redirectUri');
    if (options.clientSecret !== undefined && !(options.clientSecret instanceof Secret)) {
      throw new ConfigurationError(
        'clientSecret must be a Secret: new Secret(process.env.AUTHFI_CLIENT_SECRET)',
      );
    }
    this.#af = af;
    this.#core = coreOf(af);
    this.clientId = options.clientId;
    this.redirectUri = options.redirectUri;
    this.#auth =
      options.clientSecret === undefined
        ? { method: 'none', clientId: options.clientId }
        : {
            method: options.authMethod ?? 'client_secret_basic',
            clientId: options.clientId,
            clientSecret: options.clientSecret,
          };
    this.#key = importStateKey(options.stateKey);
    this.#key.catch(() => undefined);
    this.#aad = utf8(`${options.clientId}\n${options.redirectUri}`);
    this.#stepUp = Object.freeze([...(options.stepUpAcrValues ?? [])]);
  }

  /**
   * Starts a sign-in: PKCE S256, a fresh `state` and `nonce`. Redirect the browser to
   * `pending.url`, and keep `await pending.dump()` until the callback.
   */
  async startSignIn(request: SignInRequest = {}): Promise<PendingSignIn> {
    if ((request.prompt as string | undefined) === 'none') {
      throw new NotSupportedError(
        'prompt_none',
        'This AuthFI project does not offer silent sign-in; use a refresh token',
      );
    }
    const meta = await this.#core.metadata({ signal: request.signal });
    if (meta.authorization_endpoint === undefined)
      throw new NotSupportedError(
        'authorization_code',
        'This AuthFI project offers no authorization endpoint',
      );
    const verifier = base64url(randomBytes(32));
    const state = base64url(randomBytes(32));
    const nonce = base64url(randomBytes(32));
    const url = new URL(meta.authorization_endpoint);
    const params: Record<string, string | undefined> = {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope: [...(request.scope ?? DEFAULT_SCOPE)].join(' '),
      state,
      nonce,
      code_challenge: base64url(await sha256(utf8(verifier))),
      code_challenge_method: 'S256',
      acr_values:
        request.acrValues === undefined || request.acrValues.length === 0
          ? undefined
          : request.acrValues.join(' '),
      max_age: request.maxAge === undefined ? undefined : String(Math.floor(request.maxAge)),
      login_hint: request.loginHint,
      prompt: request.prompt,
    };
    for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
    return new PendingSignIn(
      url.toString(),
      {
        verifier: new Secret(verifier),
        state,
        nonce,
        acrValues: [...(request.acrValues ?? [])],
        maxAge: request.maxAge,
        expiresAt: this.#core.clock.now() + PENDING_LIFETIME_MS,
      },
      await this.#key,
      this.#aad,
    );
  }

  /** Restores a pending sign-in from its blob; refuses one that is expired, from another app, or altered. */
  async loadPending(blob: string): Promise<PendingSignIn> {
    return PendingSignIn.load(blob, { key: await this.#key, aad: this.#aad, nowMs: this.#core.clock.now() });
  }

  /**
   * Finishes a sign-in from its callback: requires `iss` and checks it is the issuer (the mix-up
   * defence, RFC 9207), checks `state` in constant time, exchanges the code with the PKCE verifier
   * (once: a code is single-use), and verifies the ID token.
   */
  async finishSignIn(
    callback: SignInCallback,
    pending: PendingSignIn,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<SignedIn> {
    const params = callbackParams(callback);
    const remembered = pending.remembered;
    if (remembered.expiresAt <= this.#core.clock.now())
      throw new SignInError('sign_in_callback_invalid', 'the sign-in expired: start again');
    const iss = params.get('iss');
    if (iss === null)
      throw new SignInError(
        'sign_in_issuer_mismatch',
        'the callback carries no iss: it may come from another authorization server',
      );
    if (!sameString(iss, this.#core.issuer))
      throw new SignInError('sign_in_issuer_mismatch', 'the callback comes from another issuer');
    const state = params.get('state');
    if (state === null || !sameString(state, remembered.state)) {
      throw new SignInError('sign_in_state_mismatch', "the callback's state is not this sign-in's");
    }
    const error = params.get('error');
    if (error !== null) {
      const description = params.get('error_description') ?? undefined;
      if (error === 'unmet_authentication_requirements' || error === 'insufficient_user_authentication') {
        throw new StepUpRequired(description, {
          acrValues: remembered.acrValues.length > 0 ? remembered.acrValues : this.#stepUp,
          maxAge: remembered.maxAge,
        });
      }
      throw new OAuthError(error, description);
    }
    const code = params.get('code');
    if (code === null || code === '')
      throw new SignInError('sign_in_callback_invalid', 'the callback carries no code');

    const meta = await this.#core.metadata({ signal: options.signal });
    const res = await this.#token(
      meta.token_endpoint,
      {
        grant_type: GRANT.authorizationCode,
        code,
        redirect_uri: this.redirectUri,
        code_verifier: remembered.verifier.reveal(),
      },
      options.signal,
    );
    if (res.idToken === undefined)
      throw new SignInError(
        'sign_in_callback_invalid',
        'the token endpoint answered no ID token: ask for the openid scope',
      );
    const user = await verifyIdToken(this.#core, res.idToken, {
      clientId: this.clientId,
      nonce: remembered.nonce,
      accessToken: res.accessToken,
      acrValues: remembered.acrValues,
      maxAge: remembered.maxAge,
    });
    return { tokens: TokenSet.fromResponse(res), user };
  }

  async #token(
    endpoint: string,
    params: Record<string, string | undefined>,
    signal?: AbortSignal,
  ): Promise<TokenResponse> {
    try {
      return await requestToken(
        this.#core.transport,
        { tokenEndpoint: endpoint, params, auth: this.#auth, retry: 'unsafe', signal },
        () => this.#core.clock.now(),
      );
    } catch (e) {
      if (e instanceof StepUpRequired && e.acrValues.length === 0) {
        throw new StepUpRequired(e.description, {
          status: e.status,
          requestId: e.requestId,
          acrValues: this.#stepUp,
        });
      }
      throw e;
    }
  }

  /**
   * Refreshes a person's tokens. The refresh token rotates on every use and reusing a spent one
   * revokes the whole family, so concurrent refreshes of one set share one request, and it is never
   * retried after it was sent.
   */
  refresh(tokens: TokenSet, options: { signal?: AbortSignal | undefined } = {}): Promise<TokenSet> {
    const refresh = tokens.refreshToken;
    if (refresh === undefined)
      return Promise.reject(new ConfigurationError('this token set has no refresh token'));
    return this.#refreshes.run(refresh.reveal(), async () => {
      const meta = await this.#core.metadata({ signal: options.signal });
      const res = await this.#token(
        meta.token_endpoint,
        { grant_type: GRANT.refreshToken, refresh_token: refresh.reveal() },
        options.signal,
      );
      return new TokenSet({
        accessToken: res.accessToken,
        refreshToken: res.refreshToken ?? refresh,
        idToken: res.idToken ?? tokens.idToken,
        expiresAt: new Date(res.expiresAt),
        scope: res.scope.length > 0 ? res.scope : tokens.scope,
      });
    });
  }

  /** What the userinfo endpoint releases about the person. */
  async userinfo(tokens: TokenSet, options: { signal?: AbortSignal | undefined } = {}): Promise<UserInfo> {
    const meta = await this.#core.metadata({ signal: options.signal });
    if (meta.userinfo_endpoint === undefined)
      throw new NotSupportedError('userinfo', 'This AuthFI project offers no userinfo endpoint');
    const res = await this.#core.transport.send({
      method: 'GET',
      url: meta.userinfo_endpoint,
      retry: 'safe',
      signal: options.signal,
      headers: { authorization: `Bearer ${tokens.accessToken.reveal()}` },
    });
    if (res.status !== 200) throw oauthErrorOf(res);
    const body = jsonOf(res) as Record<string, unknown> | null;
    if (typeof body?.sub !== 'string')
      throw new TransportError('response_invalid', 'userinfo answered no sub', {
        ...contextOf(res),
        retryable: false,
      });
    return {
      sub: body.sub,
      email: typeof body.email === 'string' ? body.email : undefined,
      emailVerified: typeof body.email_verified === 'boolean' ? body.email_verified : undefined,
      name: typeof body.name === 'string' ? body.name : undefined,
      claims: Object.freeze({ ...body }),
    };
  }

  /**
   * Signs the person out: revokes the refresh token first (signing out at the platform does not),
   * then returns the end-session URL to redirect the browser to. `postLogoutRedirectUri` must share
   * the scheme and host of one of the app's redirect URIs.
   */
  async signOut(
    tokens: TokenSet,
    options: {
      postLogoutRedirectUri?: string | undefined;
      state?: string | undefined;
      signal?: AbortSignal | undefined;
    } = {},
  ): Promise<string> {
    const meta = await this.#core.metadata({ signal: options.signal });
    if (tokens.refreshToken !== undefined) {
      if (meta.revocation_endpoint === undefined)
        throw new NotSupportedError('revocation', 'This AuthFI project offers no revocation endpoint');
      const endpoint = meta.revocation_endpoint;
      const refresh = tokens.refreshToken;
      const res = await this.#core.transport.send({
        method: 'POST',
        url: endpoint,
        retry: 'safe',
        signal: options.signal,
        prepare: async () => {
          const form = new URLSearchParams({ token: refresh.reveal(), token_type_hint: 'refresh_token' });
          const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
          await applyClientAuth(this.#auth, form, headers, endpoint);
          return { headers, body: form.toString() };
        },
      });
      if (res.status !== 200) throw oauthErrorOf(res);
    }
    if (meta.end_session_endpoint === undefined)
      throw new NotSupportedError('end_session', 'This AuthFI project offers no end-session endpoint');
    const url = new URL(meta.end_session_endpoint);
    url.searchParams.set('client_id', this.clientId);
    if (options.postLogoutRedirectUri !== undefined)
      url.searchParams.set('post_logout_redirect_uri', options.postLogoutRedirectUri);
    if (options.state !== undefined) url.searchParams.set('state', options.state);
    return url.toString();
  }

  /**
   * A signed-in person's token as a {@link TokenSource}, kept in a {@link TokenStore} under `key` (a
   * session id) and refreshed before expiry. A refresh writes with `compareAndSet`, so two workers
   * never both spend the same refresh token. `sendTo` names your own API's origins; without it the
   * token goes only to AuthFI.
   */
  session(options: { key: string; store: TokenStore; sendTo?: readonly string[] | undefined }): TokenSource {
    if (typeof options.key !== 'string' || options.key === '')
      throw new ConfigurationError('key is required: the session the tokens belong to');
    const sendTo =
      options.sendTo === undefined || options.sendTo.length === 0 ? undefined : checkSendTo(options.sendTo);
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const app = this;
    return new (class PersonSession extends BaseTokenSource {
      // Public, so this module can build it: BaseTokenSource keeps its constructor protected.
      // eslint-disable-next-line @typescript-eslint/no-useless-constructor
      constructor(baseFetch: typeof fetch) {
        super(baseFetch);
      }
      get sendTo(): readonly string[] {
        return sendTo ?? [...new Set([new URL(app.#af.issuer).origin, app.#af.apiOrigin])];
      }
      protected override async ready(signal?: AbortSignal): Promise<void> {
        if (sendTo === undefined) await app.#core.metadata({ signal });
      }
      async token(opts: TokenOptions = {}): Promise<string> {
        const current = await options.store.load(options.key);
        if (current === undefined)
          throw new SignInError(
            'sign_in_callback_invalid',
            'no tokens are stored for this session: sign the person in',
          );
        if (opts.force !== true && !current.expiresWithin(REFRESH_SKEW_MS, app.#core.clock.now()))
          return current.accessToken.reveal();
        const next = await app.refresh(current, opts);
        if (await options.store.compareAndSet(options.key, current, next)) return next.accessToken.reveal();
        // Another worker refreshed first: use what it stored.
        const stored = await options.store.load(options.key);
        if (stored === undefined)
          throw new SignInError('sign_in_callback_invalid', 'the session was signed out while refreshing');
        return stored.accessToken.reveal();
      }
      override toString(): string {
        return `PersonSession(${app.clientId})`;
      }
    })(this.#core.fetch);
  }

  /** The client id and redirect URI; never the secret. */
  toString(): string {
    return `WebApp(${this.clientId} -> ${this.redirectUri})`;
  }

  toJSON(): { clientId: string; redirectUri: string } {
    return { clientId: this.clientId, redirectUri: this.redirectUri };
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return this.toString();
  }
}
