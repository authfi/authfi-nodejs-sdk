import {
  ConfigurationError,
  InsufficientAuthentication,
  InsufficientPermission,
  InsufficientScope,
  InvalidToken,
} from '../core/errors.js';
import { scopeList } from '../core/oauth.js';

/** Who a party is: a person, a machine client, or an AI agent. */
export type PrincipalKind = 'user' | 'app' | 'agent';

/**
 * A party a token names, with its kind separated from its id: `user:abc` is `{ kind: 'user', id:
 * 'abc' }` whichever spelling the token used. Compare principals, never `sub` strings.
 */
export class Principal {
  readonly kind: PrincipalKind;
  readonly id: string;

  constructor(kind: PrincipalKind, id: string) {
    this.kind = kind;
    this.id = id;
    Object.freeze(this);
  }

  /** Whether `other` is the same party. */
  equals(other: Principal): boolean {
    return this.kind === other.kind && this.id === other.id;
  }

  /** The typed form, `user:abc`. */
  toString(): string {
    return `${this.kind}:${this.id}`;
  }

  toJSON(): string {
    return this.toString();
  }
}

/**
 * What kind of token it is, derived from its principal and actor:
 * - `person`: a person's own token (T1);
 * - `machine`: a machine client's own token (T2);
 * - `agent`: an AI agent's own token (T4);
 * - `delegated`: a token an agent holds for a person (T5 by CIBA, T6 by token exchange).
 */
export type TokenKind = 'person' | 'machine' | 'agent' | 'delegated';

const TYPED = /^(user|app|agent):(.+)$/;

function parseTyped(value: string): Principal | undefined {
  const m = TYPED.exec(value);
  return m?.[1] === undefined || m[2] === undefined ? undefined : new Principal(m[1] as PrincipalKind, m[2]);
}

function actorOf(sub: string): Principal {
  return parseTyped(sub) ?? new Principal(sub.startsWith('agt_') ? 'agent' : 'app', sub);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}

function requireNames(names: readonly string[], what: string): void {
  if (names.length === 0)
    throw new ConfigurationError(`${what} needs at least one name; an empty list is not "no requirement"`);
}

/**
 * A verified access token, in one shape for every kind of token that reaches an API. It keeps no
 * raw token string.
 *
 * **Authorize on `permissions` and `roles`.** On person and machine tokens `scope` is whatever the
 * client asked for and is checked against nothing; it means something on agent tokens (their granted
 * capabilities) and for scopes your API defines itself.
 */
export class AccessToken {
  /** Who the token is for. */
  readonly principal: Principal;
  /** Who acts for the principal (`act.sub`): the agent of a delegated token, else undefined. */
  readonly actor: Principal | undefined;
  /** What kind of token it is (see {@link TokenKind}). */
  readonly tokenKind: TokenKind;
  readonly clientId: string;
  readonly tenantId: string;
  readonly issuer: string;
  readonly audience: readonly string[];
  readonly scopes: ReadonlySet<string>;
  readonly permissions: ReadonlySet<string>;
  readonly roles: ReadonlySet<string>;
  readonly groups: ReadonlySet<string>;
  /** The organisation, from `custom.org_id`. */
  readonly orgId: string | undefined;
  readonly acr: string | undefined;
  readonly amr: readonly string[];
  readonly authTime: Date | undefined;
  readonly expiresAt: Date;
  readonly jti: string | undefined;
  /** Every claim, read-only. */
  readonly claims: Readonly<Record<string, unknown>>;

  /** Builds the view of a token whose signature and claims were already verified. */
  constructor(claims: Record<string, unknown>, audience: readonly string[]) {
    const sub = String(claims.sub);
    const clientId = typeof claims.client_id === 'string' ? claims.client_id : '';
    const act = claims.act as { sub?: unknown } | undefined;
    const actSub = typeof act?.sub === 'string' ? act.sub : undefined;
    const typed = parseTyped(sub);

    if (typed?.kind === 'user' || (actSub !== undefined && typed === undefined)) {
      this.principal = typed ?? new Principal('user', sub);
      this.actor = actSub === undefined ? undefined : actorOf(actSub);
      this.tokenKind = this.actor === undefined ? 'person' : 'delegated';
    } else if (typed !== undefined) {
      this.principal = typed;
      this.actor = actSub === undefined ? undefined : actorOf(actSub);
      this.tokenKind = typed.kind === 'agent' ? 'agent' : 'machine';
    } else if (sub.startsWith('agt_')) {
      this.principal = new Principal('agent', sub);
      this.actor = undefined;
      this.tokenKind = 'agent';
    } else if (sub === clientId) {
      this.principal = new Principal('app', sub);
      this.actor = undefined;
      this.tokenKind = 'machine';
    } else {
      this.principal = new Principal('user', sub);
      this.actor = undefined;
      this.tokenKind = 'person';
    }

    const custom = claims.custom as { org_id?: unknown } | undefined;
    this.clientId = clientId;
    this.tenantId = String(claims.tenant_id);
    this.issuer = String(claims.iss);
    this.audience = Object.freeze([...audience]);
    this.scopes = new Set(scopeList(claims.scope));
    this.permissions = new Set(strings(claims.permissions));
    this.roles = new Set(strings(claims.roles));
    this.groups = new Set(strings(claims.groups));
    this.orgId = typeof custom?.org_id === 'string' ? custom.org_id : undefined;
    this.acr = typeof claims.acr === 'string' ? claims.acr : undefined;
    this.amr = Object.freeze(strings(claims.amr));
    this.authTime = typeof claims.auth_time === 'number' ? new Date(claims.auth_time * 1000) : undefined;
    this.expiresAt = new Date(Number(claims.exp) * 1000);
    this.jti = typeof claims.jti === 'string' ? claims.jti : undefined;
    this.claims = deepFreeze(structuredClone(claims));
    Object.freeze(this);
  }

  /** Requires **all** of the permissions; throws {@link InsufficientPermission}. */
  requirePermission(...names: string[]): void {
    requireNames(names, 'requirePermission');
    const missing = names.filter((n) => !this.permissions.has(n));
    if (missing.length > 0)
      throw new InsufficientPermission(names, `the token lacks the permission(s) ${missing.join(', ')}`);
  }

  /** Requires **at least one** of the permissions; throws {@link InsufficientPermission}. */
  requireAnyPermission(...names: string[]): void {
    requireNames(names, 'requireAnyPermission');
    if (!names.some((n) => this.permissions.has(n))) {
      throw new InsufficientPermission(names, `the token has none of the permissions ${names.join(', ')}`);
    }
  }

  /** Requires **at least one** of the roles; throws {@link InsufficientPermission}. */
  requireRole(...names: string[]): void {
    requireNames(names, 'requireRole');
    if (!names.some((n) => this.roles.has(n)))
      throw new InsufficientPermission(names, `the token has none of the roles ${names.join(', ')}`);
  }

  /**
   * Requires **all** of the scopes; throws {@link InsufficientScope}. Meaningful for agent tokens and
   * for scopes your API defines; on person and machine tokens the client chose its own scope.
   */
  requireScope(...names: string[]): void {
    requireNames(names, 'requireScope');
    const missing = names.filter((n) => !this.scopes.has(n));
    if (missing.length > 0)
      throw new InsufficientScope(names, `the token lacks the scope(s) ${missing.join(', ')}`);
  }

  /**
   * Requires the person signed in with one of the `acr` values and, with `maxAgeSeconds`, recently
   * enough; throws {@link InsufficientAuthentication}, which an adapter answers as RFC 9470 step-up.
   */
  requireAcr(values: readonly string[], options: { maxAgeSeconds?: number; nowMs?: number } = {}): void {
    requireNames(values, 'requireAcr');
    const { maxAgeSeconds } = options;
    if (this.acr === undefined || !values.includes(this.acr)) {
      throw new InsufficientAuthentication(
        values,
        maxAgeSeconds,
        `the sign-in's acr is not one of ${values.join(', ')}`,
      );
    }
    if (maxAgeSeconds !== undefined) {
      const now = options.nowMs ?? Date.now();
      if (this.authTime === undefined || now - this.authTime.getTime() > maxAgeSeconds * 1000) {
        throw new InsufficientAuthentication(
          values,
          maxAgeSeconds,
          `the sign-in is older than ${maxAgeSeconds} seconds`,
        );
      }
    }
  }

  /** Requires an agent's token or a token an agent holds for a person; else `token_no_agent`. */
  requireAgent(): void {
    if (this.principal.kind !== 'agent' && this.actor?.kind !== 'agent') {
      throw new InvalidToken('token_no_agent', 'the token names no agent');
    }
  }

  /** The principal and kind only. */
  toString(): string {
    return `AccessToken(${this.tokenKind} ${this.principal.toString()}${this.actor === undefined ? '' : ` by ${this.actor.toString()}`})`;
  }
}
