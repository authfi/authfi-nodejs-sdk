/**
 * Express middleware for an API that accepts AuthFI access tokens.
 *
 * @example
 * import { AuthFI } from '@authfi/sdk';
 * import { protect, authfiErrorHandler } from '@authfi/sdk/express';
 *
 * const af = AuthFI.fromEnv();
 * const verifier = af.verifier({ audience: ['api_orders'] });
 * app.get('/orders', protect(verifier, { permissions: ['orders:read'] }), (req, res) => {
 *   res.json({ for: req.authfi?.principal.toString() });
 * });
 * app.use(authfiErrorHandler());
 *
 * @packageDocumentation
 */

import { isAuthFIError } from '../core/errors.js';
import { isValidRequestId } from '../core/ids.js';
import type { Logger } from '../core/logger.js';
import type { AccessToken } from '../verify/access-token.js';
import {
  applyRequirements,
  checkRequirements,
  refusalAnswer,
  type AnswerOptions,
  type Requirements,
} from '../verify/answer.js';
import { loggerOf, type Scheme, type Verifier } from '../verify/verifier.js';

declare global {
  // Express merges this into its Request type.
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** The verified token, set by `protect()`. Absent on an `optional` route without a credential. */
      authfi?: AccessToken;
    }
  }
}

/** The parts of an Express request the middleware reads. */
export interface ExpressRequest {
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  readonly method: string;
  readonly originalUrl?: string;
  readonly url?: string;
  readonly protocol?: string;
  get?(name: string): string | undefined;
  authfi?: AccessToken;
}

/** The parts of an Express response the middleware writes. */
export interface ExpressResponse {
  readonly headersSent?: boolean;
  status(code: number): this;
  set(field: Record<string, string>): this;
  json(body: unknown): unknown;
}

/** Express's `next`. */
export type NextFunction = (err?: unknown) => void;

/** How `protect()` guards a route. */
export interface ProtectOptions extends Requirements, AnswerOptions {
  /** Let a request with no credential through, with `req.authfi` unset. A credential that is present must still verify. */
  readonly optional?: boolean | undefined;
  /** Where refusals are logged (code and request id, never the token). Defaults to the project's logger. */
  readonly logger?: Logger | undefined;
}

const SILENT: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function single(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function urlOf(req: ExpressRequest): string | undefined {
  const host = req.get?.('host') ?? single(req.headers.host);
  const path = req.originalUrl ?? req.url;
  if (host === undefined || path === undefined) return undefined;
  return `${req.protocol ?? 'https'}://${host}${path}`;
}

function schemeOf(req: ExpressRequest): Scheme {
  return /^\s*dpop\s/i.test(single(req.headers.authorization) ?? '') ? 'DPoP' : 'Bearer';
}

function answer(
  req: ExpressRequest,
  res: ExpressResponse,
  error: unknown,
  options: AnswerOptions,
  logger: Logger,
): void {
  const reply = refusalAnswer(error, schemeOf(req), options);
  // The caller's id is echoed and logged only when it is one the platform would accept: anything
  // else could forge log lines or carry a value into the response.
  const given = single(req.headers['x-request-id']);
  const requestId = given !== undefined && isValidRequestId(given) ? given : undefined;
  const fields = {
    code: isAuthFIError(error) ? error.code : 'internal_error',
    status: reply.status,
    method: req.method,
    path: (req.originalUrl ?? req.url ?? '').split('?')[0],
    ...(requestId === undefined ? {} : { request_id: requestId }),
  };
  if (reply.status >= 500) logger.error('request refused: the token could not be checked', fields);
  else if (fields.code === 'token_missing') logger.info('request refused', fields);
  else logger.warn('request refused', fields);
  const headers = { ...reply.headers, ...(requestId === undefined ? {} : { 'x-request-id': requestId }) };
  res.status(reply.status).set(headers).json(reply.body);
}

/**
 * Verifies the request's access token (`Bearer` or `DPoP` scheme), applies the requirements, and
 * sets `req.authfi`. A refusal is answered on the wire as the platform answers (one opaque
 * `invalid_token`, `insufficient_scope`, `forbidden`, or RFC 9470 step-up) and logged with its code.
 *
 * Requirements combine with AND; `permissions` and `scopes` need all, `anyPermission` and `roles` need one.
 */
export function protect(
  verifier: Verifier,
  options: ProtectOptions = {},
): (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void {
  const requirements: Requirements = {
    permissions: options.permissions,
    anyPermission: options.anyPermission,
    roles: options.roles,
    scopes: options.scopes,
  };
  checkRequirements(requirements);
  const logger = options.logger ?? loggerOf(verifier) ?? SILENT;
  return (req, res, next) => {
    const authorization = single(req.headers.authorization);
    if (options.optional === true && (authorization === undefined || authorization.trim() === '')) {
      next();
      return;
    }
    verifier
      .verifyRequest({ authorization, dpop: single(req.headers.dpop), method: req.method, url: urlOf(req) })
      .then((token) => {
        applyRequirements(token, requirements);
        req.authfi = token;
        next();
      })
      .catch((error: unknown) => {
        answer(req, res, error, options, logger);
      });
  };
}

/**
 * Answers an AuthFI refusal thrown by a route handler (for example `req.authfi.requirePermission()`)
 * as `protect()` would, and passes every other error on. Register it after your routes.
 */
export function authfiErrorHandler(
  options: AnswerOptions & { logger?: Logger | undefined } = {},
): (err: unknown, req: ExpressRequest, res: ExpressResponse, next: NextFunction) => void {
  return (err, req, res, next) => {
    if (!isAuthFIError(err, 'InvalidToken') || res.headersSent === true) {
      next(err);
      return;
    }
    answer(req, res, err, options, options.logger ?? SILENT);
  };
}
