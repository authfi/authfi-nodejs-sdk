import { describe, expect, it } from 'vitest';
import {
  ConfigurationError,
  InsufficientAuthentication,
  InvalidToken,
  TransportError,
} from '../../src/core/errors.js';
import { AccessToken, Principal } from '../../src/verify/access-token.js';
import { applyRequirements, checkRequirements, refusalAnswer } from '../../src/verify/answer.js';

describe('refusalAnswer', () => {
  it('answers a server misconfiguration 500 and an unreachable issuer 503, naming nothing', () => {
    expect(refusalAnswer(new ConfigurationError('bad audience'))).toEqual({
      status: 500,
      headers: {},
      body: { error: 'internal_error' },
    });
    expect(refusalAnswer(new TransportError('timeout', 't', { retryable: true }))).toEqual({
      status: 503,
      headers: { 'retry-after': '5' },
      body: { error: 'service_unavailable' },
    });
    expect(refusalAnswer(new Error('anything')).status).toBe(503);
  });

  it('answers step-up with acr_values, max_age and the resource metadata', () => {
    const a = refusalAnswer(
      new InsufficientAuthentication(['urn:authfi:acr:mfa'], undefined, 'x'),
      'Bearer',
      {
        resourceMetadata: 'https://api.example.com/.well-known/oauth-protected-resource',
      },
    );
    expect(a.headers['www-authenticate']).toBe(
      'Bearer error="insufficient_user_authentication", acr_values="urn:authfi:acr:mfa", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it('strips quotes from challenge values', () => {
    const a = refusalAnswer(new InvalidToken('token_expired', 'x'), 'Bearer', {
      resourceMetadata: 'https://x"y',
    });
    expect(a.headers['www-authenticate']).toContain('resource_metadata="https://xy"');
  });
});

describe('requirements', () => {
  it('refuse an empty list and apply in order', () => {
    expect(() => checkRequirements({ scopes: [] })).toThrow('scopes is empty');
    expect(() => checkRequirements({ permissions: ['a'] })).not.toThrow();
    const token = new AccessToken({ iss: 'i', sub: 's', exp: 1, tenant_id: 't', permissions: ['a'] }, [
      'aud',
    ]);
    expect(() => applyRequirements(token, { permissions: ['a'] })).not.toThrow();
    expect(() => applyRequirements(token, { anyPermission: ['b'] })).toThrow();
  });
});

describe('AccessToken', () => {
  it('reads azp, scp and absent optional claims', () => {
    const token = new AccessToken(
      { iss: 'i', sub: 'app_1', azp: 'app_1', scp: ['a'], exp: 10, tenant_id: 't' },
      ['aud'],
    );
    expect(token.clientId).toBe('app_1');
    expect(token.tokenKind).toBe('machine');
    expect([...token.scopes]).toEqual(['a']);
    expect(token.orgId).toBeUndefined();
    expect(token.acr).toBeUndefined();
    expect(token.authTime).toBeUndefined();
    expect(token.jti).toBeUndefined();
    expect(token.expiresAt.getTime()).toBe(10_000);
    const bare = new AccessToken({ iss: 'i', sub: 'u', exp: 1, tenant_id: 't' }, []);
    expect(bare.clientId).toBe('');
    expect(bare.tokenKind).toBe('person');
  });

  it('compares principals', () => {
    expect(new Principal('user', 'a').equals(new Principal('user', 'a'))).toBe(true);
    expect(new Principal('user', 'a').equals(new Principal('agent', 'a'))).toBe(false);
  });
});
