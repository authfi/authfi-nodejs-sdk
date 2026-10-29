import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as otel from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { W3CTraceContextPropagator } from '@opentelemetry/core';
import { BasicTracerProvider } from '@opentelemetry/sdk-trace-base';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AgentAuth } from '../../src/agents/agent.js';
import { ConfigurationError } from '../../src/core/errors.js';
import { ClientCredentials } from '../../src/machine/client-credentials.js';
import { connect, generateAgentKeyFile } from '../../src/node/index.js';
import { json } from '../support/fake-fetch.js';
import { ISSUER, TestIssuer } from '../support/issuer.js';

const POSIX = process.platform !== 'win32';
let dir: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'authfi-connect-'));
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function project() {
  const t = await TestIssuer.create();
  t.fake.on('POST', `${ISSUER}/oauth/token`, () =>
    json({ access_token: 'at-1', token_type: 'Bearer', expires_in: 900 }),
  );
  t.fake.on('POST', `${ISSUER}/mcp`, () => json({ jsonrpc: '2.0', id: 1, result: {} }));
  return t;
}

describe('connect', () => {
  it('builds the agent from an issuer, an agent id and a key file', async () => {
    const t = await project();
    const path = join(dir, 'agent.pem');
    await generateAgentKeyFile(path, 'ES256', { kid: 'k1' });
    const credential = await connect(
      {
        AUTHFI_ISSUER: ISSUER,
        AUTHFI_AGENT_ID: 'agt_1',
        AUTHFI_AGENT_KEY_FILE: path,
        AUTHFI_AGENT_KID: 'k1',
      },
      { fetch: t.fake.fetch },
    );
    expect(credential).toBeInstanceOf(AgentAuth);
    expect(credential.gateway().agentId).toBe('agt_1');
    expect(credential.gateway().kind).toBe('agent');
  });

  it('builds a machine client from a client id and secret, for the gateways, without a warning', async () => {
    const t = await project();
    const warns: string[] = [];
    const credential = await connect(
      { AUTHFI_ISSUER: ISSUER, AUTHFI_CLIENT_ID: 'app_m', AUTHFI_CLIENT_SECRET: 's3cret' },
      { fetch: t.fake.fetch, logger: { debug() {}, info() {}, warn: (m) => warns.push(m), error() {} } },
    );
    expect(credential).toBeInstanceOf(ClientCredentials);
    const gateway = credential.gateway();
    expect(gateway.agentId).toBeUndefined();
    await gateway.fetch(gateway.mcpUrl, { method: 'POST', body: '{}' });
    expect(t.fake.to(`${ISSUER}/mcp`)[0]!.headers.get('authorization')).toBe('Bearer at-1');
    expect(warns).toEqual([]);
    expect(JSON.stringify(credential)).not.toContain('s3cret');
  });

  it('prefers the agent when both are set', async () => {
    const t = await project();
    const path = join(dir, 'agent.pem');
    await generateAgentKeyFile(path, 'ES256', { kid: 'k1' });
    const credential = await connect(
      {
        AUTHFI_ISSUER: ISSUER,
        AUTHFI_AGENT_ID: 'agt_1',
        AUTHFI_AGENT_KEY_FILE: path,
        AUTHFI_AGENT_KID: 'k1',
        AUTHFI_CLIENT_ID: 'app_m',
        AUTHFI_CLIENT_SECRET: 's3cret',
      },
      { fetch: t.fake.fetch },
    );
    expect(credential).toBeInstanceOf(AgentAuth);
  });

  it('names the variable that is missing', async () => {
    const t = await project();
    const opts = { fetch: t.fake.fetch };
    await expect(connect({ AUTHFI_AGENT_ID: 'agt_1' }, opts)).rejects.toThrow('AUTHFI_ISSUER is not set');
    await expect(connect({ AUTHFI_ISSUER: ISSUER }, opts)).rejects.toThrow(
      /AUTHFI_AGENT_ID.*AUTHFI_CLIENT_ID/,
    );
    await expect(connect({ AUTHFI_ISSUER: ISSUER, AUTHFI_CLIENT_ID: 'app_m' }, opts)).rejects.toThrow(
      'AUTHFI_CLIENT_SECRET is not set',
    );
    await expect(
      connect({ AUTHFI_ISSUER: ISSUER, AUTHFI_CLIENT_ID: 'app_m', AUTHFI_CLIENT_SECRET: '' }, opts),
    ).rejects.toBeInstanceOf(ConfigurationError);
    await expect(connect({ AUTHFI_ISSUER: ISSUER, AUTHFI_AGENT_ID: 'agt_1' }, opts)).rejects.toThrow(
      'AUTHFI_AGENT_KEY_FILE',
    );
    if (POSIX) {
      // A key file others can read is refused, as for agentFromEnv.
      const path = join(dir, 'open.pem');
      await generateAgentKeyFile(path, 'ES256', { kid: 'k1' });
      const { chmod } = await import('node:fs/promises');
      await chmod(path, 0o644);
      await expect(
        connect(
          {
            AUTHFI_ISSUER: ISSUER,
            AUTHFI_AGENT_ID: 'agt_1',
            AUTHFI_AGENT_KEY_FILE: path,
            AUTHFI_AGENT_KID: 'k1',
          },
          opts,
        ),
      ).rejects.toThrow('readable by others');
    }
  });
});

describe('connect and the active trace', () => {
  const exporterless = new BasicTracerProvider();
  beforeAll(() => {
    const manager = new AsyncLocalStorageContextManager();
    manager.enable();
    otel.context.setGlobalContextManager(manager);
    otel.trace.setGlobalTracerProvider(exporterless);
    otel.propagation.setGlobalPropagator(new W3CTraceContextPropagator());
  });
  afterAll(async () => {
    await exporterless.shutdown();
  });

  it('sends the active trace to the gateway when @opentelemetry/api is installed', async () => {
    const t = await project();
    const credential = await connect(
      { AUTHFI_ISSUER: ISSUER, AUTHFI_CLIENT_ID: 'app_m', AUTHFI_CLIENT_SECRET: 's3cret' },
      { fetch: t.fake.fetch },
    );
    const gateway = credential.gateway();
    await otel.trace.getTracer('t').startActiveSpan('step', async (span) => {
      await gateway.fetch(gateway.mcpUrl, { method: 'POST', body: '{}' });
      expect(t.fake.to(`${ISSUER}/mcp`)[0]!.headers.get('traceparent')).toContain(span.spanContext().traceId);
      span.end();
    });
  });
});
