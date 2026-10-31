import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI, type AuthFIOptions } from '../../src/core/project.js';
import type { Clock } from '../../src/core/clock.js';
import { Secret } from '../../src/core/secret.js';
import { AGENT, FakePlatform } from './fake-platform.js';
import { TestClock } from './issuer.js';

export const quiet = {
  debug() {},
  info() {},
  warn() {},
  error() {},
};

/** A project on the fake platform, with an agent that holds a key. One clock for both sides. */
export async function platform(options: Partial<AuthFIOptions> = {}) {
  const clock = new TestClock();
  clock.wall = Date.UTC(2026, 9, 30, 12, 0, 0);
  const key = await AgentKey.generate('ES256');
  const p = await FakePlatform.create(clock, key);
  const warns: string[] = [];
  const af = new AuthFI({
    issuer: p.issuer,
    fetch: p.fetch,
    clock,
    retries: 0,
    logger: { ...quiet, warn: (m) => warns.push(m) },
    ...options,
  });
  const agent = af.agent({ agentId: AGENT, key });
  return { clock, p, af, agent, key, warns, fake: p.t.fake };
}

/** A person's access token, as the app that linked the agent holds it. */
export async function person(p: FakePlatform, clock: Clock): Promise<Secret> {
  const now = Math.floor(clock.now() / 1000);
  return new Secret(await p.t.sign({ sub: 'usr_9', exp: now + 7200 }, { nowSeconds: now }));
}

/** A JSON-RPC `tools/call` body. */
export function call(name: string, args: Record<string, unknown> = {}): string {
  return JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
}
