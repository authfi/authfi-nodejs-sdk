// One agent, the fake authorization server and the fake gateways, for the framework adapter tests.

import { AgentKey } from '../../src/agents/agent-key.js';
import { AuthFI } from '../../src/core/project.js';
import { AGENT_ID, FakeAS } from './fake-as.js';
import { FakeGateway } from './fake-gateway.js';

export async function setupGateway() {
  const key = await AgentKey.generate('ES256');
  const as = await FakeAS.create(key);
  const gw = new FakeGateway(as);
  const warns: string[] = [];
  const logger = { debug() {}, info() {}, warn: (m: string) => warns.push(m), error() {} };
  const af = new AuthFI({ issuer: as.issuer, fetch: as.t.fake.fetch, logger });
  const agent = af.agent({ agentId: AGENT_ID, key });
  return { key, as, gw, af, agent, logger, warns };
}

export type GatewaySetup = Awaited<ReturnType<typeof setupGateway>>;
