// The gateway's outlook for each tool (`io.authfi/governance`) in every framework adapter: a tool
// that is never allowed to this agent is not offered to the model, whether the gateway puts the
// outlook in `_meta` (current) or in the annotation (older), and a tool that may need approval
// is still offered. Advisory only: the gateway still refuses a call to a hidden tool.

import { createMCPClient } from '@ai-sdk/mcp';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { MCPClient } from '@mastra/mcp';
import { MCPServerStreamableHttp } from '@openai/agents';
import { afterEach, describe, expect, it } from 'vitest';
import { createLangChain } from '../../src/langchain/index.js';
import { createMastra } from '../../src/mastra/index.js';
import { createOpenAIAgents } from '../../src/openai-agents/index.js';
import { createVercelAI } from '../../src/vercel-ai/index.js';
import { Secret } from '../../src/core/secret.js';
import { setupGateway } from '../support/adapter-setup.js';
import { advertiseGovernance, CONTENTS, QUESTION, STRUCTURE } from '../support/fake-gateway.js';

afterEach(() => advertiseGovernance('off'));

const OFFERED = [CONTENTS, STRUCTURE].sort();
const ALL = [CONTENTS, QUESTION, STRUCTURE].sort();

async function langchain() {
  const s = await setupGateway();
  const authfi = createLangChain({ source: s.agent, logger: s.logger });
  const client = new Client({ name: 'test', version: '1.0.0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(authfi.mcpUrl), authfi.transportOptions()));
  return (await authfi.tools(client)).map((t) => t.name).sort();
}

async function openai() {
  const s = await setupGateway();
  const authfi = createOpenAIAgents({ source: s.agent, logger: s.logger });
  const server = new MCPServerStreamableHttp(authfi.mcpServerOptions());
  await server.connect();
  return (await authfi.tools(server)).map((t) => t.name).sort();
}

async function mastra() {
  const s = await setupGateway();
  const authfi = createMastra({ source: s.agent, logger: s.logger });
  const mcp = new MCPClient({ id: `g-${Math.random()}`, servers: { authfi: authfi.mcpServer() } });
  const names = Object.keys(authfi.tools(await mcp.listTools()))
    .map((n) => n.replace(/^authfi_/, 'authfi_'))
    .sort();
  await mcp.disconnect();
  return names.map((n) => n.replace(/^authfi_/, ''));
}

async function vercel() {
  const s = await setupGateway();
  const authfi = createVercelAI({
    source: s.agent,
    approvalSecret: new Secret('s'.repeat(32)),
    logger: s.logger,
  });
  const client = await createMCPClient({ transport: authfi.mcpTransport() });
  const names = Object.keys(authfi.tools(await client.tools())).sort();
  await client.close();
  return names;
}

const ADAPTERS = { langchain, openai, mastra, vercel } as const;

describe.each(Object.entries(ADAPTERS))('%s adapter', (_name, listed) => {
  it('offers every tool when the gateway states no outlook', async () => {
    advertiseGovernance('off');
    expect(await listed()).toEqual(ALL);
  });

  it('does not offer a never_allowed tool, read from _meta', async () => {
    advertiseGovernance('meta');
    expect(await listed()).toEqual(OFFERED);
  });

  it('prefers _meta over a conflicting annotation', async () => {
    advertiseGovernance('both-conflicting');
    expect(await listed()).toEqual(OFFERED);
  });
});

// Today's MCP clients drop an annotation key they do not know (the reason the outlook is in `_meta`),
// so the fallback for an older gateway is checked with tools that carry the annotation as given.
describe('older gateway: the annotation', () => {
  const key = 'io.authfi/governance';
  const schema = { type: 'object', properties: {} };
  const listed = [
    { name: 'a__open', inputSchema: schema, annotations: { [key]: 'no_policy_restriction' } },
    { name: 'a__shut', inputSchema: schema, annotations: { [key]: 'never_allowed' } },
  ];

  it('openai-agents falls back to it', async () => {
    const s = await setupGateway();
    const authfi = createOpenAIAgents({ source: s.agent, logger: s.logger });
    const server = { listTools: () => Promise.resolve(listed), callToolResult: () => Promise.resolve({}) };
    expect((await authfi.tools(server)).map((t) => t.name)).toEqual(['a__open']);
  });

  it('mastra falls back to it', async () => {
    const s = await setupGateway();
    const authfi = createMastra({ source: s.agent, logger: s.logger });
    const tools = Object.fromEntries(
      listed.map((t) => [
        t.name,
        { execute: () => Promise.resolve({}), mcp: { annotations: t.annotations } },
      ]),
    );
    expect(Object.keys(authfi.tools(tools))).toEqual(['a__open']);
  });

  it('langchain falls back to it', async () => {
    const s = await setupGateway();
    const authfi = createLangChain({ source: s.agent, logger: s.logger });
    const client = {
      callTool: () => Promise.resolve({}),
      getProtocolEra: () => 'legacy',
      listTools: () => Promise.resolve({ tools: listed }),
    };
    expect((await authfi.tools(client)).map((t) => t.name)).toEqual(['a__open']);
  });
});

describe('advisory only', () => {
  it('the gateway still refuses a call to a tool the model was never offered', async () => {
    advertiseGovernance('meta');
    const s = await setupGateway();
    const authfi = createLangChain({ source: s.agent, logger: s.logger });
    const client = new Client({ name: 'test', version: '1.0.0' });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(authfi.mcpUrl), authfi.transportOptions()),
    );
    const result = (await client.callTool({
      name: QUESTION,
      arguments: { repoName: 'pallets/itsdangerous' },
    })) as { isError?: boolean };
    expect(result.isError).toBe(true);
    expect(s.gw.executed).toHaveLength(0);
  });
});
