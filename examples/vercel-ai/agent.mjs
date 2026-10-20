// An AI agent on the Vercel AI SDK, governed by AuthFI through @authfi/sdk/vercel-ai.
//
//   node agent.mjs keygen        generate the agent's key: the private half to AUTHFI_AGENT_KEY_FILE
//                                (0600), the public JWK printed for registration
//   node agent.mjs run           model call, granted tool, refused tool, an approved and a denied
//                                call, and (with AUTHFI_PERSON) a call made for a person
//   node agent.mjs check-trace   what the trace export carried (with the capture server's OTLP_DIR)
//
// Configuration (environment):
//   AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KEY_FILE, AUTHFI_AGENT_KID   the agent's identity
//   AUTHFI_MODEL           a model the agent is granted (default claude-haiku-5-5)
//   AUTHFI_TOOL_GRANTED    a tool the agent may call          (default deepwiki__read_wiki_structure)
//   AUTHFI_TOOL_REFUSED    a tool it has no grant for         (default deepwiki__ask_wiki_question)
//   AUTHFI_TOOL_APPROVAL   a tool a person must approve       (default deepwiki__read_wiki_contents)
//   AUTHFI_PERSON          the person to act for, by CIBA (optional)
//   RUN_ID                 the run id that prefixes every X-Request-Id (optional)
//   OTEL_EXPORTER_OTLP_ENDPOINT   where spans go (default http://127.0.0.1:4318, see otlp-capture.mjs)
//
// Nothing here handles a token: the adapter's fetch sends the agent's current token to the
// project's origin, and nowhere else.
import fs from 'node:fs';
import { generateText, stepCountIs, registerTelemetry } from 'ai';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import { OpenTelemetry } from '@ai-sdk/otel';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { SimpleSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { AgentKey, AgentAuth } from '@authfi/sdk';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const env = process.env;
const MODEL = env.AUTHFI_MODEL || 'claude-haiku-5-5';
const GRANTED = env.AUTHFI_TOOL_GRANTED || 'deepwiki__read_wiki_structure';
const REFUSED = env.AUTHFI_TOOL_REFUSED || 'deepwiki__ask_wiki_question';
const APPROVAL = env.AUTHFI_TOOL_APPROVAL || 'deepwiki__read_wiki_contents';
const REPO = 'pallets/itsdangerous';
const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');
const log = (...p) => console.log(p.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '));
const head = (t) => log(`\n=== ${t}  [${now()}]`);
const cut = (v, n = 300) => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s && s.length > n ? `${s.slice(0, n)}…(+${s.length - n})` : s; };

function showSteps(r) {
  for (const [i, s] of (r.steps || []).entries()) {
    for (const p of s.content || []) {
      if (p.type === 'text') log(`  step ${i} text: ${cut(p.text)}`);
      else if (p.type === 'tool-call') log(`  step ${i} tool-call ${p.toolName} ${cut(p.input, 120)}`);
      else if (p.type === 'tool-result') log(`  step ${i} tool-result ${p.toolName} ${cut(p.output?.content?.map((c) => c.text).join(' ') ?? p.output, 200)}`);
      else if (p.type === 'tool-error') log(`  step ${i} tool-error ${p.toolName} ${cut(String(p.error?.message ?? p.error))}`);
      else if (p.type === 'tool-approval-request') log(`  step ${i} tool-approval-request ${p.toolCall.toolName}: ${p.reason}`);
      else if (p.type !== 'reasoning') log(`  step ${i} ${p.type}`);
    }
  }
  log(`  finishReason=${r.finishReason} steps=${(r.steps || []).length}`);
}

async function keygen() {
  const file = env.AUTHFI_AGENT_KEY_FILE;
  if (!file) throw new Error('set AUTHFI_AGENT_KEY_FILE to where the private key goes');
  const key = AgentKey.generate('ES256');
  fs.writeFileSync(file, key.privatePem(), { mode: 0o600 });
  log(JSON.stringify({ kid: key.kid, jwk: key.publicJwk() }));
}

/** One generateText run, resumed until AuthFI has decided every approval it raised. */
async function runWithApprovals(authfi, { model, tools, prompt, telemetry }) {
  const messages = [{ role: 'user', content: prompt }];
  const call = () => generateText({ model, tools, messages, stopWhen: stepCountIs(4), telemetry, ...authfi.approvals() });
  let result = await call();
  showSteps(result);
  while (authfi.pendingApprovals(result).length) {
    log(`  waiting for a person to decide in AuthFI: ${authfi.pendingApprovals(result).map((p) => p.reason).join('; ')}`);
    const responses = await authfi.awaitApprovals(result);
    for (const c of responses.content) log(`  AuthFI decided: approved=${c.approved} (${cut(c.reason, 160)})`);
    messages.push(...result.response.messages, responses);
    result = await call();
    showSteps(result);
  }
  return result;
}

async function run() {
  const provider = new NodeTracerProvider({
    resource: resourceFromAttributes({ 'service.name': 'authfi-vercel-ai-example' }),
    spanProcessors: [new SimpleSpanProcessor(new OTLPTraceExporter({
      url: `${env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://127.0.0.1:4318'}/v1/traces`,
    }))],
  });
  provider.register();

  const agent = AgentAuth.fromEnv();
  const authfi = createVercelAI({ agent, runId: env.RUN_ID || undefined });
  registerTelemetry(authfi.telemetry(new OpenTelemetry({ tracer: provider.getTracer('gen_ai'), enrichSpan: authfi.enrichSpan })));
  log(`agent ${agent.agentId} at ${agent.issuer}, run ${authfi.runId}`);

  const anthropic = createAnthropic(authfi.anthropic());
  const mcp = await createMCPClient({ transport: authfi.mcpTransport(), clientName: 'authfi-vercel-ai-example' });
  const tools = authfi.tools(await mcp.tools());
  log(`tools: ${Object.keys(tools).map((k) => (authfi.mcpName(k) === k ? k : `${k} (${authfi.mcpName(k)})`)).join(', ')}`);
  const pick = (k) => { if (!tools[k]) throw new Error(`the gateway lists no tool ${k}`); return { [k]: tools[k] }; };
  const telemetry = (functionId) => ({ functionId });
  const model = anthropic(MODEL);

  head('1  model call through the AI gateway');
  const r1 = await generateText({ model, prompt: 'Reply with exactly: AUTHFI OK', maxOutputTokens: 20, telemetry: telemetry('example-model') });
  log(`  text: ${r1.text}`);

  head(`2  granted tool ${GRANTED}`);
  await runWithApprovals(authfi, { model, tools: pick(GRANTED), telemetry: telemetry('example-granted'),
    prompt: `Use the tool once to list the wiki topics of the GitHub repository ${REPO}, then give the first three.` });

  head(`3  refused tool ${REFUSED}: the refusal reaches the model as the tool's result`);
  await runWithApprovals(authfi, { model, tools: pick(REFUSED), telemetry: telemetry('example-refused'),
    prompt: `I am jane.doe@example.com. Use the tool once to ask about ${REPO}: "What does the Signer class do?". If it is refused, say why and stop.` });

  for (const leg of ['4  approval (the person approves)', '5  approval (the person denies)']) {
    head(`${leg}: ${APPROVAL}`);
    await runWithApprovals(authfi, { model, tools: pick(APPROVAL), telemetry: telemetry('example-approval'),
      prompt: `Use the tool once to read the wiki of ${REPO} and summarise it in one sentence.` });
  }

  if (env.AUTHFI_PERSON) {
    head(`6  acting for ${env.AUTHFI_PERSON}: they approve in their own sign-in (CIBA)`);
    const scope = authfi.scope(GRANTED);
    const delegated = await agent.tokenAsUser({
      loginHint: env.AUTHFI_PERSON,
      bindingMessage: `Let ${agent.agentId} list wiki topics for you (${authfi.runId})`,
      scope,
    });
    log(`  delegated token: sub=${delegated.claims.sub} act.sub=${delegated.claims.act?.sub} scope=${delegated.scope}`);
    const forPerson = createVercelAI({ agent, credentials: delegated, runId: `${authfi.runId}.person` });
    const pmcp = await createMCPClient({ transport: forPerson.mcpTransport(), clientName: 'authfi-vercel-ai-example-person' });
    const ptools = forPerson.tools(await pmcp.tools());
    for (const k of [GRANTED, APPROVAL]) {
      log(`  ${k} for the person (${k === GRANTED ? 'consented' : 'not consented'}):`);
      await runWithApprovals(forPerson, { model, tools: { [k]: ptools[k] }, telemetry: telemetry('example-person'),
        prompt: `Use the tool once for ${REPO}. If it is refused, say why and stop.` });
    }
    await pmcp.close();
  }

  await mcp.close();
  await provider.forceFlush();
  await provider.shutdown();
  log(`\ndone ${now()}`);
}

/** What the capture server received: counts only, nothing is printed from the spans' values. */
function checkTrace() {
  const dir = env.OTLP_DIR || './otlp';
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const blob = files.map((f) => fs.readFileSync(`${dir}/${f}`, 'utf8')).join('\n');
  const count = (needle) => blob.split(needle).length - 1;
  log(`${files.length} exports, ${blob.length} bytes`);
  log(`JWT-shaped strings: ${(blob.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g) || []).length}`);
  for (const [what, needle] of [['the email in a prompt', 'jane.doe@example.com'], ['the repository in prompts', REPO],
    ['a tool result ("Available pages")', 'Available pages'], ['a refusal ("Denied by policy" or "Refused")', 'Denied by policy'],
    ['"Refused ("', 'Refused ('], ['Bearer', 'Bearer'], ['gen_ai.input.messages', 'gen_ai.input.messages'],
    ['gen_ai.tool.call.arguments', 'gen_ai.tool.call.arguments'], ['gen_ai.tool.call.result', 'gen_ai.tool.call.result'],
    ['authfi.agent_id', 'authfi.agent_id'], ['authfi.run_id', 'authfi.run_id'], ['authfi.request_id', 'authfi.request_id'],
    ['authfi.tool_approval spans', 'authfi.tool_approval'], ['authfi.approval_wait spans', 'authfi.approval_wait']]) {
    log(`${what}: ${count(needle)}`);
  }
}

const phase = process.argv[2] || 'run';
if (phase === 'keygen') await keygen();
else if (phase === 'check-trace') checkTrace();
else await run();
