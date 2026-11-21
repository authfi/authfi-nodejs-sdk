# Quickstart: a governed agent in 10 minutes

From `npm install` to an agent that signs in with no secret, calls a model through AuthFI, calls a tool through AuthFI,
pauses for a person's approval and resumes, and shows up in the console. The example uses the Vercel AI SDK; every
other framework is the same steps (see [the framework pages](frameworks/README.md)).

Your project's address is its issuer, for example `https://acme.authfi.io`. Every address below is on it.

| What | Address |
|---|---|
| Models (the AI gateway) | `https://acme.authfi.io/llm` |
| Tools (the MCP gateway) | `https://acme.authfi.io/mcp` |
| Sign-in and tokens | `https://acme.authfi.io/oauth/token` |

## 1. Install (1 minute)

```bash
npm install @authfi/sdk ai @ai-sdk/anthropic @ai-sdk/mcp
```

Node.js 22.12 or later. The framework packages are optional peers of `@authfi/sdk`: install the ones you use.

## 2. Register the agent once in the console (3 minutes)

An agent here has no password, API key or key file. It proves where it runs, and AuthFI trusts that. You need a
group in **Identity > Groups** whose members answer for the agent, and a Kubernetes cluster
connected to your project (or a device, below).

1. Open the console (`console.authfi.io`), **Identity > AI Agents**, **Register agent**. Registration has the steps
   **Name it**, **Where it runs**, **What it may do**, **Review** and **Done**.
2. **Name it**: a name, **Works on its own**, and the group that answers for the agent.
3. **Where it runs**: **In a connected Kubernetes cluster (recommended)**, then the **Cluster**, **Namespace** and
   **Service account** the agent's pod runs as. Only pods running as that service account can sign in as this agent.
4. **What it may do**: under **Through the MCP gateway**, open **May call** and choose the tools the agent may use.
   Everything you do not choose is denied. Grant the model under **Integrations > MCP Gateway**, **Tools**,
   **Say who may call a tool**: caller type **An AI agent**, your agent, and a model such as
   `anthropic/claude-haiku-5-5` (connect the provider first under **Integrations > Connections**).
5. **Review**, then **Register**. The **Done** step shows the **Agent id** and the two values your code needs:

| Value | Looks like | Goes in |
|---|---|---|
| Project issuer | `https://acme.authfi.io` | `AUTHFI_ISSUER` |
| Agent id | `agt_...` | `AUTHFI_AGENT_ID` |
| Approved configuration (version and digest), after a person approves the agent's first run | `1`, `sha256:...` | `AUTHFI_CONFIG_VERSION`, `AUTHFI_CONFIG_DIGEST` |

A new agent has no approved configuration yet. On the **Done** step select **Observe its first run**, choose how long
(`1 hour`) and **Start observing**; nothing is denied while you watch. Run the agent once with
`AUTHFI_CONFIG_OBSERVE=1`. Then open the agent's **Approved configuration**, tick what it was seen doing, **Approve**,
and copy the version and digest. From then on the agent names that version.

On Kubernetes, project the service-account token for the project's origin (`audience: https://acme.authfi.io`,
`expirationSeconds: 600`). On a laptop, set `AUTHFI_DEVICE_KEY_FILE` and `AUTHFI_DEVICE_KEY_KID` to the device key the console gave the device.

Also set `APPROVAL_SECRET` to 32 random bytes, base64, the same in every process of the agent. It signs the approval
requests so that only AuthFI's decision can resume a held call.

## 3. Sign in (1 line)

```ts
import { connect } from '@authfi/sdk/node';

const source = await connect();     // reads AUTHFI_ISSUER and AUTHFI_AGENT_ID, finds where it runs, signs in
```

There is no secret to paste. The instance makes its own key in memory, the platform checks the attestation, and the
token is bound to that key: every call proves it holds it.

## 4. One model call through `/llm`, one tool call through `/mcp` (2 minutes)

```ts
import { createAnthropic } from '@ai-sdk/anthropic';
import { createMCPClient } from '@ai-sdk/mcp';
import { generateText, stepCountIs, type ModelMessage } from 'ai';
import { Secret } from '@authfi/sdk';
import { connect } from '@authfi/sdk/node';
import { createVercelAI } from '@authfi/sdk/vercel-ai';

const authfi = createVercelAI({
  source: await connect(),
  approvalSecret: new Secret(process.env.APPROVAL_SECRET ?? ''),
});
const model = createAnthropic(authfi.anthropic())('claude-haiku-5-5');   // calls go to <issuer>/llm
const mcp = await createMCPClient({ transport: authfi.mcpTransport() });  // tools come from <issuer>/mcp
const tools = authfi.tools(await mcp.tools());

const messages: ModelMessage[] = [{ role: 'user', content: 'List the tools you have, then use one.' }];
const run = () => generateText({ model, tools, messages, stopWhen: stepCountIs(4), ...authfi.approvals() });

let result = await run();
console.log(result.text);
```

The model is called through AuthFI's AI gateway with the agent's token and no model-provider key in your code. Each
tool is the gateway's, under the gateway's name (`<server>__<tool>`). A tool the agent may not use is not offered; a
call that policy refuses comes back to the model as the tool's answer, with the reason, and the run carries on.

## 5. An approval pause and resume (2 minutes)

When policy says a person must approve a call, the call is held. The model reads only that the action is waiting, and
the run pauses. Resume it when the person has decided:

```ts
while (authfi.pendingApprovals(result).length > 0) {
  console.log('waiting for a person to decide in AuthFI');
  // Asks the gateway, never the model or your app: only AuthFI's decision resumes the call.
  messages.push(...result.response.messages, await authfi.awaitApprovals(result));
  result = await run();
}
console.log(result.text);
await mcp.close();
```

Approved, the tool runs and the model reads its answer. Denied or expired, the model reads the refusal. Nothing the
app or the model says can approve the call: only the person's decision in AuthFI does.

## 6. See the run in the console

- **Identity > AI Agents**, then your agent: its Agent id, its approved configuration and what it has done.
- **Approvals**: the held call, who it is waiting on and the decision, linked to the run.
- **Security > Audit**: the tape of every sign-in, tool call, model call, refusal and approval, in order. Enter `agent:agt_...` in **Who**.

To see each framework step (which model call, which tool, how long) as well, send the steps to AuthFI. It needs
`@ai-sdk/otel`, `@opentelemetry/api`, `@opentelemetry/sdk-trace-base` and `@opentelemetry/otlp-transformer`:

```ts
const steps = await authfi.exportSteps();   // before the first generateText
// ... run the agent ...
await steps.shutdown();                     // before the process exits
```

## Next

- [One page per framework](frameworks/README.md)
- The [README](../README.md): acting for a person, mandates, cloud credentials, webhooks, administering a project
- [Examples](../examples)
