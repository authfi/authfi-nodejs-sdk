# Vercel AI SDK agent, governed by AuthFI

An AI agent built on the Vercel AI SDK (`ai` 7, `@ai-sdk/anthropic`, `@ai-sdk/mcp`, `@ai-sdk/otel`)
that reaches its model through the project's AI gateway and its tools through the project's MCP
gateway, using `@authfi/sdk/vercel-ai`. The agent code holds no token and no glue of its own.

`agent.mjs run` makes, in order:

1. a model call;
2. a call to a tool the agent is granted;
3. a call to a tool it is not granted: the model reads the refusal as the tool's result;
4. a call a person must approve, which the person approves in AuthFI: the run resumes and returns
   the tool's answer;
5. the same call, which the person denies: the run resumes and the model reads the denial;
6. with `AUTHFI_PERSON` set, a call made for that person after they approve it in their own sign-in
   (CIBA), and a call outside what they approved.

Its trace goes to `otlp-capture.mjs`, a collector on 127.0.0.1 that only stores what it receives,
so `agent.mjs check-trace` can show what a trace carries: the agent and run ids and the gateway
request ids, and no prompt, tool argument, tool result or token.

## Run it

You need a project where:

- the agent is registered with its public key (`publicJwk` and `jwkKid` in `registerAgent`);
- it is granted the model, and one tool (`AUTHFI_TOOL_GRANTED`);
- it is not granted a second tool (`AUTHFI_TOOL_REFUSED`);
- a step-up policy makes a person approve a third tool for it (`AUTHFI_TOOL_APPROVAL`);
- someone can decide that approval in the console.

```bash
npm install
export AUTHFI_ISSUER=https://<your project>.authfi.io
export AUTHFI_AGENT_KEY_FILE=$PWD/agent-key.pem
node agent.mjs keygen                  # prints { kid, jwk }: register the jwk, keep the kid
export AUTHFI_AGENT_ID=agt_... AUTHFI_AGENT_KID=<kid>

node otlp-capture.mjs &                # the local collector
node agent.mjs run                     # decide the approvals in the console when it waits
node agent.mjs check-trace
```

The tool names default to DeepWiki's (`deepwiki__read_wiki_structure`, `deepwiki__ask_wiki_question`,
`deepwiki__read_wiki_contents`); set `AUTHFI_TOOL_GRANTED`, `AUTHFI_TOOL_REFUSED` and
`AUTHFI_TOOL_APPROVAL` to the provider-legal names of your own tools.
