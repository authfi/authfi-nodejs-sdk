# Approvals on the Vercel AI SDK

An agent built on the Vercel AI SDK (`ai` 7), governed by AuthFI through `@authfi/sdk/vercel-ai`.

```bash
npm install @authfi/sdk ai @ai-sdk/anthropic @ai-sdk/mcp
cp .env.example .env    # APPROVAL_SECRET: 32 random bytes, the same for every process of the agent
node --env-file=.env --import tsx agent.ts
```

What the adapter does, so the app writes no glue:

- **The token never reaches a tracer.** `authfi.anthropic()` and `authfi.mcpTransport()` give the
  provider and the MCP client a fetch that attaches the agent's current token to each request.
- **A refusal is a tool result.** The model reads why it was refused, and the run goes on.
- **Approvals resume only on AuthFI's decision.** A call a person must approve becomes an AI SDK
  approval request. `awaitApprovals` asks the gateway until the person has decided; an approval the
  app makes up is refused. A resumed run never opens a second approval, and the gateway's hold text,
  which names the approval, never reaches the model. An approval id a model writes into a tool call
  is removed.
- **Content stays out of telemetry** unless `captureContent: true`: wrap your integration with
  `registerTelemetry(authfi.telemetry(new OpenTelemetry({ tracer })))`. `authfi.enrichSpan()` puts
  the agent and run ids on spans, and every gateway call carries `X-Request-Id` `<runId>.<n>`.
- **A revoked agent ends the run** with `GatewayTokenRefused`.

Tool names are the gateway's (`<server>__<tool>`), unchanged.
