# Agent identity

Give an AI agent its own identity: a key it holds, and a token minted with it. No shared secret.

1. **Make the key** and register its public half in the console (AI Agents, the agent, Keys):

   ```bash
   node --import tsx keygen.ts ./agent-key.pem
   ```

   The private key goes to a file readable by its owner only; the SDK never uploads it. Registering
   an agent and its keys is a console step.

2. **Run the agent:**

   ```bash
   cp .env.example .env    # AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_AGENT_KID, AUTHFI_AGENT_KEY_FILE
   node --env-file=.env --import tsx agent.ts
   ```

The agent's token is minted at the project's token endpoint with a fresh five-minute assertion,
cached, and minted again a minute before it expires. Its audience is the gateway (`<issuer>/mcp`),
and `agent.fetch` sends it only to AuthFI. For your own API, use
`agent.forResource('api_orders', { sendTo: ['https://api.example.com'] })`.

Keep the key in a mounted file (`AUTHFI_AGENT_KEY_FILE`). `AUTHFI_AGENT_PRIVATE_KEY`, the PEM itself
in the environment, is for runtimes with no file system: an environment variable is inherited by
child processes and copied into crash dumps, so the SDK warns when it reads one.
