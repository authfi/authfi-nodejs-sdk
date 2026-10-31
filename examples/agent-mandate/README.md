# An agent on a mandate

An agent signs in as an instance of its workload (no key to keep), then does one job for one person under a
**mandate**: the authority the person gave it, narrowed from what the agent may ever do.

1. **Bind the workload** to the agent and approve its configuration in the console. On Kubernetes, project a
   service-account token for the project's origin (`audience`) with `expirationSeconds: 600`.

2. **Run the agent:**

   ```bash
   # AUTHFI_ISSUER, AUTHFI_AGENT_ID, AUTHFI_CONFIG_VERSION, AUTHFI_CONFIG_DIGEST, and PERSON_TOKEN
   node --env-file=.env --import tsx agent.ts
   ```

`connect()` finds the evidence itself, makes the instance's key in memory, and every call after that carries a
DPoP proof of it. The mandate is a credential like the agent's own token: the gateway holds each call to it.
A tool outside it, a spend over its budget and an ended mandate are refused, and the refusal says what the
agent can still do. The cloud credential comes back as a handle; only the runtime fetches the secret.
