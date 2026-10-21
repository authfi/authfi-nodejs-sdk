# Acting for a caller with no browser (CIBA)

A phone caller cannot follow a redirect, so the agent asks AuthFI to ask them on a separate channel:
a card in their AuthFI app, or a link by email or SMS. They read the **binding message** ("Refund
order 4411") and approve or refuse. The agent never sees a code or a credential, so a cloned voice
cannot approve for them.

```bash
cp .env.example .env
CALLER=ada@example.com node --env-file=.env --import tsx agent.ts
```

- `bindingMessage` is required: it is the line the person reads before approving.
- The token the agent receives names the caller as subject and the agent as actor, with the
  caller's approval intersected with the agent's capabilities. It is not renewed: near expiry it
  raises `ConsentExpired`, and the agent asks again.
- A refusal is `ConsentDenied`. The request is sent once: a retry would ask the person twice.
