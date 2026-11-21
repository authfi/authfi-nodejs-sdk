# Express: protect an API

```bash
npm install @authfi/sdk express
```

```ts
import { AuthFI } from '@authfi/sdk';
import { protect, authfiErrorHandler } from '@authfi/sdk/express';

const af = AuthFI.fromEnv();
const verifier = af.verifier({ audience: ['api_orders'], expectedTenantId: process.env.AUTHFI_TENANT_ID });

app.get('/orders', protect(verifier, { permissions: ['orders:read'] }), (req, res) => {
  res.json({ caller: req.authfi!.principal.toString() });
});
app.use(authfiErrorHandler());
```

- `audience` is your API's client id, and the client ids of the front ends that call it. Every token is checked for
  its type, issuer, audience, expiry and tenant; a refused one gets an opaque 401 and the reason goes to your log.
- The same verifier checks a person's token and an agent's: the caller is `req.authfi.principal`, and for an agent
  acting for a person, the person with the agent as the actor.
- `permissions` are resolved by your project's policy, not read from the token.
