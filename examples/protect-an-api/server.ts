// An Express API that accepts AuthFI access tokens: people signed in to your front end, machine
// clients and AI agents, each checked for the permission the route needs.
//
//   AUTHFI_ISSUER=https://<slug>.authfi.io API_AUDIENCE=api_orders,app_web node --import tsx server.ts

import express from 'express';
import { AuthFI } from '@authfi/sdk';
import { authfiErrorHandler, protect } from '@authfi/sdk/express';

const af = AuthFI.fromEnv();

// The audiences this API accepts: its own client id (machine and agent tokens minted with
// resource=api_orders) and the client ids of the front ends that call it (a person's token names
// the app they signed in to). AuthFI's own audiences are refused at startup.
const verifier = af.verifier({
  audience: (process.env.API_AUDIENCE ?? 'api_orders').split(','),
  expectedTenantId: process.env.AUTHFI_TENANT_ID,
});

const app = express();

// Authorize on permissions and roles: on person and machine tokens, scope is what the client asked for.
app.get('/orders', protect(verifier, { permissions: ['orders:read'] }), (req, res) => {
  const token = req.authfi!;
  res.json({
    caller: token.principal.toString(),
    via: token.actor?.toString() ?? null,
    kind: token.tokenKind,
  });
});

// A check inside the handler: refund needs the permission and a recent multi-factor sign-in.
app.post('/orders/:id/refund', protect(verifier), (req, res) => {
  const token = req.authfi!;
  token.requirePermission('orders:refund');
  if (token.tokenKind === 'person') token.requireAcr(['urn:authfi:acr:mfa'], { maxAgeSeconds: 900 });
  res.json({ refunded: req.params.id });
});

// Answers the refusals thrown inside handlers (403 forbidden, 401 step-up) as protect() does.
app.use(authfiErrorHandler());

app.listen(Number(process.env.PORT ?? 3000), () => {
  console.log(`listening on ${process.env.PORT ?? 3000}`);
});
