// A scheduled job that calls the orders API as a machine client, with a token for that API only.
//
//   AUTHFI_ISSUER=… AUTHFI_CLIENT_ID=… AUTHFI_CLIENT_SECRET=… ORDERS_API=https://api.example.com node --import tsx job.ts

import { AuthFI, isAuthFIError, Secret } from '@authfi/sdk';

const af = AuthFI.fromEnv();
const ordersApi = process.env.ORDERS_API ?? 'https://api.example.com';

const m2m = af.clientCredentials({
  clientId: process.env.AUTHFI_CLIENT_ID ?? '',
  clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET ?? ''),
  resource: 'api_orders', // the API's client id: the token's audience
  sendTo: [ordersApi], // the token is sent here and nowhere else
});

try {
  // The token is minted once, cached, and renewed at two thirds of its lifetime.
  const res = await m2m.fetch(`${ordersApi}/orders?status=open`);
  console.log(res.status, await res.json());
} catch (e) {
  if (isAuthFIError(e, 'OAuthError')) console.error('the token endpoint refused:', e.code, e.requestId);
  else throw e;
}
