# SAML sign-in for a standard app

An app that speaks SAML 2.0 and no OpenID Connect uses AuthFI as its identity provider. `@authfi/sdk/saml`
is the service-provider side: it reads the project's metadata, sends the browser to AuthFI, and turns the
returned assertion into the same user model the OpenID Connect sign-in gives.

```bash
npm install github:authfi/authfi-nodejs-sdk#main @node-saml/node-saml @xmldom/xmldom
```

Both are optional peers of the SDK; install them only for SAML. Register the app in your project first: its
entity id and its assertion consumer URL (ACS). Then:

```ts
import { AuthFI } from '@authfi/sdk';
import { PendingSamlSignIn, SamlServiceProvider } from '@authfi/sdk/saml';

const af = new AuthFI({ issuer: process.env.AUTHFI_ISSUER! });
const sp = await SamlServiceProvider.fromProject(af, {
  spEntityId: 'https://app.example.com/saml', // as registered in the project
  acsUrl: 'https://app.example.com/saml/acs', // as registered in the project
});

// GET /login
const pending = await sp.startSignIn('/dashboard');
req.session.saml = pending.dump(); // keep it server-side
res.redirect(pending.url);

// POST /saml/acs
const signedIn = await sp.finishSignIn(req.body.SAMLResponse, PendingSamlSignIn.load(req.session.saml));
signedIn.user.sub; // the assertion's NameID
signedIn.user.email; signedIn.user.groups; signedIn.user.roles;
signedIn.relayState; // "/dashboard"
```

`fromProject` reads `<project origin>/saml/metadata` and refuses metadata that does not name that address as
its entity id. Only the first certificate of the signing key descriptor may sign an assertion.

## What is checked

`finishSignIn` accepts an assertion only when all of this holds, and throws `SamlAssertionRefused` with a
stable `code` otherwise:

| check                                                                                        | code on failure                                                      |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| the Assertion is signed with a key in the project's metadata                                 | `saml_signature_invalid`                                             |
| every signature and digest algorithm is SHA-256 or stronger                                  | `saml_algorithm_rejected`                                            |
| exactly one assertion, and the signed element is the one read                                | `saml_assertion_count`                                               |
| the audience is your `spEntityId`                                                            | `saml_audience_mismatch`                                             |
| a bearer confirmation names your `acsUrl` as its recipient (not the host of the request)     | `saml_recipient_mismatch`                                            |
| the issuer is the project                                                                    | `saml_issuer_mismatch`                                               |
| `InResponseTo` is the request this browser started                                           | `saml_in_response_to_mismatch`                                       |
| it is inside its validity window, with `leewayMs` of skew                                    | `saml_assertion_expired`, `saml_assertion_not_yet_valid`             |
| it was not used before                                                                       | `saml_assertion_replayed`                                            |
| the sign-in was started in the last ten minutes                                              | `saml_pending_expired`                                               |

A response with a DTD, a non-base64 body, an unsigned assertion or an encrypted assertion is refused too.

An assertion is accepted once. The default replay store is per process: pass `replayStore` (anything with
`remember(key, expiresAtMs, nowMs)`) backed by Redis or your database when several processes serve the ACS.

## The user

`signedIn.user` has the same shape as the OpenID Connect sign-in's: `sub` is the NameID, `email` comes from the
`email` attribute (or an email-format NameID), `groups` and `roles` from the attributes of those names, `acr`
from the authentication context, `authTime` from `AuthnInstant`, and `claims.saml_attributes` holds every
attribute. `emailVerified` is never claimed. Pass `attributes: { email: ['work_email'] }` to read other
attribute names.

## Launching from the AuthFI portal

A tile in the portal starts at the identity provider, so the response answers no request of yours. Build the
provider with `allowIdpInitiated: true` and call `finishSignIn(response, undefined)`. It is still signed,
checked and single-use; do not trust a `RelayState` that arrives that way.
