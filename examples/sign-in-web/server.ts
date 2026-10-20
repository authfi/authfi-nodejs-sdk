// Sign people in to an Express app: the authorization code flow with PKCE, the pending sign-in
// kept encrypted in a cookie, tokens in a server-side store, refresh, and a sign-out that revokes.
//
//   node --env-file=.env --import tsx server.ts

import { randomUUID } from 'node:crypto';
import express, { type Request } from 'express';
import { AuthFI, isAuthFIError, MemoryTokenStore, Secret } from '@authfi/sdk';

const af = AuthFI.fromEnv();
const web = af.webApp({
  clientId: process.env.AUTHFI_CLIENT_ID ?? '',
  clientSecret: new Secret(process.env.AUTHFI_CLIENT_SECRET ?? ''),
  redirectUri: process.env.REDIRECT_URI ?? 'http://localhost:3000/callback',
  // 32 random bytes in base64. It encrypts the pending sign-in, which holds the PKCE verifier and
  // the nonce: a signed cookie would hand them to the browser.
  stateKey: new Secret(process.env.AUTHFI_STATE_KEY ?? ''),
});
// One process only. With several workers or pods, use a shared store with an atomic compareAndSet.
const store = new MemoryTokenStore();

const cookie = (req: Request, name: string): string | undefined =>
  (req.headers.cookie ?? '')
    .split(';')
    .map((c) => c.trim().split('='))
    .find(([k]) => k === name)?.[1];
const SECURE = 'HttpOnly; Secure; SameSite=Lax; Path=/';

const app = express();

app.get('/login', async (_req, res) => {
  const pending = await web.startSignIn({ scope: ['openid', 'profile', 'email'] });
  res.setHeader('set-cookie', `authfi_pending=${await pending.dump()}; Max-Age=600; ${SECURE}`);
  res.redirect(pending.url);
});

app.get('/callback', async (req, res) => {
  try {
    const pending = await web.loadPending(cookie(req, 'authfi_pending') ?? '');
    const { tokens, user } = await web.finishSignIn(req.originalUrl, pending);
    const sid = randomUUID();
    await store.compareAndSet(sid, undefined, tokens);
    res.setHeader('set-cookie', [`authfi_pending=; Max-Age=0; ${SECURE}`, `sid=${sid}; ${SECURE}`]);
    res.send(`Signed in as ${user.email ?? user.sub}`);
  } catch (e) {
    if (isAuthFIError(e, 'StepUpRequired')) {
      const pending = await web.startSignIn({ acrValues: e.acrValues });
      res.setHeader('set-cookie', `authfi_pending=${await pending.dump()}; Max-Age=600; ${SECURE}`);
      res.redirect(pending.url);
      return;
    }
    res.status(400).send(isAuthFIError(e) ? `Sign-in failed (${e.code})` : 'Sign-in failed');
  }
});

app.get('/me', async (req, res) => {
  const sid = cookie(req, 'sid');
  if (sid === undefined) {
    res.redirect('/login');
    return;
  }
  // The person's token, refreshed through the store when it nears expiry.
  const session = web.session({ key: sid, store });
  const tokens = await store.load(sid);
  if (tokens === undefined) {
    res.redirect('/login');
    return;
  }
  await session.token();
  res.json(await web.userinfo((await store.load(sid)) ?? tokens));
});

app.get('/logout', async (req, res) => {
  const sid = cookie(req, 'sid');
  const tokens = sid === undefined ? undefined : await store.load(sid);
  if (sid !== undefined) await store.delete(sid);
  res.setHeader('set-cookie', `sid=; Max-Age=0; ${SECURE}`);
  if (tokens === undefined) {
    res.redirect('/');
    return;
  }
  // Revokes the refresh token, then sends the browser to the platform's sign-out.
  res.redirect(await web.signOut(tokens, { postLogoutRedirectUri: process.env.POST_LOGOUT_URI }));
});

app.listen(Number(process.env.PORT ?? 3000));
