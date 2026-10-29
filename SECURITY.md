# Security

Please report a vulnerability privately, through this repository's **Security** tab ("Report a
vulnerability"), or by email to security@authfi.io. Do not open a public issue.

Include what you found, how to reproduce it, and the version or commit. We acknowledge a report
within two working days and keep you informed until it is fixed.

## What this SDK guarantees

- It never prints, logs or serialises a secret: client secrets, tokens, assertions and keys are held
  in `Secret`, and `reveal()` is the one way to read one.
- A credential is sent only to the origins its `TokenSource` names.
- It never follows a redirect, and never retries a request that may have created state.
- Its verifier refuses `none` and `HS*`, keys from the token, ID tokens as bearers, and audiences
  that belong to AuthFI itself; refusal causes stay off the wire unless an API opts in.

A way around any of these is a vulnerability: please report it.
