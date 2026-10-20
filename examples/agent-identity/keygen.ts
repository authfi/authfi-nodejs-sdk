// Makes the agent's key pair, writes the private key to a 0600 file, and prints the public JWK and
// its thumbprint to register in the console (AI Agents, then the agent, then Keys).
//
//   node --import tsx keygen.ts ./agent-key.pem

import { generateAgentKeyFile } from '@authfi/sdk/node';

const file = process.argv[2] ?? './agent-key.pem';
const key = await generateAgentKeyFile(file, 'EdDSA'); // a new file, owner-only; never overwrites
console.log(
  JSON.stringify({ kid: key.kid, thumbprint: await key.thumbprint(), public_jwk: key.publicJwk() }, null, 2),
);
console.log(
  `private key written to ${file}; set AUTHFI_AGENT_KEY_FILE=${file} and AUTHFI_AGENT_KID=${key.kid}`,
);
