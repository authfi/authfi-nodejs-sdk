'use strict';

// Stable refusal codes. A code names the rule that refused; the message is fixed text and never
// holds a token, a proof, a signature or a claim value.
class AuthFIError extends Error {
  constructor(code, message) {
    super(message ? `authfi: ${code}: ${message}` : `authfi: ${code}`);
    this.name = 'AuthFIError';
    this.code = code;
  }
}

const refuse = (code, message) => new AuthFIError(code, message);

module.exports = { AuthFIError, refuse };
