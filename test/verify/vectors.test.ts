import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { runVectors } from '../support/vectors.js';

describe('the conformance vectors in Node', () => {
  it('match their checksum', () => {
    const text = readFileSync(new URL('../../conformance/vectors.json', import.meta.url), 'utf8');
    const recorded = readFileSync(
      new URL('../../conformance/vectors.json.sha256', import.meta.url),
      'utf8',
    ).split(/\s+/)[0];
    expect(createHash('sha256').update(text).digest('hex')).toBe(recorded);
  });
  runVectors();
});
