/// <reference types="node" />

/**
 * Whether the running code is inside `agent.withMandate(...)`, only to refuse a second mandate there.
 * It needs `AsyncLocalStorage`, which a Node-like runtime has and a browser or edge runtime may not; where
 * it is missing nothing is tracked, and the one-level rule rests on the gateway, which refuses a call the
 * mandate does not cover whatever started it.
 */
import { ConfigurationError } from '../core/errors.js';

interface Storage {
  run<T>(store: boolean, fn: () => T): T;
  getStore(): boolean | undefined;
}

function storage(): Storage | undefined {
  try {
    const process = (
      globalThis as {
        process?: {
          getBuiltinModule?: (id: string) => { AsyncLocalStorage?: new () => Storage } | undefined;
        };
      }
    ).process;
    const als = process?.getBuiltinModule?.('node:async_hooks')?.AsyncLocalStorage;
    return als === undefined ? undefined : new als();
  } catch {
    return undefined;
  }
}

const inside = storage();

/** A mandate is one level deep: nothing started inside one can be a mandate. */
export function refuseNested(): void {
  if (inside?.getStore() === true) {
    throw new ConfigurationError(
      'a mandate is one level deep: you are inside one already. Nothing a mandate does can start another or widen it. Finish this mandate, and ask the person for the next.',
    );
  }
}

/** Runs `fn` as the body of a mandate. */
export function runInMandate<T>(fn: () => T): T {
  return inside === undefined ? fn() : inside.run(true, fn);
}
