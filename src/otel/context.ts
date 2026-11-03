import { context, ROOT_CONTEXT, type Context, type ContextManager } from '@opentelemetry/api';

interface Storage {
  run<R, A extends unknown[]>(store: Context, fn: (...args: A) => R, ...args: A): R;
  getStore(): Context | undefined;
  disable(): void;
}

/**
 * Keeps the active OpenTelemetry context through `await`s with `AsyncLocalStorage`, as
 * `@opentelemetry/context-async-hooks` does. Without a context manager `context.with` does nothing,
 * so a framework that runs a step inside its span (the AI SDK's tool and model calls do) leaves no
 * active step for a gateway call to name. Event emitters are not bound; nothing here uses them.
 */
class StepContextManager implements ContextManager {
  readonly #storage: Storage;

  constructor(storage: Storage) {
    this.#storage = storage;
  }

  active(): Context {
    return this.#storage.getStore() ?? ROOT_CONTEXT;
  }

  with<A extends unknown[], F extends (...args: A) => ReturnType<F>>(
    ctx: Context,
    fn: F,
    thisArg?: ThisParameterType<F>,
    ...args: A
  ): ReturnType<F> {
    const call = thisArg == null ? fn : fn.bind(thisArg);
    return this.#storage.run(ctx, call, ...args);
  }

  bind<T>(ctx: Context, target: T): T {
    if (typeof target !== 'function') return target;
    const fn = target as unknown as (...a: unknown[]) => unknown;
    return ((...args: unknown[]) => this.with(ctx, () => fn(...args))) as T;
  }

  enable(): this {
    return this;
  }

  disable(): this {
    this.#storage.disable();
    return this;
  }
}

/** A new `AsyncLocalStorage`, where the runtime has one (a Node-like runtime does; some edge runtimes do not). */
function storage(): Storage | undefined {
  try {
    const host = (
      globalThis as {
        process?: {
          getBuiltinModule?: (id: string) => { AsyncLocalStorage?: new () => Storage } | undefined;
        };
      }
    ).process;
    const als = host?.getBuiltinModule?.('node:async_hooks')?.AsyncLocalStorage;
    return als === undefined ? undefined : new als();
  } catch {
    return undefined;
  }
}

/**
 * Registers a context manager when the process has none, so the step a framework is running is the
 * active context. Returns what it registered, or undefined when the app already has a context
 * manager (its own is used) or the runtime cannot hold a context across `await`.
 */
export function installContextManager(): ContextManager | undefined {
  const store = storage();
  if (store === undefined) return undefined;
  const manager = new StepContextManager(store);
  return context.setGlobalContextManager(manager) ? manager : undefined;
}
