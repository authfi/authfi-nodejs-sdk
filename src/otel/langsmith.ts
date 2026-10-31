/**
 * The same spans to LangSmith and to AuthFI: LangSmith's OpenTelemetry mapping, and no secret in a span.
 *
 * LangSmith reads an OpenTelemetry span through these attributes: `langsmith.span.kind` (the run type:
 * `llm`, `chain`, `tool`, `retriever`, `embedding`, `prompt`, `parser`), `langsmith.trace.name` (the run's
 * name), `langsmith.metadata.<key>`, and the span's OpenTelemetry parent (the run tree). It reads the
 * `gen_ai.*` attributes too. {@link LangSmithProcessor} sets the first three where the framework's own
 * instrumentation left them out, so one span carries what both products read. A customer who also exports
 * to LangSmith adds LangSmith's exporter to the same provider and changes no code.
 *
 * {@link redactSpan} runs on every export, whether or not content capture is on: a value shaped like a
 * token or a key, and any attribute named like a credential, leaves as `[redacted]`.
 */

import type { ReadableSpan, Span, SpanProcessor } from '@opentelemetry/sdk-trace-base';

/** What a secret-shaped value or a credential-named attribute leaves as. */
export const REDACTED = '[redacted]';

const SECRET_VALUE = new RegExp(
  [
    String.raw`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`, // a JWT
    String.raw`\b(?:Bearer|DPoP|Basic)\s+[A-Za-z0-9._~+/=-]{8,}`, // an Authorization value
    String.raw`\bsk-[A-Za-z0-9_-]{16,}`, // a provider key
    String.raw`\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{16,}`,
    String.raw`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`, // an AWS key id
    '-----BEGIN [A-Z ]*PRIVATE KEY-----',
    String.raw`\bxox[abprs]-[A-Za-z0-9-]{10,}`,
  ].join('|'),
  'g',
);
const SECRET_NAME =
  /(?:^|[._-])(?:authorization|api[_-]?key|password|passwd|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|credentials?|cookie|session[_-]?token)s?(?:$|[._-])/i;

/** `gen_ai.operation.name` values and the LangSmith run type each one is. */
const RUN_TYPES: Readonly<Record<string, string>> = {
  chat: 'llm',
  text_completion: 'llm',
  completion: 'llm',
  generate_content: 'llm',
  embeddings: 'embedding',
  embedding: 'embedding',
  execute_tool: 'tool',
  retrieval: 'retriever',
  invoke_agent: 'chain',
  create_agent: 'chain',
};

/** The LangSmith run type of a span with these attributes (`chain` when nothing says otherwise). */
export function runTypeOf(attributes: Readonly<Record<string, unknown>>): string {
  const named = attributes['langsmith.span.kind'];
  if (typeof named === 'string' && named !== '') return named;
  const operation = attributes['gen_ai.operation.name'];
  if (typeof operation === 'string' && operation in RUN_TYPES) return RUN_TYPES[operation] ?? 'chain';
  if ('gen_ai.tool.name' in attributes) return 'tool';
  return 'chain';
}

/** Sets `langsmith.span.kind`, `langsmith.trace.name` (on a root span) and the AuthFI agent and run as metadata. */
export class LangSmithProcessor implements SpanProcessor {
  readonly #metadata: Readonly<Record<string, string>>;

  /** @param metadata AuthFI values to carry as `langsmith.metadata.<key>` (`authfi_agent_id`, `authfi_run_id`). */
  constructor(metadata: Readonly<Record<string, string>> = {}) {
    this.#metadata = metadata;
  }

  onStart(span: Span): void {
    const current = span.attributes;
    if (!('langsmith.span.kind' in current)) span.setAttribute('langsmith.span.kind', runTypeOf(current));
    if (span.parentSpanContext === undefined && !('langsmith.trace.name' in current))
      span.setAttribute('langsmith.trace.name', span.name);
    for (const [key, value] of Object.entries(this.#metadata)) {
      const name = `langsmith.metadata.${key}`;
      if (!(name in current)) span.setAttribute(name, value);
    }
  }

  onEnd(): void {
    // Everything is set at the start.
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

function cleanValue(value: unknown): unknown {
  if (typeof value === 'string') return value.replace(SECRET_VALUE, REDACTED);
  if (Array.isArray(value)) return value.map(cleanValue);
  return value;
}

function clean(attributes: Readonly<Record<string, unknown>>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(attributes).map(([k, v]) => [k, SECRET_NAME.test(k) ? REDACTED : cleanValue(v)]),
  );
}

/** `span` with every secret-shaped value and credential-named attribute replaced; `span` itself if clean. */
export function redactSpan(span: ReadableSpan): ReadableSpan {
  const attributes = clean(span.attributes);
  const events = span.events.map((e) => {
    const cleaned = clean(e.attributes ?? {});
    return JSON.stringify(cleaned) === JSON.stringify(e.attributes ?? {}) ? e : { ...e, attributes: cleaned };
  });
  const name = span.name.replace(SECRET_VALUE, REDACTED);
  const description = span.status.message;
  const status =
    description !== undefined && description.replace(SECRET_VALUE, REDACTED) !== description
      ? { ...span.status, message: description.replace(SECRET_VALUE, REDACTED) }
      : span.status;
  const same =
    JSON.stringify(attributes) === JSON.stringify(span.attributes) &&
    events.every((e, i) => e === span.events[i]) &&
    name === span.name &&
    status === span.status;
  if (same) return span;
  return new Proxy(span, {
    get(target, prop) {
      if (prop === 'attributes') return attributes;
      if (prop === 'events') return events;
      if (prop === 'name') return name;
      if (prop === 'status') return status;
      const value: unknown = Reflect.get(target, prop, target);
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}
