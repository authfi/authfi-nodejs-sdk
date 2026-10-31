/**
 * The steps of an agent's framework, exported to AuthFI as OpenTelemetry traces. Spans go to
 * `<issuer origin>/otlp/v1/traces` (OTLP/HTTP, protobuf) under the agent's own token, so AuthFI
 * keeps each span as that agent's. The token is read for every export, so a renewed or refreshed
 * token is used and none is held in a header. What was said (prompts, answers, tool arguments and
 * results) is dropped before export unless `captureContent` is on; the gateway drops it too.
 *
 * `@opentelemetry/api`, `@opentelemetry/sdk-trace-base` and `@opentelemetry/otlp-transformer` are
 * optional peers: install them to use this entry.
 *
 * @example
 * const credential = await connect();
 * const telemetry = await registerAuthFITelemetry({ source: credential });
 * // ... run the agent; the AI SDK's own OpenTelemetry integration now reports to AuthFI ...
 * await telemetry.shutdown();
 *
 * @packageDocumentation
 */

import { trace, type Tracer, type TracerProvider } from '@opentelemetry/api';
import { ProtobufTraceSerializer } from '@opentelemetry/otlp-transformer';
import {
  BasicTracerProvider,
  BatchSpanProcessor,
  type ReadableSpan,
  type Span,
  type SpanExporter,
  type SpanProcessor,
} from '@opentelemetry/sdk-trace-base';
import { ConfigurationError, GatewayTokenRefused } from '../core/errors.js';
import { isValidRunId, newRunId } from '../core/ids.js';
import { consoleLogger, type Logger } from '../core/logger.js';
import type { Gateway } from '../gateway/gateway.js';
import { LangSmithProcessor, redactSpan } from './langsmith.js';

/** A credential the exporter can use: anything with gateways, an `AgentAuth` or a `ClientCredentials`. */
export interface TelemetrySource {
  gateway(): Gateway;
  /** Used to renew the token once when the endpoint refuses it. */
  token?(options?: { force?: boolean }): Promise<string>;
}

/** The result of one export, in the shape OpenTelemetry's `ExportResult` has (0 success, 1 failed). */
interface Result {
  code: 0 | 1;
  error?: Error;
}

/** Attributes that carry what was said, not what was done. Dropped unless `captureContent` is on. */
const CONTENT_ATTRIBUTE =
  /^(gen_ai\.(input\.messages|output\.messages|system_instructions|prompt|completion|tool\.call\.(arguments|result))(\..*)?|llm\.(input|output)_messages.*|ai\.(prompt|response\.(text|object|toolCalls|reasoning)|toolCall\.(args|result)).*)$/;
const EXPORT_TIMEOUT_MS = 10_000;

/** Whether `name` is an attribute that carries content. */
export function isContentAttribute(name: string): boolean {
  return CONTENT_ATTRIBUTE.test(name);
}

function withoutContent(span: ReadableSpan): ReadableSpan {
  const attributes = Object.fromEntries(
    Object.entries(span.attributes).filter(([k]) => !isContentAttribute(k)),
  );
  const events = span.events.filter((e) => !e.name.startsWith('gen_ai.'));
  return new Proxy(span, {
    get(target, prop) {
      if (prop === 'attributes') return attributes;
      if (prop === 'events') return events;
      const value: unknown = Reflect.get(target, prop, target);
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  });
}

/** Exports spans to AuthFI. Made by {@link registerAuthFITelemetry}; use it directly with your own provider. */
export class AuthFISpanExporter implements SpanExporter {
  readonly #source: TelemetrySource;
  readonly #gateway: Gateway;
  readonly #capture: boolean;
  readonly #logger: Logger;
  #closed = false;

  constructor(options: { source: TelemetrySource; captureContent?: boolean; logger?: Logger }) {
    if (typeof (options.source as Partial<TelemetrySource> | undefined)?.gateway !== 'function') {
      throw new ConfigurationError(
        'source must be an AgentAuth or a ClientCredentials: the exporter sends its token to AuthFI',
      );
    }
    this.#source = options.source;
    this.#gateway = options.source.gateway();
    this.#capture = options.captureContent === true;
    this.#logger = options.logger ?? consoleLogger;
  }

  export(spans: ReadableSpan[], resultCallback: (result: Result) => void): void {
    if (this.#closed) {
      resultCallback({ code: 1, error: new Error('the AuthFI exporter is shut down') });
      return;
    }
    this.#send(spans).then(
      () => {
        resultCallback({ code: 0 });
      },
      (error: unknown) => {
        this.#logger.warn('AuthFI did not take the trace export', { error: String(error) });
        resultCallback({ code: 1, error: error instanceof Error ? error : new Error(String(error)) });
      },
    );
  }

  async #post(body: Uint8Array): Promise<Response> {
    return this.#gateway.fetch(this.#gateway.otlpTracesUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/x-protobuf' },
      body: body as BodyInit,
      signal: AbortSignal.timeout(EXPORT_TIMEOUT_MS),
    });
  }

  async #send(spans: ReadableSpan[]): Promise<void> {
    // A secret never leaves in a span, with content capture on or off.
    const body = ProtobufTraceSerializer.serializeRequest(
      spans.map((s) => redactSpan(this.#capture ? s : withoutContent(s))),
    );
    if (body === undefined) return;
    let res: Response;
    try {
      res = await this.#post(body);
    } catch (error) {
      // A token the endpoint refuses is renewed once; a second refusal is the answer.
      if (!(error instanceof GatewayTokenRefused) || this.#source.token === undefined) throw error;
      await this.#source.token({ force: true });
      res = await this.#post(body);
    }
    if (res.status !== 200) {
      await res.body?.cancel();
      throw new Error(`AuthFI refused the trace export: HTTP ${String(res.status)}`);
    }
    const answer = ProtobufTraceSerializer.deserializeResponse(new Uint8Array(await res.arrayBuffer()));
    const rejected = answer.partialSuccess?.rejectedSpans ?? 0;
    if (rejected > 0) this.#logger.warn('AuthFI did not keep some spans', { rejected });
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    this.#closed = true;
    return Promise.resolve();
  }
}

/** Puts `authfi.agent_id` and `authfi.run_id` on every span at its start. */
class StampProcessor implements SpanProcessor {
  readonly #attributes: Record<string, string>;
  constructor(attributes: Record<string, string>) {
    this.#attributes = attributes;
  }
  onStart(span: Span): void {
    span.setAttributes(this.#attributes);
  }
  onEnd(): void {
    // Stamping happens at the start.
  }
  forceFlush(): Promise<void> {
    return Promise.resolve();
  }
  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

/** How {@link registerAuthFITelemetry} is configured. */
export interface AuthFITelemetryOptions {
  /** The credential that exports: the agent, or a machine client. */
  readonly source: TelemetrySource;
  /** The run's id, on every span as `authfi.run_id`. Use the adapter's `runId` to join them; else one is made. */
  readonly runId?: string | undefined;
  /** Export prompts, answers and tool payloads. Off by default; a tenant policy decision. */
  readonly captureContent?: boolean | undefined;
  /**
   * Make this the process's tracer provider (`trace.setGlobalTracerProvider`). Default true; it
   * throws when another provider is already registered. With `false`, give `tracer` to the
   * framework.
   */
  readonly global?: boolean | undefined;
  /** How often the batch is sent, in milliseconds (default 5 000). */
  readonly scheduleDelayMs?: number | undefined;
  readonly logger?: Logger | undefined;
}

/** What {@link registerAuthFITelemetry} made. */
export interface AuthFITelemetry {
  readonly runId: string;
  readonly tracerProvider: TracerProvider;
  /** A tracer on that provider, for a framework that takes one (`new OpenTelemetry({ tracer })`). */
  readonly tracer: Tracer;
  /** Sends what is buffered now. */
  forceFlush(): Promise<void>;
  /** Sends what is buffered and stops. Call it before the process exits. */
  shutdown(): Promise<void>;
}

/**
 * Sends the steps of the agent's framework to AuthFI: a tracer provider that exports to
 * `<issuer origin>/otlp/v1/traces` under the credential's current token, stamps `authfi.agent_id` and
 * `authfi.run_id` on every span, and drops content unless `captureContent` is on. To join a step
 * with the gateway's record of the call, build the project with the same `@opentelemetry/api`
 * (`connect()` does): calls then carry the active trace as `traceparent`.
 */
export function registerAuthFITelemetry(options: AuthFITelemetryOptions): AuthFITelemetry {
  const runId = options.runId ?? newRunId();
  if (!isValidRunId(runId))
    throw new ConfigurationError('runId must be 1-96 of A-Z a-z 0-9 . _ : - (it prefixes X-Request-Id)');
  const exporter = new AuthFISpanExporter({
    source: options.source,
    ...(options.captureContent === undefined ? {} : { captureContent: options.captureContent }),
    ...(options.logger === undefined ? {} : { logger: options.logger }),
  });
  const agentId = options.source.gateway().agentId;
  const provider = new BasicTracerProvider({
    spanProcessors: [
      new StampProcessor({
        ...(agentId === undefined ? {} : { 'authfi.agent_id': agentId }),
        'authfi.run_id': runId,
      }),
      // LangSmith's run type, trace name and metadata, so the same spans go to LangSmith and to AuthFI.
      new LangSmithProcessor({
        ...(agentId === undefined ? {} : { authfi_agent_id: agentId }),
        authfi_run_id: runId,
      }),
      new BatchSpanProcessor(exporter, {
        scheduledDelayMillis: options.scheduleDelayMs ?? 5000,
      }),
    ],
  });
  if (options.global !== false && !trace.setGlobalTracerProvider(provider)) {
    void provider.shutdown();
    throw new ConfigurationError(
      'a tracer provider is already registered; pass global: false and give the framework result.tracer',
    );
  }
  return {
    runId,
    tracerProvider: provider,
    tracer: provider.getTracer('@authfi/sdk'),
    forceFlush: () => provider.forceFlush(),
    shutdown: () => provider.shutdown(),
  };
}
