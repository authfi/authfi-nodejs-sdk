import type { OpenTelemetryApi } from './transport.js';

const TRACE_ID = /^[0-9a-f]{32}$/;
const SPAN_ID = /^[0-9a-f]{16}$/;
const ZEROS = /^0+$/;

/**
 * The `traceparent` of the step running now: the trace id and span id of the active OpenTelemetry
 * span, which is the span a tracer exports for that step. Undefined when no step is active, and the
 * caller then sends a fresh unsampled one.
 *
 * The registered propagator is asked first, so its `tracestate` goes along. Where none is registered
 * (a tracer provider on its own does not register one) the header is made from the span's own ids,
 * so the id sent is the id exported either way.
 */
export function stepTraceparent(otel: OpenTelemetryApi | undefined): Record<string, string> | undefined {
  if (otel === undefined) return undefined;
  const active = otel.context.active();
  const carrier: Record<string, string> = {};
  otel.propagation.inject(active, carrier);
  if (carrier.traceparent !== undefined) return carrier;
  const span = otel.trace?.getSpanContext?.(active);
  if (span === undefined || !TRACE_ID.test(span.traceId) || !SPAN_ID.test(span.spanId)) return undefined;
  if (ZEROS.test(span.traceId) || ZEROS.test(span.spanId)) return undefined;
  const flags = (span.traceFlags & 0xff).toString(16).padStart(2, '0');
  return { traceparent: `00-${span.traceId}-${span.spanId}-${flags}` };
}
