import type { OpenTelemetryApi } from '../core/transport.js';
import type { ToolOutcome } from './gateway.js';

/**
 * A gateway decision as a child span of the agent's step, in LangSmith's words.
 *
 * Each decision the gateway makes about a tool call becomes one finished child span of the span that made
 * the call: `langsmith.span.kind` `tool`, and the decision id, the outcome (`allow`, `deny` or
 * `needs_approval`), the rule or grant that decided, and the mandate id, where the gateway named them.
 * Nothing the tool was given or answered is in it. Without OpenTelemetry given to the project, or outside a
 * span, it does nothing.
 */

/** `_meta` key of a result the gateway decided, with the ids it names. */
export const DECISION_META = 'io.authfi/decision';
const REFUSAL_META = 'io.authfi/refusal';
const NAMED = {
  decision_id: 'authfi.decision.id',
  rule: 'authfi.decision.rule',
  grant: 'authfi.decision.grant',
  mandate_id: 'authfi.mandate.id',
} as const;

/** What the decision's span can carry beyond the gateway's answer. */
export interface DecisionNames {
  readonly tool?: string | undefined;
  readonly decisionId?: string | undefined;
  readonly rule?: string | undefined;
  readonly grant?: string | undefined;
  readonly mandateId?: string | undefined;
}

function namedIn(result: unknown): Record<string, string> {
  const meta = (result as { _meta?: Record<string, unknown> } | undefined)?._meta;
  const found: Record<string, string> = {};
  for (const source of [meta?.[DECISION_META], meta?.[REFUSAL_META]]) {
    if (typeof source !== 'object' || source === null) continue;
    for (const [key, value] of Object.entries(source)) {
      if (key in NAMED && typeof value === 'string' && value !== '' && !(key in found)) found[key] = value;
    }
  }
  return found;
}

/** The span attributes of `outcome`. `names` supplies what the gateway's answer did not. */
export function decisionAttributes(outcome: ToolOutcome, names: DecisionNames = {}): Record<string, string> {
  const result = outcome.kind === 'approval_required' ? undefined : outcome.result;
  const found: Record<string, string> = {
    ...namedIn(result),
    ...(names.decisionId ? { decision_id: names.decisionId } : {}),
    ...(names.rule ? { rule: names.rule } : {}),
    ...(names.grant ? { grant: names.grant } : {}),
    ...(names.mandateId ? { mandate_id: names.mandateId } : {}),
  };
  const attributes: Record<string, string> = { 'langsmith.span.kind': 'tool' };
  if (names.tool) attributes['gen_ai.tool.name'] = names.tool;
  if (outcome.kind === 'allowed') {
    attributes['authfi.decision.outcome'] = 'allow';
  } else if (outcome.kind === 'approval_required') {
    attributes['authfi.decision.outcome'] = 'needs_approval';
    attributes['authfi.decision.approval_id'] = outcome.approvalId;
    attributes['authfi.decision.code'] = outcome.code;
  } else {
    attributes['authfi.decision.outcome'] = 'deny';
    const code = outcome.code ?? outcome.error;
    if (code) attributes['authfi.decision.code'] = code;
    if (outcome.reason) attributes['authfi.decision.reason'] = outcome.reason;
    if (outcome.requiredScope) attributes['authfi.decision.required_scope'] = outcome.requiredScope;
    attributes['authfi.decision.why'] = outcome.why;
  }
  for (const [key, attribute] of Object.entries(NAMED)) {
    const value = found[key];
    if (value !== undefined) attributes[attribute] = value;
  }
  return attributes;
}

/**
 * Adds the decision as a finished child span of the active span; a no-op when OpenTelemetry was not given
 * to the project or there is no active span to attach to.
 */
export function recordDecision(
  otel: OpenTelemetryApi | undefined,
  outcome: ToolOutcome,
  names: DecisionNames = {},
): void {
  const trace = otel?.trace;
  if (otel === undefined || trace === undefined) return;
  try {
    const active = trace.getActiveSpan?.();
    const ctx = active?.spanContext();
    if (ctx === undefined || !/^[0-9a-f]{32}$/.test(ctx.traceId) || /^0+$/.test(ctx.traceId)) return;
    const span = trace
      .getTracer('authfi')
      .startSpan(
        names.tool ? `authfi.decision ${names.tool}` : 'authfi.decision',
        { attributes: decisionAttributes(outcome, names) },
        otel.context.active(),
      );
    span.end();
  } catch {
    // A tracer that fails must never fail the call it describes.
  }
}
