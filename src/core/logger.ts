/** Structured fields on a log line. The SDK never puts a secret in them. */
export type LogFields = Readonly<Record<string, unknown>>;

/**
 * Where the SDK logs. Any logger with these four methods fits (pino, winston, console). The SDK
 * never passes a secret value to it; a redaction filter runs on every message and field as a second
 * net.
 */
export interface Logger {
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
}

const JWT_SHAPED = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const BEARER = /\b(Bearer|DPoP)\s+[A-Za-z0-9._~+/=-]+/gi;

/** Replaces JWT-shaped strings and `Bearer …` credentials in a string with a placeholder. */
export function redact(text: string): string {
  return text.replace(JWT_SHAPED, '[redacted-jwt]').replace(BEARER, '$1 [redacted]');
}

function redactValue(value: unknown, depth: number): unknown {
  if (typeof value === 'string') return redact(value);
  if (depth > 3 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, depth + 1);
  return out;
}

/** Wraps a logger so every message and field passes the redaction filter. */
export function redactingLogger(inner: Logger): Logger {
  const wrap =
    (level: keyof Logger) =>
    (message: string, fields?: LogFields): void => {
      const safe = fields === undefined ? undefined : (redactValue(fields, 0) as LogFields);
      if (safe === undefined) inner[level](redact(message));
      else inner[level](redact(message), safe);
    };
  return { debug: wrap('debug'), info: wrap('info'), warn: wrap('warn'), error: wrap('error') };
}

/** The default logger: warnings and errors to the console, prefixed `[authfi]`; debug and info are dropped. */
export const consoleLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: (message, fields) => {
    console.warn(`[authfi] ${message}`, ...(fields === undefined ? [] : [fields]));
  },
  error: (message, fields) => {
    console.error(`[authfi] ${message}`, ...(fields === undefined ? [] : [fields]));
  },
};

/** Logs a warning once per key for the lifetime of the set it is given. */
export function warnOnce(
  logger: Logger,
  seen: Set<string>,
  key: string,
  message: string,
  fields?: LogFields,
): void {
  if (seen.has(key)) return;
  seen.add(key);
  if (fields === undefined) logger.warn(message);
  else logger.warn(message, fields);
}
