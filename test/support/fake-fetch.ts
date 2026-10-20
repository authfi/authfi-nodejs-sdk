// A fetch double that routes by method and URL, records every request, and answers with real
// Response objects, so the SDK runs its real parsing, header and abort code against it.

export interface Recorded {
  readonly method: string;
  readonly url: string;
  readonly headers: Headers;
  readonly body: string;
}

export type Handler = (req: Recorded, n: number) => Response | Promise<Response>;

export class FakeFetch {
  readonly requests: Recorded[] = [];
  readonly #routes: { method: string; match: (url: string) => boolean; handler: Handler; count: number }[] =
    [];

  /** Answers `method url` (an exact URL, or a predicate) with the handler; the newest route wins. */
  on(method: string, url: string | ((url: string) => boolean), handler: Handler): this {
    const match = typeof url === 'string' ? (u: string) => u.split('?')[0] === url : url;
    this.#routes.unshift({ method, match, handler, count: 0 });
    return this;
  }

  /** The requests sent to a URL (query ignored). */
  to(url: string): Recorded[] {
    return this.requests.filter((r) => r.url.split('?')[0] === url);
  }

  readonly fetch: typeof fetch = async (input, init) => {
    const request = new Request(input, init);
    const recorded: Recorded = {
      method: request.method,
      url: request.url,
      headers: new Headers(request.headers),
      body: request.body === null ? '' : await request.text(),
    };
    this.requests.push(recorded);
    const route = this.#routes.find((r) => r.method === recorded.method && r.match(recorded.url));
    if (route === undefined) return json({ error: 'not_found' }, 404);
    route.count += 1;
    const signal = init?.signal ?? undefined;
    const answer = route.handler(recorded, route.count);
    if (signal === undefined) return answer;
    return Promise.race([
      answer,
      new Promise<Response>((_, reject) => {
        if (signal.aborted) reject(signal.reason);
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      }),
    ]);
  };
}

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** A handler that never answers (until the request is aborted). */
export function hang(): Promise<Response> {
  return new Promise(() => undefined);
}

/** A network failure, as fetch raises it for a refused connection or a reset. */
export function networkError(): never {
  throw new TypeError('fetch failed');
}
