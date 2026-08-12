/**
 * `stub.fetch` with the retry the runtime asks for. A Durable Object stub is
 * invalidated when the Worker's code reloads under it (deploys in production,
 * per-file module re-evaluation under vitest-pool-workers); the stub then
 * throws a transient marked `retryable: true` whose message literally says
 * "Please retry the `DurableObjectStub#fetch()` call". Retryable means the
 * request never reached the object, so a retry can't double-apply anything.
 * Every DO call site funnels through here so none surfaces that transient.
 */
export async function stubFetch(
  stub: DurableObjectStub,
  input: RequestInfo,
  init?: RequestInit,
): Promise<Response> {
  for (let attempt = 1; ; attempt++) {
    try {
      // Clone per attempt — a failed dispatch may have consumed the body.
      return await stub.fetch(input instanceof Request ? input.clone() : input, init);
    } catch (e) {
      if (attempt >= 3 || !isRetryable(e)) throw e;
    }
  }
}

function isRetryable(e: unknown): boolean {
  const err = e as { retryable?: boolean; message?: unknown } | null;
  return (
    err?.retryable === true ||
    (typeof err?.message === "string" &&
      err.message.includes("invalidating this Durable Object"))
  );
}
