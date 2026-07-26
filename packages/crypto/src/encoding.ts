import { base32crockford, base64urlnopad } from "@scure/base";

export function toB64url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

export function fromB64url(s: string): Uint8Array {
  return base64urlnopad.decode(s);
}

export function toCrockford(bytes: Uint8Array): string {
  return base32crockford.encode(bytes);
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
