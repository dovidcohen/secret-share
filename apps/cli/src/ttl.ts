import { MAX_TTL_SECONDS, MIN_TTL_SECONDS } from "@secret-share/protocol";

export class TtlFormatError extends Error {
  override name = "TtlFormatError";
}

const UNIT_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3_600,
  d: 86_400,
};

/**
 * Parses "90s", "30m", "2h", "1d", or a bare number of seconds into seconds,
 * enforcing the protocol's 60s..7d bounds.
 */
export function parseTtl(input: string): number {
  const m = /^(\d+)\s*([smhd]?)$/i.exec(input.trim());
  if (!m) {
    throw new TtlFormatError(
      `Cannot parse TTL "${input}" — use e.g. 90s, 30m, 2h, 1d`,
    );
  }
  const unit = (m[2] || "s").toLowerCase();
  const seconds = Number(m[1]) * (UNIT_SECONDS[unit] ?? 1);
  if (seconds < MIN_TTL_SECONDS || seconds > MAX_TTL_SECONDS) {
    throw new TtlFormatError(
      `TTL must be between ${MIN_TTL_SECONDS}s and 7d, got ${input}`,
    );
  }
  return seconds;
}

/** "86400" -> "24h" — for the human-readable expiry line. */
export function formatTtl(seconds: number): string {
  if (seconds % 86_400 === 0) return `${seconds / 86_400}d`;
  if (seconds % 3_600 === 0) return `${seconds / 3_600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}
