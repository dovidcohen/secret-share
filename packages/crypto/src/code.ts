import { WORDLIST } from "./wordlist.js";
import { randomBytes, toCrockford } from "./encoding.js";

export interface ShareCode {
  /** Canonical display form: "XKQ2-M7PT-tiger-ocean-cable-ruby-drum". */
  code: string;
  /** 8 Crockford base32 chars (40 random bits) — the only part the server ever sees. */
  mailboxId: string;
  /** 5 EFF-wordlist words = 64.6 bits of key entropy; never sent to the server. */
  words: string[];
}

export const WORD_COUNT = 5;
export const MAILBOX_ID_BYTES = 5; // 40 bits -> 8 crockford chars

const WORDSET = new Set(WORDLIST);
const MAILBOX_ID_RE = /^[0-9A-HJKMNP-TV-Z]{8}$/;

export class CodeFormatError extends Error {
  override name = "CodeFormatError";
}

/** Uniform draw in [0, 7776) via rejection sampling on 16-bit values. */
function randomWordIndex(): number {
  const limit = 65536 - (65536 % WORDLIST.length); // 62208
  for (;;) {
    const b = randomBytes(2);
    const v = ((b[0] ?? 0) << 8) | (b[1] ?? 0);
    if (v < limit) return v % WORDLIST.length;
  }
}

export function generateCode(): ShareCode {
  const mailboxId = toCrockford(randomBytes(MAILBOX_ID_BYTES));
  const words = Array.from(
    { length: WORD_COUNT },
    () => WORDLIST[randomWordIndex()] as string,
  );
  return { mailboxId, words, code: canonical(mailboxId, words) };
}

function canonical(mailboxId: string, words: string[]): string {
  return `${mailboxId.slice(0, 4)}-${mailboxId.slice(4)}-${words.join("-")}`;
}

export function formatCode(c: Pick<ShareCode, "mailboxId" | "words">): string {
  return canonical(c.mailboxId, c.words);
}

/** Crockford decode aliases: I/L read as 1, O as 0. U is simply invalid. */
function normalizeCrockford(s: string): string {
  return s.toUpperCase().replace(/[IL]/g, "1").replace(/O/g, "0");
}

/**
 * Parses user input into a ShareCode. Forgiving about case, whitespace vs dash
 * separators, and Crockford lookalike characters; strict about structure.
 */
export function parseCode(input: string): ShareCode {
  const parts = input.trim().toLowerCase().split(/[\s-]+/).filter(Boolean);

  let idPart: string;
  let words: string[];
  if (parts.length === WORD_COUNT + 2) {
    idPart = `${parts[0]}${parts[1]}`;
    words = parts.slice(2);
  } else if (parts.length === WORD_COUNT + 1) {
    idPart = parts[0] as string;
    words = parts.slice(1);
  } else {
    throw new CodeFormatError(
      "Expected a code like XXXX-XXXX followed by 5 words",
    );
  }

  const mailboxId = normalizeCrockford(idPart);
  if (!MAILBOX_ID_RE.test(mailboxId)) {
    throw new CodeFormatError("The XXXX-XXXX part of the code is not valid");
  }
  for (const w of words) {
    if (!WORDSET.has(w)) {
      throw new CodeFormatError(`"${w}" is not a valid code word`);
    }
  }
  return { mailboxId, words, code: canonical(mailboxId, words) };
}
