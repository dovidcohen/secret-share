import { describe, expect, it } from "vitest";
import {
  CodeFormatError,
  formatCode,
  generateCode,
  parseCode,
} from "../code.js";
import { WORDLIST } from "../wordlist.js";

describe("wordlist", () => {
  it("has 7776 unique lowercase words", () => {
    expect(WORDLIST.length).toBe(7776);
    expect(new Set(WORDLIST).size).toBe(7776);
    for (const w of WORDLIST) expect(w).toMatch(/^[a-z]+$/);
  });
});

describe("generateCode / parseCode", () => {
  it("round-trips its own output (1000 iterations)", () => {
    for (let i = 0; i < 1000; i++) {
      const c = generateCode();
      expect(c.mailboxId).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/);
      expect(c.words).toHaveLength(5);
      const parsed = parseCode(c.code);
      expect(parsed).toEqual(c);
      expect(formatCode(parsed)).toBe(c.code);
    }
  });

  it("is forgiving about case, separators, and Crockford lookalikes", () => {
    const c = generateCode();
    expect(parseCode(c.code.toUpperCase()).mailboxId).toBe(c.mailboxId);
    expect(parseCode(c.code.replace(/-/g, " "))).toEqual(c);
    expect(parseCode(`  ${c.code}  `)).toEqual(c);
    // I/L -> 1, O -> 0
    const aliased = c.code
      .slice(0, 9)
      .replace(/1/g, "l")
      .replace(/0/g, "O");
    expect(parseCode(aliased + c.code.slice(9))).toEqual(c);
    // single-chunk mailbox id (no dash in the middle)
    expect(parseCode(`${c.mailboxId} ${c.words.join(" ")}`)).toEqual(c);
  });

  it("rejects malformed input", () => {
    expect(() => parseCode("")).toThrow(CodeFormatError);
    expect(() => parseCode("too-short")).toThrow(CodeFormatError);
    const c = generateCode();
    // 'U' is invalid crockford even as an alias
    expect(() => parseCode(`UUUU-UUUU-${c.words.join("-")}`)).toThrow(CodeFormatError);
    // non-wordlist word
    expect(() =>
      parseCode(`${c.mailboxId.slice(0, 4)}-${c.mailboxId.slice(4)}-zzzznotaword-${c.words.slice(1).join("-")}`),
    ).toThrow(CodeFormatError);
    // six words
    expect(() => parseCode(`${c.code}-${c.words[0]}`)).toThrow(CodeFormatError);
  });

  it("draws words from the full list without obvious bias", () => {
    // loose smoke test: 2000 codes x 5 words should hit a wide spread of the list
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) for (const w of generateCode().words) seen.add(w);
    expect(seen.size).toBeGreaterThan(4000); // E[distinct] ~ 5680 of 7776
  });
});
