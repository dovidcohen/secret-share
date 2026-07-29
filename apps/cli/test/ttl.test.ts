import { describe, expect, it } from "vitest";
import { formatTtl, parseTtl, TtlFormatError } from "../src/ttl.js";

describe("parseTtl", () => {
  it("parses units", () => {
    expect(parseTtl("90s")).toBe(90);
    expect(parseTtl("30m")).toBe(1_800);
    expect(parseTtl("2h")).toBe(7_200);
    expect(parseTtl("1d")).toBe(86_400);
    expect(parseTtl("7d")).toBe(604_800);
  });

  it("treats bare numbers as seconds and tolerates case/whitespace", () => {
    expect(parseTtl("3600")).toBe(3_600);
    expect(parseTtl(" 2H ")).toBe(7_200);
    expect(parseTtl("30 m")).toBe(1_800);
  });

  it("rejects garbage", () => {
    for (const bad of ["", "soon", "1w", "2.5h", "-60", "1h30m"]) {
      expect(() => parseTtl(bad), bad).toThrow(TtlFormatError);
    }
  });

  it("enforces protocol bounds", () => {
    expect(() => parseTtl("59s")).toThrow(TtlFormatError);
    expect(parseTtl("60s")).toBe(60);
    expect(() => parseTtl("8d")).toThrow(TtlFormatError);
    expect(() => parseTtl("605000")).toThrow(TtlFormatError);
  });
});

describe("formatTtl", () => {
  it("picks the largest exact unit", () => {
    expect(formatTtl(86_400)).toBe("1d");
    expect(formatTtl(7_200)).toBe("2h");
    expect(formatTtl(1_800)).toBe("30m");
    expect(formatTtl(90)).toBe("90s");
  });
});
