import { describe, expect, it } from "vitest";
import { packGiveFragment, parseGiveFragment } from "../grant.js";

describe("give-link fragment", () => {
  it("round-trips grant + code", () => {
    const grant = "q".repeat(43);
    const code = "XKQ2-M7PT-tiger-ocean-cable-ruby-drum";
    const packed = packGiveFragment(grant, code);
    expect(parseGiveFragment(packed)).toEqual({ grant, code });
  });

  it("returns null for junk or partial fragments", () => {
    expect(parseGiveFragment("")).toBeNull();
    expect(parseGiveFragment("g=onlygrant")).toBeNull();
    expect(parseGiveFragment("c=only-code")).toBeNull();
    expect(parseGiveFragment("XKQ2-M7PT-tiger-ocean-cable-ruby-drum")).toBeNull();
  });
});
