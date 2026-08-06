import { describe, expect, it } from "vitest";
import { parseTenantConfig } from "../tenant.js";

const VALID = {
  tenantId: "acme",
  name: "Acme",
  productName: "Acme Secrets",
  logoUrl: "/api/tenant/logo?v=1",
  primaryColor: "#0e7490",
  footerText: null,
  idpLabel: "Acme (Microsoft)",
};

describe("parseTenantConfig", () => {
  it("accepts a valid injected block", () => {
    expect(parseTenantConfig(JSON.stringify(VALID))).toEqual(VALID);
  });

  it("degrades to public mode on garbage", () => {
    expect(parseTenantConfig(null)).toBeNull();
    expect(parseTenantConfig("")).toBeNull();
    expect(parseTenantConfig("not json {")).toBeNull();
    expect(parseTenantConfig(JSON.stringify({ hello: "world" }))).toBeNull();
  });

  it("rejects malformed colors rather than injecting them into CSS", () => {
    expect(
      parseTenantConfig(
        JSON.stringify({ ...VALID, primaryColor: "red;} body{display:none" }),
      ),
    ).toBeNull();
  });
});
