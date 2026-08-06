import { SELF } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { clearTenantCache } from "../src/tenant/registry.js";
import { rewriteHtmlForTenant } from "../src/branding.js";
import { seedTenant, tenantHost } from "./helpers.js";

beforeEach(() => clearTenantCache());

const PAGE = `<!doctype html><html lang="en"><head><meta charset="UTF-8"><title>Secret Share — one-time</title><link rel="canonical" href="https://shareasecret.io/"><meta name="description" content="x"><meta property="og:title" content="x"><script type="application/ld+json">{"@context":"https://schema.org"}</script></head><body><div id="root"></div></body></html>`;

function htmlResponse(): Response {
  return new Response(PAGE, { headers: { "Content-Type": "text/html;charset=utf-8" } });
}

describe("HTML rewriting (unit)", () => {
  it("injects a parseable branding block and strips SEO surface", async () => {
    const tenant = await seedTenant({
      displayName: "Acme Corp",
      theme: { logoVersion: 2, primaryColor: "#0e7490", footerText: "For staff." },
    });
    const res = rewriteHtmlForTenant(htmlResponse(), tenant);
    const html = await res.text();

    const m = html.match(
      /<script type="application\/json" id="tenant-config">(.*?)<\/script>/s,
    );
    expect(m).toBeTruthy();
    const branding = JSON.parse(m![1] as string) as Record<string, unknown>;
    expect(branding.name).toBe("Acme Corp");
    expect(branding.primaryColor).toBe("#0e7490");
    expect(branding.logoUrl).toBe("/api/tenant/logo?v=2");

    expect(html).toContain("<title>Acme Corp — secure one-time secrets</title>");
    expect(html).not.toContain("canonical");
    expect(html).not.toContain("ld+json");
    expect(html).not.toContain('property="og:');
    expect(res.headers.get("X-Robots-Tag")).toBe("noindex");
  });

  it("keeps hostile config strings inert (no </script> breakout)", async () => {
    const tenant = await seedTenant({
      displayName: 'Evil</script><script>alert(1)</script>',
    });
    const res = rewriteHtmlForTenant(htmlResponse(), tenant);
    const html = await res.text();
    const start = html.indexOf('id="tenant-config">') + 'id="tenant-config">'.length;
    const end = html.indexOf("</script>", start);
    const block = html.slice(start, end);
    // The raw payload inside the data block must not contain a script closer…
    expect(block).not.toContain("</script>");
    // …yet still parse back to the original string.
    expect((JSON.parse(block) as { name: string }).name).toContain("</script>");
  });
});

describe("asset delivery (SELF)", () => {
  it("tenant hosts get the branding block; the public host stays untouched", async () => {
    const tenant = await seedTenant();
    const tenantRes = await SELF.fetch(`https://${tenantHost(tenant)}/`);
    const tenantHtml = await tenantRes.text();
    expect(tenantHtml).toContain('id="tenant-config"');
    expect(tenantRes.headers.get("X-Robots-Tag")).toBe("noindex");

    const publicRes = await SELF.fetch("https://shareasecret.io/");
    const publicHtml = await publicRes.text();
    expect(publicHtml).not.toContain("tenant-config");
    expect(publicRes.headers.get("X-Robots-Tag")).toBeNull();
  });

  it("redirects marketing paths on tenant hosts only", async () => {
    const tenant = await seedTenant();
    const res = await SELF.fetch(`https://${tenantHost(tenant)}/blog`, {
      redirect: "manual",
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(`https://${tenantHost(tenant)}/`);

    const publicRes = await SELF.fetch("https://shareasecret.io/blog", {
      redirect: "manual",
    });
    expect(publicRes.status).not.toBe(302);
  });
});
