import { brandingFor, type TenantConfig } from "./tenant/schema.js";

/**
 * White-label delivery. The SPA is a single bundle; tenant-ness is injected at
 * serve time so the public site stays byte-identical (it never goes through
 * the rewriter). CSP (`script-src 'self'`) is deliberately untouched: the
 * config travels as a NON-executable JSON data block, which script-src does
 * not apply to, and the SPA applies theme color via CSSOM.
 */

/** Marketing/SEO paths have no place on a customer's white-label host. */
const MARKETING_PATH = /^\/(guides|blog|compare)(\/|$)/;

export function marketingRedirect(url: URL): Response | null {
  if (!MARKETING_PATH.test(url.pathname)) return null;
  return Response.redirect(`${url.origin}/`, 302);
}

/** `</script>` inside the JSON must never terminate the data block. */
function escapeJsonForHtml(json: string): string {
  return json.replace(/</g, "\\u003c");
}

export function rewriteHtmlForTenant(
  res: Response,
  tenant: TenantConfig,
): Response {
  const branding = brandingFor(tenant);
  const block = `<script type="application/json" id="tenant-config">${escapeJsonForHtml(
    JSON.stringify(branding),
  )}</script>`;

  const rewritten = new HTMLRewriter()
    .on("head", {
      element(el) {
        el.append(block, { html: true });
      },
    })
    .on("title", {
      element(el) {
        el.setInnerContent(`${branding.productName} — secure one-time secrets`);
      },
    })
    // A tenant host is a private tool: strip the apex's SEO surface.
    .on('link[rel="canonical"]', { element(el) { el.remove(); } })
    .on('script[type="application/ld+json"]', { element(el) { el.remove(); } })
    .on('meta[name="description"]', { element(el) { el.remove(); } })
    .on('meta[property^="og:"]', { element(el) { el.remove(); } })
    .on('meta[name^="twitter:"]', { element(el) { el.remove(); } })
    .transform(res);

  const out = new Response(rewritten.body, rewritten);
  out.headers.set("X-Robots-Tag", "noindex");
  return out;
}

/** Serves the raster logo uploaded via the admin API. Keyed by tenant, not by path. */
export async function serveLogo(
  request: Request,
  tenant: TenantConfig,
  env: Env,
): Promise<Response> {
  const etag = `"v${tenant.theme.logoVersion}"`;
  if (request.headers.get("If-None-Match") === etag) {
    return new Response(null, { status: 304, headers: { ETag: etag } });
  }
  const entry = await env.TENANTS.getWithMetadata<{ contentType?: string }>(
    `logo:${tenant.tenantId}`,
    { type: "arrayBuffer", cacheTtl: 3600 },
  ).catch(() => null);
  if (!entry?.value) return Response.json({ error: "NOT_FOUND" }, { status: 404 });
  return new Response(entry.value, {
    headers: {
      "Content-Type": entry.metadata?.contentType ?? "image/png",
      "Cache-Control": "public, max-age=86400",
      ETag: etag,
    },
  });
}
