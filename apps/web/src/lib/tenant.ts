import { createContext, useContext } from "react";
import { TenantBrandingSchema, type TenantBranding } from "@secret-share/protocol";

/**
 * White-label branding, injected by the Worker as a non-executable JSON data
 * block (<script type="application/json" id="tenant-config">) — chosen over an
 * inline executable script because the site's CSP (script-src 'self') would
 * block that. Absent or malformed block = the public shareasecret.io site.
 */
export type TenantConfig = TenantBranding;

export function readTenant(): TenantConfig | null {
  if (import.meta.env.DEV && import.meta.env.VITE_DEV_TENANT) {
    // `VITE_DEV_TENANT=1 pnpm dev` exercises tenant mode without the Worker rewriter.
    return {
      tenantId: "devtenant",
      name: "Dev Tenant",
      productName: "Dev Tenant Secrets",
      logoUrl: null,
      primaryColor: "#0e7490",
      footerText: "Local tenant-mode preview.",
      idpLabel: "Dev IdP",
    };
  }
  return parseTenantConfig(
    document.getElementById("tenant-config")?.textContent ?? null,
  );
}

/** Pure for testability: bad input degrades to the public experience, never a broken page. */
export function parseTenantConfig(raw: string | null): TenantConfig | null {
  if (!raw) return null;
  try {
    const parsed = TenantBrandingSchema.safeParse(JSON.parse(raw));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const TenantContext = createContext<TenantConfig | null>(null);

export function useTenant(): TenantConfig | null {
  return useContext(TenantContext);
}
