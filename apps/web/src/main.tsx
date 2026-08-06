import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.js";
import { readTenant, TenantContext } from "./lib/tenant.js";
import { SessionProvider } from "./lib/session.js";
import "./styles.css";

const tenant = readTenant();
// Theme before first paint, via CSSOM — inline <style> would violate the CSP.
if (tenant?.primaryColor) {
  document.documentElement.style.setProperty("--accent", tenant.primaryColor);
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <TenantContext.Provider value={tenant}>
      <SessionProvider tenant={tenant}>
        <App />
      </SessionProvider>
    </TenantContext.Provider>
  </StrictMode>,
);
