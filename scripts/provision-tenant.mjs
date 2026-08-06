#!/usr/bin/env node
// Operator CLI for white-label tenants. Writes the KV registry via wrangler
// (OAuth) and, when CF_API_TOKEN is set, drives Cloudflare for SaaS custom
// hostnames + worker routes. OIDC client secrets NEVER pass through here —
// the script prints the `wrangler secret put` command to run instead.
//
//   node scripts/provision-tenant.mjs create --id fordmed --name "FordMed" \
//     --issuer https://login.microsoftonline.com/<dir-tenant-id>/v2.0 \
//     --client-id <guid> --admin admin@fordmed.com [--hostname secrets.fordmed.com]
//     [--color "#0e7490"] [--idp-label "FordMed (Microsoft)"] [--domain fordmed.com]
//   node scripts/provision-tenant.mjs set-logo --id fordmed --file ./logo.png
//   node scripts/provision-tenant.mjs set-hostname --id fordmed --hostname secrets.fordmed.com
//   node scripts/provision-tenant.mjs show --id fordmed
//   node scripts/provision-tenant.mjs delete --id fordmed

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const API_DIR = fileURLToPath(new URL("../workers/api", import.meta.url));
const WRANGLER_CONFIG = path.join(API_DIR, "wrangler.jsonc");
const ZONE_NAME = "shareasecret.io";

function namespaceId() {
  const config = readFileSync(WRANGLER_CONFIG, "utf8");
  const m = config.match(/"binding":\s*"TENANTS",\s*"id":\s*"([0-9a-f]{32})"/);
  if (!m) fail("Could not find the TENANTS namespace id in wrangler.jsonc");
  return m[1];
}

function wranglerKv(args, input) {
  return execFileSync(
    process.platform === "win32" ? "npx.cmd" : "npx",
    ["wrangler", "kv", ...args, "--namespace-id", namespaceId(), "--remote"],
    { cwd: API_DIR, input, encoding: "utf8", shell: process.platform === "win32" },
  );
}

function kvGet(key) {
  try {
    return wranglerKv(["key", "get", key]);
  } catch {
    return null;
  }
}

function kvPut(key, value, metadata) {
  const args = ["key", "put", key, value];
  if (metadata) args.push("--metadata", JSON.stringify(metadata));
  wranglerKv(args);
}

function kvPutFile(key, file, metadata) {
  const args = ["key", "put", key, "--path", file];
  if (metadata) args.push("--metadata", JSON.stringify(metadata));
  wranglerKv(args);
}

function kvDelete(key) {
  try {
    wranglerKv(["key", "delete", key]);
  } catch {}
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const value = argv[i + 1]?.startsWith("--") || argv[i + 1] === undefined ? true : argv[++i];
      if (out[key] === undefined) out[key] = value;
      else out[key] = [].concat(out[key], value);
    } else {
      out._.push(a);
    }
  }
  return out;
}

function fail(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

function loadTenant(id) {
  const raw = kvGet(`tenant:${id}`);
  if (!raw) fail(`Tenant "${id}" not found`);
  return JSON.parse(raw);
}

function saveTenant(tenant) {
  tenant.updatedAt = Date.now();
  kvPut(`tenant:${tenant.tenantId}`, JSON.stringify(tenant));
  for (const host of tenant.hostnames) {
    kvPut(`host:${host}`, JSON.stringify({ tenantId: tenant.tenantId }));
  }
}

// ---------- Cloudflare for SaaS (optional; requires CF_API_TOKEN + CF_ZONE_ID) ----------

async function cfApi(pathname, init = {}) {
  const token = process.env.CF_API_TOKEN;
  const zone = process.env.CF_ZONE_ID;
  if (!token || !zone) return null;
  const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone}${pathname}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
  const body = await res.json();
  if (!body.success) {
    console.error(JSON.stringify(body.errors, null, 2));
    fail(`Cloudflare API call ${pathname} failed`);
  }
  return body.result;
}

async function provisionCustomHostname(hostname) {
  const result = await cfApi("/custom_hostnames", {
    method: "POST",
    body: JSON.stringify({ hostname, ssl: { method: "http", type: "dv" } }),
  });
  if (result === null) {
    console.log(`! CF_API_TOKEN/CF_ZONE_ID not set — create the custom hostname manually:`);
    console.log(`    SSL/TLS -> Custom Hostnames -> Add "${hostname}" (HTTP validation)`);
  } else {
    console.log(`+ custom hostname ${hostname} created (status: ${result.status})`);
  }
  console.log(`! Add a worker route for it (dashboard or API): pattern "${hostname}/*", zone ${ZONE_NAME}`);
  console.log(`! Customer DNS required: ${hostname} CNAME fallback.${ZONE_NAME}`);
}

// ---------- commands ----------

const args = parseArgs(process.argv.slice(2));
const cmd = args._[0];

function entraChecklist(tenant, hostname) {
  const secretName = `OIDC_CLIENT_SECRET_${tenant.tenantId.toUpperCase().replace(/-/g, "_")}`;
  console.log(`
Next steps for ${tenant.displayName}:
  1. Entra ID app registration (or equivalent at another IdP):
     - Platform: Web, redirect URI: https://${hostname}/auth/callback
       (add one per hostname if the tenant has several)
     - Issuer to configure here: ${tenant.oidc.issuer}
     - For group gating, prefer App Roles (the 'groups' claim is omitted for
       users in >200 groups); put role values in oidc.allowedGroups.
  2. Client secret (NOTE ITS EXPIRY — Entra caps at 24 months):
       cd workers/api && npx wrangler secret put ${secretName}
  3. One-time platform secret if not done yet:
       cd workers/api && npx wrangler secret put SESSION_SECRET   (32+ random chars)
  4. Deploy: pnpm build && pnpm --filter @secret-share/api deploy
  5. Smoke it: https://${hostname}/ should show "${tenant.displayName}" branding.
`);
}

switch (cmd) {
  case "create": {
    const id = args.id;
    if (!id || !/^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/.test(id)) {
      fail("--id must be 3-32 chars of [a-z0-9-]");
    }
    if (!args.name) fail("--name is required");
    if (!args.issuer) fail("--issuer is required");
    if (!args["client-id"]) fail("--client-id is required");
    if (!args.admin) fail("--admin <email> is required (repeatable)");
    if (kvGet(`tenant:${id}`)) fail(`Tenant "${id}" already exists`);

    const defaultHost = `${id}.${ZONE_NAME}`;
    const hostnames = [defaultHost];
    if (args.hostname && args.hostname !== true) hostnames.push(args.hostname);

    const now = Date.now();
    const tenant = {
      v: 1,
      tenantId: id,
      displayName: args.name,
      hostnames,
      theme: {
        logoVersion: 0,
        ...(args.color && args.color !== true ? { primaryColor: args.color } : {}),
      },
      oidc: {
        issuer: args.issuer,
        clientId: args["client-id"],
        clientAuth: "secret",
        scopes: "openid profile email",
        ...(args["idp-label"] && args["idp-label"] !== true
          ? { idpLabel: args["idp-label"] }
          : {}),
        allowedEmailDomains: [].concat(args.domain ?? []).filter((d) => d !== true),
        allowedGroups: [].concat(args.group ?? []).filter((g) => g !== true),
      },
      adminEmails: [].concat(args.admin).filter((a) => a !== true),
      features: { guestGrants: true, liveSend: true },
      createdAt: now,
      updatedAt: now,
    };
    saveTenant(tenant);
    console.log(`+ tenant ${id} created with hostnames: ${hostnames.join(", ")}`);
    if (hostnames[1]) await provisionCustomHostname(hostnames[1]);
    entraChecklist(tenant, defaultHost);
    break;
  }

  case "set-hostname": {
    const tenant = loadTenant(args.id);
    const hostname = args.hostname;
    if (!hostname || hostname === true) fail("--hostname is required");
    if (!tenant.hostnames.includes(hostname)) tenant.hostnames.push(hostname);
    saveTenant(tenant);
    console.log(`+ ${hostname} -> ${tenant.tenantId}`);
    if (!hostname.endsWith(`.${ZONE_NAME}`)) await provisionCustomHostname(hostname);
    console.log(`! Remember the IdP redirect URI: https://${hostname}/auth/callback`);
    break;
  }

  case "set-logo": {
    const tenant = loadTenant(args.id);
    const file = args.file;
    if (!file || file === true) fail("--file is required");
    const types = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp" };
    const contentType = types[path.extname(file).toLowerCase()];
    if (!contentType) fail("Logo must be .png, .jpg, or .webp (SVG is rejected by design)");
    kvPutFile(`logo:${tenant.tenantId}`, file, { contentType });
    tenant.theme.logoVersion = (tenant.theme.logoVersion ?? 0) + 1;
    saveTenant(tenant);
    console.log(`+ logo updated (v${tenant.theme.logoVersion})`);
    break;
  }

  case "show": {
    console.log(JSON.stringify(loadTenant(args.id), null, 2));
    break;
  }

  case "delete": {
    const tenant = loadTenant(args.id);
    for (const host of tenant.hostnames) kvDelete(`host:${host}`);
    kvDelete(`logo:${tenant.tenantId}`);
    kvDelete(`tenant:${tenant.tenantId}`);
    console.log(`+ tenant ${tenant.tenantId} removed (custom hostnames/routes NOT touched — remove in dashboard if any)`);
    break;
  }

  default:
    fail(`Unknown command "${cmd ?? ""}" — use create | set-hostname | set-logo | show | delete`);
}
