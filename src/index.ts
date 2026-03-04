import express, { Request, Response } from "express";
import crypto from "crypto";
import cookieParser from "cookie-parser";
import { Pool } from "pg";
import fetch from "node-fetch";
import qs from "querystring";
import { XMLParser } from "fast-xml-parser";

/**
 * ==========================================
 * NeoSys ↔ Shopify Custom App (Render)
 * - OAuth install + token storage (Postgres)
 * - Webhook registration + verification (HMAC raw body)
 * - Orders → NeoSys (/comanda_client) as XML
 * - Products pull from NeoSys (/nomenclatoare/articole) as XML (helper endpoint)
 * ==========================================
 */

const app = express();

// =====================
// ENV
// =====================
const {
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_SCOPES,
  SHOPIFY_APP_URL,
  DATABASE_URL,
  PORT,

  // NeoSys
  NEOSYS_BASE_URL,          // ex: https://api.neosys.ro
  NEOSYS_API_VERSION,       // ex: v1
  NEOSYS_AUTHORIZATION,     // ex: Bearer xxx  (valoarea completa pt header Authorization)
  NEOSYS_PUNCT_LUCRU,       // ex: depozit
  NEOSYS_GESTIUNE,          // ex: depozit
  NEOSYS_DEFAULT_TVA,       // ex: 19
  NEOSYS_PRICES_INCLUDE_TVA // true/false
} = process.env;

if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !SHOPIFY_SCOPES || !SHOPIFY_APP_URL || !DATABASE_URL) {
  throw new Error("Missing env vars. Required: SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_SCOPES, SHOPIFY_APP_URL, DATABASE_URL");
}

// NeoSys envs are optional at boot; required only when you actually call NeoSys.
const pool = new Pool({ connectionString: DATABASE_URL });

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  trimValues: true,
});

// =====================
// DB init (safe)
// =====================
async function initDb() {
  await pool.query(`
    create table if not exists shopify_sessions (
      shop text primary key,
      access_token text not null,
      scope text,
      installed_at timestamptz default now(),
      updated_at timestamptz default now()
    );
  `);

  await pool.query(`
    create table if not exists neosys_order_map (
      shop text not null,
      shopify_order_id bigint not null,
      neosys_document_id text,
      neosys_document_number text,
      created_at timestamptz default now(),
      primary key (shop, shopify_order_id)
    );
  `);
}

// =====================
// Helpers
// =====================
function base64Hmac(secret: string, data: Buffer | string) {
  return crypto.createHmac("sha256", secret).update(data).digest("base64");
}

function safeCompare(a: string, b: string) {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function xmlEscape(value: any): string {
  const s = String(value ?? "");
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function buildShopifyAuthUrl(shop: string, state: string) {
  const redirectUri = `${SHOPIFY_APP_URL}/auth/callback`;
  const params = {
    client_id: SHOPIFY_API_KEY!,
    scope: SHOPIFY_SCOPES!,
    redirect_uri: redirectUri,
    state,
  };
  return `https://${shop}/admin/oauth/authorize?${qs.stringify(params)}`;
}

function verifyOAuthHmac(query: Record<string, any>) {
  // Shopify OAuth: verify "hmac" computed from rest of query params (sorted, without hmac/signature)
  const { hmac, signature, ...rest } = query;

  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((key) => {
      const value = Array.isArray(rest[key]) ? rest[key].join(",") : rest[key];
      return `${key}=${value}`;
    })
    .join("&");

  const digest = crypto.createHmac("sha256", SHOPIFY_API_SECRET!).update(message).digest("hex");
  return safeCompare(digest, String(hmac));
}

async function upsertToken(shop: string, accessToken: string, scope?: string) {
  await pool.query(
    `
    insert into shopify_sessions (shop, access_token, scope, updated_at)
    values ($1, $2, $3, now())
    on conflict (shop) do update set
      access_token = excluded.access_token,
      scope = excluded.scope,
      updated_at = now()
    `,
    [shop, accessToken, scope || null]
  );
}

async function getToken(shop: string): Promise<string | null> {
  const res = await pool.query(`select access_token from shopify_sessions where shop=$1`, [shop]);
  return res.rows?.[0]?.access_token ?? null;
}

// =====================
// Shopify Admin API (REST) – Webhooks
// =====================
type WebhookTopic =
  | "orders/create"
  | "orders/paid"
  | "orders/cancelled"
  | "fulfillments/create"
  | "products/update"
  | "products/create";

const WEBHOOKS: Array<{ topic: WebhookTopic; path: string }> = [
  { topic: "orders/create", path: "/webhooks/orders_create" },
  { topic: "orders/paid", path: "/webhooks/orders_paid" },
  { topic: "orders/cancelled", path: "/webhooks/orders_cancelled" },
  { topic: "fulfillments/create", path: "/webhooks/fulfillments_create" },
  { topic: "products/update", path: "/webhooks/products_update" },
  { topic: "products/create", path: "/webhooks/products_create" },
];

async function shopifyRequest(shop: string, accessToken: string, method: string, endpoint: string, body?: any) {
  const url = `https://${shop}/admin/api/2024-10${endpoint}`;
  const res = await fetch(url, {
    method,
    headers: {
      "X-Shopify-Access-Token": accessToken,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }

  if (!res.ok) {
    const err: any = new Error(`Shopify API error ${res.status}: ${text}`);
    err.status = res.status;
    err.body = json || text;
    throw err;
  }

  return json;
}

function isDuplicateWebhookError(err: any) {
  // Shopify returns 422 with errors.address[0] = "has already been taken"
  const body = err?.body;
  const addressErrors = body?.errors?.address;
  if (Array.isArray(addressErrors) && addressErrors.some((e: string) => String(e).toLowerCase().includes("already been taken"))) {
    return true;
  }
  return false;
}

async function registerWebhooks(shop: string, accessToken: string) {
  for (const wh of WEBHOOKS) {
    const address = `${SHOPIFY_APP_URL}${wh.path}`;

    try {
      await shopifyRequest(shop, accessToken, "POST", "/webhooks.json", {
        webhook: { topic: wh.topic, address, format: "json" },
      });
      console.log(`[webhooks] Registered: ${wh.topic} -> ${address}`);
    } catch (err: any) {
      if (isDuplicateWebhookError(err)) {
        console.log(`[webhooks] Exists already (ignored): ${wh.topic} -> ${address}`);
        continue;
      }
      console.error(`[webhooks] Failed for ${wh.topic}`, err?.body || err);
      throw err;
    }
  }
}

// =====================
// Middleware
// =====================
app.use(cookieParser());

// IMPORTANT: webhook routes use express.raw() separately
app.use((req, res, next) => {
  if (req.path.startsWith("/webhooks/")) return next();
  return express.json({ limit: "2mb" })(req, res, next);
});

// =====================
// HEALTH
// =====================
app.get("/", (_req, res) => res.status(200).send("OK neosys-shopify-app"));
app.get("/health", async (_req, res) => {
  try {
    await pool.query("select 1 as ok");
    res.status(200).json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message || "db error" });
  }
});

// =====================
// OAUTH START
// =====================
app.get("/auth", async (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop || !shop.endsWith(".myshopify.com")) {
    return res.status(400).send("Missing or invalid shop param (?shop=xxx.myshopify.com)");
  }

  const state = crypto.randomBytes(16).toString("hex");

  // signed cookie state
  const stateSig = base64Hmac(SHOPIFY_API_SECRET!, state);
  res.cookie("shopify_state", `${state}.${stateSig}`, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });

  const url = buildShopifyAuthUrl(shop, state);
  return res.redirect(url);
});

// =====================
// OAUTH CALLBACK
// =====================
app.get("/auth/callback", async (req, res) => {
  try {
    const shop = String(req.query.shop || "");
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");

    if (!shop || !code || !state) return res.status(400).send("Missing shop/code/state");

    // 1) verify HMAC
    if (!verifyOAuthHmac(req.query as any)) {
      return res.status(401).send("Invalid HMAC");
    }

    // 2) verify state
    const cookieState = req.cookies?.shopify_state as string | undefined;
    if (cookieState) {
      const [val, sig] = cookieState.split(".");
      const expected = base64Hmac(SHOPIFY_API_SECRET!, val);
      const ok = val === state && safeCompare(sig, expected);
      if (!ok) return res.status(401).send("Invalid state");
    }

    // 3) exchange code -> token
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }),
    });

    const tokenText = await tokenRes.text();
    const tokenJson: any = tokenText ? JSON.parse(tokenText) : null;

    if (!tokenRes.ok) {
      return res.status(500).send(`Token exchange failed: ${tokenText}`);
    }

    const accessToken = tokenJson.access_token as string;
    const scope = tokenJson.scope as string | undefined;

    await upsertToken(shop, accessToken, scope);
    console.log(`Installed OK. Token saved for ${shop}`);

    // 4) register webhooks (idempotent)
    await registerWebhooks(shop, accessToken);

    return res.status(200).send("App installed + webhooks registered.");
  } catch (e: any) {
    console.error("OAuth callback error:", e?.body || e);
    return res.status(500).send("OAuth callback error");
  }
});

// =====================
// WEBHOOK VERIFY + HANDLERS
// =====================
function verifyWebhookHmac(rawBody: Buffer, hmacHeader: string | undefined) {
  if (!hmacHeader) return false;
  const digest = base64Hmac(SHOPIFY_API_SECRET!, rawBody);
  return safeCompare(digest, hmacHeader);
}

function webhookEndpoint(
  handlerName: string,
  handler: (topic: string, shop: string, payload: any) => Promise<void>
) {
  return [
    express.raw({ type: "*/*", limit: "5mb" }),
    async (req: Request, res: Response) => {
      const hmac = (req.header("X-Shopify-Hmac-Sha256") || "").trim() || undefined;
      const topic = req.header("X-Shopify-Topic") || "";
      const shop = req.header("X-Shopify-Shop-Domain") || "";
      const webhookId = req.header("X-Shopify-Webhook-Id") || "";
      const raw = req.body as Buffer;

      if (!verifyWebhookHmac(raw, hmac)) {
        console.warn(`[${handlerName}] Invalid webhook HMAC`, { shop, topic, webhookId });
        return res.status(401).send("Invalid HMAC");
      }

      let payload: any = null;
      try {
        payload = JSON.parse(raw.toString("utf8"));
      } catch {
        return res.status(400).send("Invalid JSON");
      }

      try {
        await handler(topic, shop, payload);
        return res.status(200).send("ok");
      } catch (e: any) {
        console.error(`[${handlerName}] error`, e?.message || e);
        return res.status(500).send("webhook error");
      }
    },
  ] as any;
}

// =====================
// NeoSys client (XML)
// =====================
function requireNeoSysEnv() {
  if (!NEOSYS_BASE_URL) throw new Error("Missing NEOSYS_BASE_URL");
  if (!NEOSYS_API_VERSION) throw new Error("Missing NEOSYS_API_VERSION (ex: v1)");
  if (!NEOSYS_AUTHORIZATION) throw new Error("Missing NEOSYS_AUTHORIZATION (full Authorization header value)");
}

async function neosysPost(path: string, xmlBody: string, options?: { parseXml?: boolean }): Promise<{ status: number; raw: string; parsed: any }> {
  requireNeoSysEnv();

  const url = `${NEOSYS_BASE_URL}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "API-Version": String(NEOSYS_API_VERSION),
      "Authorization": String(NEOSYS_AUTHORIZATION),
      "Content-Type": "application/xml",
      "Accept": "application/xml",
    },
    body: xmlBody,
  });

  const raw = await res.text();

  // IMPORTANT: /nomenclatoare/articole can return VERY large XML.
  // Parsing huge XML in-memory can crash small instances (Render free) with "heap out of memory".
  const shouldParse = options?.parseXml !== false;

  let parsed: any = null;
  if (shouldParse) {
    // basic guard (avoid parsing extremely large payloads)
    const maxToParse = 5 * 1024 * 1024; // 5MB
    if (raw.length > maxToParse) {
      throw new Error(`NeoSys XML too large to parse safely (${raw.length} bytes). Use parseXml:false and/or add filters/batching.`);
    }
    try { parsed = xmlParser.parse(raw); } catch { /* ignore */ }
  }

  return { status: res.status, raw, parsed };
}

function pick(obj: any, ...paths: string[]) {
  for (const p of paths) {
    const parts = p.split(".");
    let cur = obj;
    for (const part of parts) {
      if (!cur || typeof cur !== "object") { cur = null; break; }
      cur = cur[part];
    }
    if (cur !== undefined && cur !== null && cur !== "") return cur;
  }
  return null;
}

function parseNeoSysResult(parsed: any): { success: boolean; error?: string; docId?: string; nr?: string; data?: string; total?: string } {
  const root = parsed?.neoSys || parsed?.neosys || parsed;
  const successVal = pick(root, "Succes", "Success");
  const success = String(successVal ?? "").toLowerCase() === "true";

  const error = pick(root, "MesajEroare");
  const comanda = pick(root, "Comanda_Client");
  const docId = pick(comanda, "ID");
  const nr = pick(comanda, "Nr");
  const data = pick(comanda, "Data");
  const total = pick(comanda, "Total");

  return { success, error: error ? String(error) : undefined, docId: docId ? String(docId) : undefined, nr: nr ? String(nr) : undefined, data: data ? String(data) : undefined, total: total ? String(total) : undefined };
}

// =====================
// Shopify → NeoSys order XML mapping
// =====================
function formatNeoSysDate(iso: string | null): string {
  // NeoSys expects ZZ/LL/AAAA. Shopify gives ISO.
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const dd = String(d.getDate()).padStart(2, "0");
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const yyyy = d.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

function calcVatPercent(order: any): number {
  // try derive from order.tax_lines[0].rate
  const rate = order?.tax_lines?.[0]?.rate;
  if (typeof rate === "number") return Math.round(rate * 100);
  const amount = Number(order?.total_tax ?? 0);
  if (amount > 0) return Number(NEOSYS_DEFAULT_TVA ?? 19);
  return Number(NEOSYS_DEFAULT_TVA ?? 19);
}

function isPricesIncludeTva(): boolean {
  const v = String(NEOSYS_PRICES_INCLUDE_TVA ?? "true").toLowerCase();
  return v === "true" || v === "1" || v === "yes";
}

function mapOrderToNeoSysXml(order: any): string {
  const createdAt = order?.created_at ? formatNeoSysDate(order.created_at) : "";
  const customer = order?.customer || {};
  const shipping = order?.shipping_address || order?.billing_address || {};
  const billing = order?.billing_address || shipping;

  const fullName =
    [customer?.first_name, customer?.last_name].filter(Boolean).join(" ").trim() ||
    shipping?.name ||
    billing?.name ||
    "Client Shopify";

  const email = order?.email || customer?.email || "";
  const phone = order?.phone || shipping?.phone || billing?.phone || "";

  const company = shipping?.company || billing?.company || "";
  const clientName = company ? company : fullName;

  const vat = calcVatPercent(order);
  const defaultTva = Number(NEOSYS_DEFAULT_TVA ?? vat ?? 19);

  const punctLucru = String(NEOSYS_PUNCT_LUCRU ?? "depozit");
  const gestiune = String(NEOSYS_GESTIUNE ?? punctLucru);

  const currency = order?.currency || "RON";
  const note = order?.note || "";

  // Shopify line items
  const items = Array.isArray(order?.line_items) ? order.line_items : [];

  const articoleXml = items.map((li: any) => {
    const title = li?.title || li?.name || "Produs";
    const sku = li?.sku || "";
    const barcode = li?.barcode || ""; // usually not present in order payload
    const qty = Number(li?.quantity ?? 1);

    // Shopify line_item.price is a string/number.
    const unitPrice = Number(li?.price ?? 0);

    // VAT calc per line item if present
    const liVat = typeof li?.tax_lines?.[0]?.rate === "number" ? Math.round(li.tax_lines[0].rate * 100) : defaultTva;

    const includeTva = isPricesIncludeTva();
    const priceWithVat = includeTva ? unitPrice : Number((unitPrice * (1 + liVat / 100)).toFixed(2));

    return `
\t\t<Articol>
\t\t\t<Denumire>${xmlEscape(title)}</Denumire>
\t\t\t<ID></ID>
\t\t\t<Cod>${xmlEscape(sku)}</Cod>
\t\t\t<Cod_Bare>${xmlEscape(barcode)}</Cod_Bare>
\t\t\t<Gestiune_Denumire>${xmlEscape(gestiune)}</Gestiune_Denumire>
\t\t\t<Gestiune_ID></Gestiune_ID>
\t\t\t<Cantitate>${qty}</Cantitate>
\t\t\t<Pret_Cu_TVA>${xmlEscape(priceWithVat)}</Pret_Cu_TVA>
\t\t\t<Cota_TVA>${xmlEscape(liVat)}</Cota_TVA>
\t\t\t<Discount>0</Discount>
\t\t\t<Rezervare_Stoc>false</Rezervare_Stoc>
\t\t\t<Serii></Serii>
\t\t\t<Creare_Daca_Nu_Exista>true</Creare_Daca_Nu_Exista>
\t\t</Articol>`;
  }).join("\n");

  const street = shipping?.address1 || billing?.address1 || "";
  const city = shipping?.city || billing?.city || "";
  const zip = shipping?.zip || billing?.zip || "";
  const countryCode = shipping?.country_code || billing?.country_code || "RO";
  const provinceCode = shipping?.province_code || billing?.province_code || "";

  // NeoSys expects Cod_Judet. If you have mapping, set it here.
  // For now we pass provinceCode as-is; if empty, it remains empty.
  const codJudet = provinceCode;

  return `<?xml version="1.0" encoding="UTF-8"?>
<neoSys>
\t<Data>${xmlEscape(createdAt)}</Data>
\t<Valabilitate></Valabilitate>
\t<Nr></Nr>
\t<Punct_Lucru>
\t\t<Denumire>${xmlEscape(punctLucru)}</Denumire>
\t\t<ID></ID>
\t</Punct_Lucru>
\t<Moneda>${xmlEscape(currency)}</Moneda>
\t<Client>
\t\t<Denumire>${xmlEscape(clientName)}</Denumire>
\t\t<ID></ID>
\t\t<CIF></CIF>
\t\t<Nr_Reg_Com></Nr_Reg_Com>
\t\t<Cod></Cod>
\t\t<Tip>persoana fizica</Tip>
\t\t<Adresa>
\t\t\t<Strada>${xmlEscape(street)}</Strada>
\t\t\t<Localitate>${xmlEscape(city)}</Localitate>
\t\t\t<Cod_Judet>${xmlEscape(codJudet)}</Cod_Judet>
\t\t\t<Sector></Sector>
\t\t\t<Cod_Tara>${xmlEscape(countryCode)}</Cod_Tara>
\t\t</Adresa>
\t\t<Contact>
\t\t\t<Nume>${xmlEscape(fullName)}</Nume>
\t\t\t<Telefon>${xmlEscape(phone)}</Telefon>
\t\t\t<Email>${xmlEscape(email)}</Email>
\t\t</Contact>
\t\t<Banca>
\t\t\t<Denumire></Denumire>
\t\t\t<IBAN></IBAN>
\t\t</Banca>
\t\t<Adresa_Livrare>
\t\t\t<Strada>${xmlEscape(street)}</Strada>
\t\t\t<Localitate>${xmlEscape(city)}</Localitate>
\t\t\t<Cod_Judet>${xmlEscape(codJudet)}</Cod_Judet>
\t\t\t<Sector></Sector>
\t\t\t<Cod_Tara>${xmlEscape(countryCode)}</Cod_Tara>
\t\t\t<Cod_Postal>${xmlEscape(zip)}</Cod_Postal>
\t\t\t<Contact>
\t\t\t\t<Nume>${xmlEscape(fullName)}</Nume>
\t\t\t\t<Telefon>${xmlEscape(phone)}</Telefon>
\t\t\t\t<Email>${xmlEscape(email)}</Email>
\t\t\t</Contact>
\t\t\t<Alte_Informatii></Alte_Informatii>
\t\t\t<Denumire_Locatie></Denumire_Locatie>
\t\t\t<Cod_Locatie></Cod_Locatie>
\t\t</Adresa_Livrare>
\t\t<Creare_Daca_Nu_Exista>true</Creare_Daca_Nu_Exista>
\t\t<Actualizare_Date>true</Actualizare_Date>
\t</Client>
\t<Discount>
\t\t<Tip>valoric</Tip>
\t\t<Valoare>0</Valoare>
\t\t<Include_TVA>true</Include_TVA>
\t</Discount>
\t<AWB></AWB>
\t<Observatii>${xmlEscape(note)}</Observatii>
\t<Articole>
${articoleXml}
\t</Articole>
</neoSys>`;
}

// =====================
// NeoSys actions
// =====================
async function createNeoSysOrder(shop: string, order: any) {
  const xml = mapOrderToNeoSysXml(order);
  const resp = await neosysPost("/comanda_client", xml);
  const parsed = parseNeoSysResult(resp.parsed);

  if (!parsed.success) {
    const msg = parsed.error || `NeoSys error (HTTP ${resp.status})`;
    const err: any = new Error(msg);
    err.httpStatus = resp.status;
    err.raw = resp.raw;
    throw err;
  }

  // persist mapping
  const shopifyOrderId = Number(order?.id);
  if (shopifyOrderId) {
    await pool.query(
      `
      insert into neosys_order_map (shop, shopify_order_id, neosys_document_id, neosys_document_number)
      values ($1,$2,$3,$4)
      on conflict (shop, shopify_order_id) do update set
        neosys_document_id = excluded.neosys_document_id,
        neosys_document_number = excluded.neosys_document_number
      `,
      [shop, shopifyOrderId, parsed.docId || null, parsed.nr || null]
    );
  }

  console.log(`[neosys] order created. shop=${shop} shopify_order_id=${order?.id} neosys_id=${parsed.docId} nr=${parsed.nr}`);
  return parsed;
}

// =====================
// Products pull (NeoSys nomenclatoare/articole)
// =====================
function buildNeoSysArticlesFilterXml(params: {
  stocInterogare?: boolean;
  doarCuStoc?: boolean;
  articolIdCsv?: string;
  articolCod?: string;
  articolCodBare?: string;
  categorieId?: string;
  categorieDenumire?: string;
  stocGestiuneDenumire?: string;
  stocGestiuneId?: string;
}) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<neoSys>
\t<Stoc_Interogare>${params.stocInterogare ? "true" : "false"}</Stoc_Interogare>
\t<Doar_Articole_Cu_Stoc>${params.doarCuStoc ? "true" : "false"}</Doar_Articole_Cu_Stoc>
\t<Filtre>
\t\t<Articol_Denumire></Articol_Denumire>
\t\t<Articol_ID>${xmlEscape(params.articolIdCsv || "")}</Articol_ID>
\t\t<Articol_Cod>${xmlEscape(params.articolCod || "")}</Articol_Cod>
\t\t<Articol_Cod_Bare>${xmlEscape(params.articolCodBare || "")}</Articol_Cod_Bare>
\t\t<Categorie_Denumire>${xmlEscape(params.categorieDenumire || "")}</Categorie_Denumire>
\t\t<Categorie_ID>${xmlEscape(params.categorieId || "")}</Categorie_ID>
\t\t<Stoc_Gestiune_Denumire>${xmlEscape(params.stocGestiuneDenumire || "")}</Stoc_Gestiune_Denumire>
\t\t<Stoc_Gestiune_ID>${xmlEscape(params.stocGestiuneId || "")}</Stoc_Gestiune_ID>
\t</Filtre>
</neoSys>`;
}

// =====================
// WEBHOOK ROUTES
// =====================
app.post(
  "/webhooks/orders_create",
  ...webhookEndpoint("orders_create", async (_topic, shop, payload) => {
    // create order in NeoSys on create
    await createNeoSysOrder(shop, payload);
  })
);

app.post(
  "/webhooks/orders_paid",
  ...webhookEndpoint("orders_paid", async (_topic, shop, payload) => {
    // optional: update status in NeoSys (not implemented)
    console.log(`[neosys] orders/paid received. shop=${shop} order_id=${payload?.id}`);
  })
);

app.post(
  "/webhooks/orders_cancelled",
  ...webhookEndpoint("orders_cancelled", async (_topic, shop, payload) => {
    // optional: cancel in NeoSys (not implemented)
    console.log(`[neosys] orders/cancelled received. shop=${shop} order_id=${payload?.id}`);
  })
);

app.post(
  "/webhooks/fulfillments_create",
  ...webhookEndpoint("fulfillments_create", async (_topic, shop, payload) => {
    console.log(`[neosys] fulfillments/create received. shop=${shop} fulfillment_id=${payload?.id}`);
  })
);

app.post(
  "/webhooks/products_update",
  ...webhookEndpoint("products_update", async (_topic, shop, payload) => {
    console.log(`[neosys] products/update received. shop=${shop} product_id=${payload?.id}`);
  })
);

app.post(
  "/webhooks/products_create",
  ...webhookEndpoint("products_create", async (_topic, shop, payload) => {
    console.log(`[neosys] products/create received. shop=${shop} product_id=${payload?.id}`);
  })
);

// =====================
// DEBUG endpoints (protected by simple token if you set DEBUG_TOKEN)
// =====================
const DEBUG_TOKEN = process.env.DEBUG_TOKEN;

function requireDebug(req: Request, res: Response): boolean {
  if (!DEBUG_TOKEN) return true; // if not set, allow
  const got = req.header("X-Debug-Token") || "";
  if (got !== DEBUG_TOKEN) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

app.post("/debug/neosys/create-order", async (req, res) => {
  try {
    if (!requireDebug(req, res)) return;
    const shop = String(req.body?.shop || "");
    const order = req.body?.order;
    if (!shop || !order) return res.status(400).json({ ok: false, error: "send {shop, order}" });

    const result = await createNeoSysOrder(shop, order);
    res.status(200).json({ ok: true, result });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message || "error", raw: e?.raw });
  }
});

app.post("/debug/neosys/articles", async (req, res) => {
  try {
    if (!requireDebug(req, res)) return;

    const xml = buildNeoSysArticlesFilterXml({
      stocInterogare: Boolean(req.body?.stoc_interogare ?? false),
      doarCuStoc: Boolean(req.body?.doar_cu_stoc ?? false),
      articolIdCsv: String(req.body?.articol_id_csv ?? ""),
      articolCod: String(req.body?.articol_cod ?? ""),
      articolCodBare: String(req.body?.articol_cod_bare ?? ""),
      categorieId: String(req.body?.categorie_id ?? ""),
      categorieDenumire: String(req.body?.categorie_denumire ?? ""),
      stocGestiuneDenumire: String(req.body?.stoc_gestiune_denumire ?? ""),
      stocGestiuneId: String(req.body?.stoc_gestiune_id ?? ""),
    });

    const resp = await neosysPost("/nomenclatoare/articole", xml, { parseXml: false });
    res.status(200).type("application/xml").send(resp.raw);
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message || "error" });
  }
});

// =====================
// START
// =====================
(async () => {
  await initDb();

  const port = Number(PORT || 10000);
  app.listen(port, () => console.log(`Server running on port ${port}`));
})();
