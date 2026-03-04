import crypto from "crypto";
import express, { Request, Response } from "express";
import fetch from "node-fetch";
import { Pool } from "pg";

/**
 * ENV
 */
const APP_URL = process.env.APP_URL || "";
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY || "";
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || "";
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || SHOPIFY_API_SECRET;
const SCOPES = process.env.SCOPES || "";
const PORT = Number(process.env.PORT || 3000);

if (!APP_URL || !SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !SCOPES || !process.env.DATABASE_URL) {
  console.error("Missing required env vars. Need APP_URL, SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SCOPES, DATABASE_URL");
}

/**
 * Postgres
 */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shops (
      shop TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS webhook_events (
      id BIGSERIAL PRIMARY KEY,
      shop TEXT NOT NULL,
      topic TEXT NOT NULL,
      webhook_id TEXT,
      payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("DB initialized");
}

initDb().catch((e) => console.error("DB init error:", e));

/**
 * Helpers - OAuth HMAC verification (query params)
 */
function verifyOauthHmacFromQuery(query: Record<string, string>): boolean {
  const { hmac, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");

  const digest = crypto.createHmac("sha256", SHOPIFY_API_SECRET).update(message).digest("hex");
  return safeEqualHex(digest, hmac);
}

function safeEqualHex(a: string, b: string) {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/**
 * Webhook verification (raw body) - Shopify sends X-Shopify-Hmac-Sha256 base64. :contentReference[oaicite:1]{index=1}
 */
function verifyWebhookHmac(rawBody: Buffer, hmacBase64: string | undefined): boolean {
  if (!hmacBase64) return false;
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest("base64");

  // constant-time compare
  const a = Buffer.from(digest, "utf8");
  const b = Buffer.from(hmacBase64, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * Shopify Admin GraphQL - create webhooks
 * (Webhook subscriptions are managed via GraphQL in modern flows; using webhookSubscriptionCreate is standard.) :contentReference[oaicite:2]{index=2}
 */
async function shopifyGraphQL(shop: string, accessToken: string, query: string, variables?: any) {
  const resp = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`Shopify GraphQL error (${resp.status}): ${text}`);
  }
  const json = JSON.parse(text);
  if (json.errors) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

async function ensureWebhook(shop: string, accessToken: string, topic: string, callbackUrl: string) {
  const mutation = `
    mutation WebhookCreate($topic: WebhookSubscriptionTopic!, $callbackUrl: URL!) {
      webhookSubscriptionCreate(
        topic: $topic,
        webhookSubscription: { callbackUrl: $callbackUrl, format: JSON }
      ) {
        webhookSubscription { id }
        userErrors { field message }
      }
    }
  `;

  const data = await shopifyGraphQL(shop, accessToken, mutation, { topic, callbackUrl });
  const res = data.webhookSubscriptionCreate;

  if (res.userErrors?.length) {
    throw new Error(`Webhook create userErrors: ${JSON.stringify(res.userErrors)}`);
  }

  console.log(`✅ Webhook ensured: ${topic} -> ${callbackUrl} (id=${res.webhookSubscription?.id})`);
  return res.webhookSubscription?.id;
}

async function registerWebhooks(shop: string, accessToken: string) {
  // Aici alegem webhook-urile utile pentru facturare + sincronizări:
  // - ORDERS_CREATE: pentru log & detect COD
  // - ORDERS_PAID: pentru "factura la plata" (online)
  // - FULFILLMENTS_CREATE: pentru COD (de obicei facturezi la expediere/livrare, nu la creare)
  // Poți adăuga și INVENTORY_LEVELS_UPDATE dacă vrei update intern.
  const hooks: Array<{ topic: string; path: string }> = [
    { topic: "ORDERS_CREATE", path: "/webhooks/orders_create" },
    { topic: "ORDERS_PAID", path: "/webhooks/orders_paid" },
    { topic: "FULFILLMENTS_CREATE", path: "/webhooks/fulfillments_create" },
  ];

  for (const h of hooks) {
    await ensureWebhook(shop, accessToken, h.topic, `${APP_URL}${h.path}`);
  }
}

/**
 * Express app
 */
const app = express();

// Root (ca să nu mai vezi "Cannot GET /")
app.get("/", (_req: Request, res: Response) => res.status(200).send("neosys-shopify-app: OK"));
app.get("/health", (_req: Request, res: Response) => res.status(200).send("ok"));

/**
 * OAuth start
 */
app.get("/auth", (req: Request, res: Response) => {
  const shop = String(req.query.shop || "").trim();
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop");

  const state = crypto.randomBytes(16).toString("hex");
  const redirectUri = `${APP_URL}/auth/callback`;

  // IMPORTANT: în producție, state ar trebui persistat (cookie/DB).
  // Pentru început, îl lăsăm simplu (dar există un risc teoretic).
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

/**
 * OAuth callback
 */
app.get("/auth/callback", async (req: Request, res: Response) => {
  try {
    const shop = String(req.query.shop || "");
    const code = String(req.query.code || "");
    const hmac = String(req.query.hmac || "");
    const state = String(req.query.state || "");

    if (!shop || !code || !hmac || !state) return res.status(400).send("Missing params");

    const ok = verifyOauthHmacFromQuery(
      Object.fromEntries(Object.entries(req.query).map(([k, v]) => [k, String(v)]))
    );
    if (!ok) return res.status(401).send("HMAC verification failed");

    const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }),
    });

    const tokenText = await tokenResp.text();
    if (!tokenResp.ok) return res.status(500).send(`Token exchange failed: ${tokenText}`);

    const tokenJson = JSON.parse(tokenText) as { access_token: string; scope: string };
    const accessToken = tokenJson.access_token;

    // Save token
    await pool.query(
      `
      INSERT INTO shops (shop, access_token)
      VALUES ($1, $2)
      ON CONFLICT (shop)
      DO UPDATE SET
        access_token = EXCLUDED.access_token,
        updated_at = NOW();
      `,
      [shop, accessToken]
    );

    console.log(`✅ Token saved for ${shop}. Registering webhooks...`);

    // Auto-register webhooks after install
    await registerWebhooks(shop, accessToken);

    return res.status(200).send("✅ Installed OK. Token saved + webhooks registered.");
  } catch (e: any) {
    console.error("Auth callback error:", e);
    return res.status(500).send(`Auth callback error: ${e?.message || "unknown"}`);
  }
});

/**
 * WEBHOOKS
 * IMPORTANT: Use raw body to verify HMAC.
 */
app.post("/webhooks/orders_create", express.raw({ type: "application/json" }), async (req: any, res: Response) => {
  const hmac = req.header("X-Shopify-Hmac-Sha256");
  const topic = req.header("X-Shopify-Topic") || "ORDERS_CREATE";
  const shop = req.header("X-Shopify-Shop-Domain") || "unknown";
  const webhookId = req.header("X-Shopify-Webhook-Id") || null;

  const rawBody: Buffer = req.body;
  const ok = verifyWebhookHmac(rawBody, hmac);

  if (!ok) {
    console.warn("❌ Webhook HMAC failed:", { topic, shop });
    return res.status(401).send("Invalid HMAC");
  }

  const payload = JSON.parse(rawBody.toString("utf8"));
  console.log("📩 WEBHOOK ORDERS_CREATE", { shop, webhookId, orderId: payload?.id, financial_status: payload?.financial_status });

  await pool.query(
    `INSERT INTO webhook_events (shop, topic, webhook_id, payload) VALUES ($1,$2,$3,$4)`,
    [shop, topic, webhookId, payload]
  );

  return res.status(200).send("ok");
});

app.post("/webhooks/orders_paid", express.raw({ type: "application/json" }), async (req: any, res: Response) => {
  const hmac = req.header("X-Shopify-Hmac-Sha256");
  const topic = req.header("X-Shopify-Topic") || "ORDERS_PAID";
  const shop = req.header("X-Shopify-Shop-Domain") || "unknown";
  const webhookId = req.header("X-Shopify-Webhook-Id") || null;

  const rawBody: Buffer = req.body;
  const ok = verifyWebhookHmac(rawBody, hmac);

  if (!ok) {
    console.warn("❌ Webhook HMAC failed:", { topic, shop });
    return res.status(401).send("Invalid HMAC");
  }

  const payload = JSON.parse(rawBody.toString("utf8"));
  console.log("💰 WEBHOOK ORDERS_PAID", { shop, webhookId, orderId: payload?.id });

  await pool.query(
    `INSERT INTO webhook_events (shop, topic, webhook_id, payload) VALUES ($1,$2,$3,$4)`,
    [shop, topic, webhookId, payload]
  );

  // TODO: aici chemi neoSys /factura (Factura la plata)
  // - construiești XML cu datele clientului + articole (SKU/EAN etc)
  // - trimiți către neoSys
  // - salvezi ID factura / număr în DB

  return res.status(200).send("ok");
});

app.post("/webhooks/fulfillments_create", express.raw({ type: "application/json" }), async (req: any, res: Response) => {
  const hmac = req.header("X-Shopify-Hmac-Sha256");
  const topic = req.header("X-Shopify-Topic") || "FULFILLMENTS_CREATE";
  const shop = req.header("X-Shopify-Shop-Domain") || "unknown";
  const webhookId = req.header("X-Shopify-Webhook-Id") || null;

  const rawBody: Buffer = req.body;
  const ok = verifyWebhookHmac(rawBody, hmac);

  if (!ok) {
    console.warn("❌ Webhook HMAC failed:", { topic, shop });
    return res.status(401).send("Invalid HMAC");
  }

  const payload = JSON.parse(rawBody.toString("utf8"));
  console.log("📦 WEBHOOK FULFILLMENTS_CREATE", { shop, webhookId, fulfillmentId: payload?.id, orderId: payload?.order_id });

  await pool.query(
    `INSERT INTO webhook_events (shop, topic, webhook_id, payload) VALUES ($1,$2,$3,$4)`,
    [shop, topic, webhookId, payload]
  );

  // TODO: dacă e COD și vrei să facturezi la expediere -> aici faci factura
  return res.status(200).send("ok");
});

/**
 * Start server
 */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running: ${APP_URL} (port ${PORT})`);
});