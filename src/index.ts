import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { Pool } from "pg";

dotenv.config();

const app = express();

// --- ENV ---
const {
  PORT = "3000",
  SHOPIFY_API_KEY,
  SHOPIFY_API_SECRET,
  SHOPIFY_SCOPES = "read_products,write_products,read_orders,write_orders,write_fulfillments",
  SHOPIFY_APP_URL,           // ex: https://neosys-shopify-app.onrender.com
  DATABASE_URL,

  // optional (dacă vrei să forțezi un shop la test)
  DEFAULT_SHOP
} = process.env;

if (!SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !SHOPIFY_APP_URL || !DATABASE_URL) {
  console.error("Missing env. Required: SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SHOPIFY_APP_URL, DATABASE_URL");
  process.exit(1);
}

// --- DB ---
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Render Postgres
});

// --- Helpers ---
function timingSafeEqual(a: string, b: string) {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function verifyShopifyHmacFromQuery(query: Record<string, any>): boolean {
  // Shopify OAuth redirect: query includes hmac + rest params
  const { hmac, signature, ...rest } = query as any;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET!)
    .update(message)
    .digest("hex");

  return timingSafeEqual(digest, String(hmac));
}

function verifyWebhookHmac(rawBody: Buffer, hmacHeader: string | undefined): boolean {
  if (!hmacHeader) return false;

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET!)
    .update(rawBody)
    .digest("base64");

  return timingSafeEqual(digest, hmacHeader);
}

async function ensureTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shop_tokens (
      shop TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
ensureTables().catch((e) => console.error("DB init error:", e));

// --- Basic ---
app.get("/", (_req, res) => {
  res.status(200).send("OK");
});

// --- OAuth start ---
// GET /auth?shop=xxx.myshopify.com
app.get("/auth", (req, res) => {
  const shop = (req.query.shop as string) || DEFAULT_SHOP;
  if (!shop) return res.status(400).send("Missing shop");

  // state random (poți salva și în DB/session; pentru simplu demo îl lăsăm fix sau random)
  const state = crypto.randomBytes(16).toString("hex");

  const redirectUri = `${SHOPIFY_APP_URL}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_API_KEY}` +
    `&scope=${encodeURIComponent(SHOPIFY_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  return res.redirect(installUrl);
});

// --- OAuth callback ---
// Shopify hits: /auth/callback?code=...&shop=...&hmac=...&state=...
app.get("/auth/callback", async (req, res) => {
  try {
    if (!verifyShopifyHmacFromQuery(req.query as any)) {
      return res.status(400).send("Invalid HMAC");
    }

    const shop = String(req.query.shop || "");
    const code = String(req.query.code || "");
    if (!shop || !code) return res.status(400).send("Missing shop or code");

    const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code
      })
    });

    if (!tokenResp.ok) {
      const txt = await tokenResp.text();
      console.error("Token exchange failed:", tokenResp.status, txt);
      return res.status(500).send("Token exchange failed");
    }

    // TS18046 fix: cast
    const tokenJson = (await tokenResp.json()) as any;
    const accessToken: string | undefined = tokenJson.access_token;

    if (!accessToken) {
      console.error("No access_token in response:", tokenJson);
      return res.status(500).send("No access token");
    }

    // save token
    await pool.query(
      `INSERT INTO shop_tokens (shop, access_token) VALUES ($1,$2)
       ON CONFLICT (shop) DO UPDATE SET access_token=EXCLUDED.access_token, updated_at=NOW()`,
      [shop, accessToken]
    );

    console.log(`✅ Installed OK. Token saved for ${shop}`);

    // auto-register webhooks
    await registerWebhooks(shop, accessToken).catch((e) => {
      console.error("Webhook registration error:", e);
    });

    return res.status(200).send("Installed OK. Token saved. Webhooks registered.");
  } catch (e: any) {
    console.error("Callback error:", e);
    return res.status(500).send("Callback error");
  }
});

// --- Webhook receiver (raw body for HMAC verification) ---
app.post("/webhooks/orders_create", express.raw({ type: "application/json" }), (req, res) => {
  try {
    const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || undefined;
    const ok = verifyWebhookHmac(req.body as Buffer, hmacHeader);

    if (!ok) {
      console.warn("❌ Webhook HMAC failed");
      return res.status(401).send("Invalid webhook signature");
    }

    const topic = req.get("X-Shopify-Topic");
    const shop = req.get("X-Shopify-Shop-Domain");

    const payloadStr = (req.body as Buffer).toString("utf8");
    const payload = JSON.parse(payloadStr);

    console.log("✅ Webhook received:", { topic, shop, order_id: payload?.id });

    // TODO: aici trimiți în NeoSys / ERP sau salvezi în DB
    return res.status(200).send("ok");
  } catch (e) {
    console.error("Webhook handler error:", e);
    return res.status(200).send("ok"); // Shopify vrea 200 rapid
  }
});

// --- Register webhooks via Admin REST ---
async function registerWebhooks(shop: string, accessToken: string) {
  const webhookAddress = `${SHOPIFY_APP_URL}/webhooks/orders_create`;

  // orders/create exemplu (poți adăuga și altele)
  const body = {
    webhook: {
      topic: "orders/create",
      address: webhookAddress,
      format: "json"
    }
  };

  const resp = await fetch(`https://${shop}/admin/api/2025-07/webhooks.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken
    },
    body: JSON.stringify(body)
  });

  const txt = await resp.text();
  if (!resp.ok) {
    console.error("❌ Webhook create failed:", resp.status, txt);
    return;
  }

  console.log("✅ Webhook registered:", txt);
}

// --- Start ---
app.listen(Number(PORT), () => {
  console.log(`Server running on port ${PORT}`);
});