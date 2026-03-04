import crypto from "crypto";
import fetch from "node-fetch";
import express from "express";
import type { Request, Response } from "express";
import { Pool } from "pg";

/**
 * ENV required on Render:
 * - APP_URL=https://neosys-shopify-app.onrender.com
 * - SHOPIFY_API_KEY=...
 * - SHOPIFY_API_SECRET=...
 * - SCOPES=read_orders,read_products,write_products,read_inventory,write_inventory
 * - DATABASE_URL=...
 * Optional:
 * - SHOPIFY_API_VERSION=2026-01
 */

const APP_URL = process.env.APP_URL || "";
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY || "";
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || "";
const SCOPES = process.env.SCOPES || "";
const API_VERSION = process.env.SHOPIFY_API_VERSION || "2026-01";

if (!APP_URL || !SHOPIFY_API_KEY || !SHOPIFY_API_SECRET || !SCOPES || !process.env.DATABASE_URL) {
  console.warn(
    "⚠️ Missing ENV vars. Required: APP_URL, SHOPIFY_API_KEY, SHOPIFY_API_SECRET, SCOPES, DATABASE_URL"
  );
}

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

  // optional: dedupe webhooks
  await pool.query(`
    CREATE TABLE IF NOT EXISTS webhook_events (
      webhook_id TEXT PRIMARY KEY,
      shop TEXT NOT NULL,
      topic TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("DB initialized");
}
initDb().catch((e) => console.error("DB init error:", e));

const app = express();

/**
 * =========================
 * 1) WEBHOOK ENDPOINT (RAW)
 * =========================
 * MUST be defined before app.use(express.json()) so we can validate HMAC on raw body.
 */
app.post("/webhooks/shopify", express.raw({ type: "*/*" }), async (req, res) => {
  const hmacHeader = String(req.get("X-Shopify-Hmac-Sha256") || "");
  const topic = String(req.get("X-Shopify-Topic") || "");
  const shop = String(req.get("X-Shopify-Shop-Domain") || "");
  const webhookId = String(req.get("X-Shopify-Webhook-Id") || "");

  try {
    const rawBody = req.body as Buffer;

    // HMAC verify (base64)
    const digest = crypto.createHmac("sha256", SHOPIFY_API_SECRET).update(rawBody).digest("base64");
    const ok =
      digest.length === hmacHeader.length &&
      crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader));

    if (!ok) return res.status(401).send("Invalid HMAC");

    // respond fast
    res.status(200).send("ok");

    // dedupe (optional)
    if (webhookId) {
      try {
        await pool.query(
          `INSERT INTO webhook_events (webhook_id, shop, topic) VALUES ($1, $2, $3)`,
          [webhookId, shop, topic]
        );
      } catch {
        // duplicate => already processed
        return;
      }
    }

    const payloadText = rawBody.toString("utf8");
    const payload = payloadText ? JSON.parse(payloadText) : {};

    console.log("✅ Webhook received:", { shop, topic, webhookId });

    // Load token for this shop (so you can call Shopify / NeoSys)
    const accessToken = await getShopToken(shop);
    if (!accessToken) {
      console.error("No token found for shop:", shop);
      return;
    }

    // Process by topic
    await handleWebhook({ shop, topic, payload, accessToken });
  } catch (e) {
    console.error("Webhook processing error:", e);
    // response already sent; Shopify will retry if it didn't get 200, but we did send 200.
  }
});

// After webhook route, use JSON for normal endpoints
app.use(express.json());

/**
 * =========================
 * 2) BASIC ROUTES
 * =========================
 */
app.get("/", (_req: Request, res: Response) => res.status(200).send("OK"));
app.get("/health", (_req: Request, res: Response) => res.status(200).send("ok"));

/**
 * =========================
 * 3) OAUTH HELPERS
 * =========================
 */
function verifyHmacFromQuery(query: Record<string, string>) {
  const { hmac, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");

  const digest = crypto.createHmac("sha256", SHOPIFY_API_SECRET).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

/**
 * =========================
 * 4) OAUTH ROUTES
 * =========================
 */
app.get("/auth", (req: Request, res: Response) => {
  const shop = String(req.query.shop || "").trim();
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop");

  const state = crypto.randomBytes(16).toString("hex");
  const redirectUri = `${APP_URL}/auth/callback`;

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

app.get("/auth/callback", async (req: Request, res: Response) => {
  const shop = String(req.query.shop || "");
  const code = String(req.query.code || "");
  const hmac = String(req.query.hmac || "");
  const state = String(req.query.state || "");

  if (!shop || !code || !hmac || !state) return res.status(400).send("Missing params");

  const ok = verifyHmacFromQuery(
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

  if (!tokenResp.ok) {
    const txt = await tokenResp.text();
    return res.status(500).send(`Token exchange failed: ${txt}`);
  }

  const tokenJson = (await tokenResp.json()) as { access_token: string; scope: string };
  const accessToken = tokenJson.access_token;

  // Save token in DB (upsert)
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

  // Register webhooks right after install
  try {
    await registerAllWebhooks(shop, accessToken);
  } catch (e) {
    console.error("Webhook registration error:", e);
    // continue; install still OK
  }

  return res.send("✅ Installed OK. Token saved + webhooks registered.");
});

/**
 * =========================
 * 5) WEBHOOK REGISTRATION
 * =========================
 */
async function registerWebhook(shop: string, accessToken: string, topic: string) {
  const address = `${APP_URL}/webhooks/shopify`;

  const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/webhooks.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({
      webhook: {
        topic,
        address,
        format: "json",
      },
    }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Webhook create failed (${topic}): ${txt}`);
  }
}

async function registerAllWebhooks(shop: string, accessToken: string) {
  // topics you asked for ("toate")
  const topics = [
    "orders/create",
    "orders/paid",
    "orders/cancelled",
    "refunds/create",
    "fulfillments/create",
    "fulfillments/update",
    "products/create",
    "products/update",
    "inventory_levels/update",
  ];

  for (const t of topics) {
    try {
      await registerWebhook(shop, accessToken, t);
      console.log("✅ Webhook registered:", t);
    } catch (e: any) {
      // if already exists, Shopify may return 422; we just log
      console.warn("⚠️ Webhook register failed:", t, String(e?.message || e));
    }
  }
}

/**
 * =========================
 * 6) DB HELPERS
 * =========================
 */
async function getShopToken(shop: string): Promise<string | null> {
  const r = await pool.query(`SELECT access_token FROM shops WHERE shop = $1`, [shop]);
  return r.rowCount ? (r.rows[0].access_token as string) : null;
}

/**
 * =========================
 * 7) WEBHOOK HANDLER (YOUR LOGIC)
 * =========================
 */
async function handleWebhook(input: {
  shop: string;
  topic: string;
  payload: any;
  accessToken: string;
}) {
  const { shop, topic, payload } = input;

  // Useful IDs
  const orderId = payload?.id;

  switch (topic) {
    case "orders/paid":
      // ONLINE: factura la plata
      console.log("🧾 orders/paid => issue invoice", { shop, orderId });
      // TODO: build neoSys XML & POST factura
      return;

    case "fulfillments/create":
    case "fulfillments/update":
      // COD: factura la fulfillment (cum ai zis)
      console.log("📦 fulfillment => COD invoice", { shop, orderId });
      // TODO: build neoSys XML & POST factura
      return;

    case "refunds/create":
      console.log("↩️ refund => stornare", { shop, orderId });
      // TODO: POST factura_stornare in neoSys
      return;

    case "orders/cancelled":
      console.log("❌ order cancelled", { shop, orderId });
      return;

    case "products/create":
    case "products/update":
      console.log("🛒 product changed", { shop, productId: payload?.id });
      return;

    case "inventory_levels/update":
      console.log("📊 inventory updated", { shop, inventoryItemId: payload?.inventory_item_id });
      return;

    default:
      console.log("ℹ️ ignored topic", topic);
      return;
  }
}

/**
 * =========================
 * 8) START SERVER (Render)
 * =========================
 */
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});