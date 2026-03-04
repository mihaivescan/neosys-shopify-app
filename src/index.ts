import express, { Request, Response } from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import { Pool } from "pg";

const app = express();

// Shopify webhooks need raw body to verify HMAC
app.use(
  "/webhooks",
  express.raw({
    type: "*/*",
  })
);

// For normal routes
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const APP_URL = mustEnv("APP_URL"); // e.g. https://neosys-shopify-app.onrender.com
const SHOPIFY_API_KEY = mustEnv("SHOPIFY_API_KEY");
const SHOPIFY_API_SECRET = mustEnv("SHOPIFY_API_SECRET");
const SHOPIFY_WEBHOOK_SECRET = mustEnv("SHOPIFY_WEBHOOK_SECRET"); // usually same as SHOPIFY_API_SECRET
const SCOPES = mustEnv("SCOPES"); // comma separated: read_orders,write_products,...

const pool = new Pool({
  connectionString: mustEnv("DATABASE_URL"),
  ssl: process.env.DATABASE_URL?.includes("render.com") ? { rejectUnauthorized: false } : undefined,
});

async function ensureDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shopify_tokens (
      shop TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      installed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

// ---------- Helpers ----------
function mustEnv(key: string): string {
  const v = process.env[key];
  if (!v) throw new Error(`Missing env var: ${key}`);
  return v;
}

function safeEqual(a: string, b: string) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifyOAuthHmac(query: Record<string, any>): boolean {
  const { hmac, signature, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("&");

  const digest = crypto.createHmac("sha256", SHOPIFY_API_SECRET).update(message).digest("hex");
  return safeEqual(digest, String(hmac));
}

function verifyWebhookHmac(rawBody: Buffer, hmacHeader: string | undefined): boolean {
  if (!hmacHeader) return false;
  const digest = crypto.createHmac("sha256", SHOPIFY_WEBHOOK_SECRET).update(rawBody).digest("base64");
  return safeEqual(digest, hmacHeader);
}

async function saveToken(shop: string, token: string) {
  await pool.query(
    `INSERT INTO shopify_tokens (shop, access_token)
     VALUES ($1, $2)
     ON CONFLICT (shop) DO UPDATE SET access_token = EXCLUDED.access_token, installed_at = NOW()`,
    [shop, token]
  );
}

async function getToken(shop: string): Promise<string | null> {
  const r = await pool.query(`SELECT access_token FROM shopify_tokens WHERE shop=$1`, [shop]);
  return r.rows?.[0]?.access_token ?? null;
}

async function shopifyGraphQL(shop: string, accessToken: string, query: string, variables?: any) {
  const res = await fetch(`https://${shop}/admin/api/2026-01/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Shopify GraphQL HTTP ${res.status}: ${JSON.stringify(json)}`);
  }
  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

// Create or ensure webhook subscription for topic + callback
async function ensureWebhook(shop: string, accessToken: string, topic: string, callbackUrl: string) {
  // Try to find existing subscription with same topic+callback (best-effort)
  const listQ = `
    query ListWebhooks($first:Int!) {
      webhookSubscriptions(first:$first) {
        edges {
          node {
            id
            topic
            endpoint {
              __typename
              ... on WebhookHttpEndpoint { callbackUrl }
            }
          }
        }
      }
    }
  `;
  const data = await shopifyGraphQL(shop, accessToken, listQ, { first: 100 });
  const edges = data.webhookSubscriptions.edges as any[];
  const exists = edges.find((e) => {
    const n = e.node;
    const cb = n.endpoint?.callbackUrl;
    return n.topic === topic && cb === callbackUrl;
  });

  if (exists) return { id: exists.node.id, created: false };

  const createQ = `
    mutation CreateWebhook($topic: WebhookSubscriptionTopic!, $callbackUrl: URL!) {
      webhookSubscriptionCreate(
        topic: $topic
        webhookSubscription: { callbackUrl: $callbackUrl, format: JSON }
      ) {
        webhookSubscription { id topic }
        userErrors { field message }
      }
    }
  `;

  const created = await shopifyGraphQL(shop, accessToken, createQ, {
    topic,
    callbackUrl,
  });

  const errs = created.webhookSubscriptionCreate.userErrors;
  if (errs?.length) {
    throw new Error(`Webhook create userErrors: ${JSON.stringify(errs)}`);
  }

  return { id: created.webhookSubscriptionCreate.webhookSubscription.id, created: true };
}

async function registerWebhooks(shop: string, accessToken: string) {
  // ✅ topic-uri safe/uzuale
  const hooks = [
    { topic: "ORDERS_CREATE", path: "/webhooks/orders_create" },
    { topic: "ORDERS_PAID", path: "/webhooks/orders_paid" },

    // ✅ pentru fulfillment:
    { topic: "FULFILLMENTS_CREATE", path: "/webhooks/fulfillments_create" },
  ];

  for (const h of hooks) {
    const url = `${APP_URL}${h.path}`;
    const res = await ensureWebhook(shop, accessToken, h.topic, url);
    console.log(`✅ Webhook ensured: ${h.topic} -> ${url} (id=${res.id})`);
  }
}

// ---------- Routes ----------
app.get("/", (_req: Request, res: Response) => {
  res.status(200).send("OK");
});

// start OAuth
app.get("/auth", async (req: Request, res: Response) => {
  const shop = String(req.query.shop || "").trim();
  const state = crypto.randomBytes(16).toString("hex");

  if (!shop || !shop.endsWith(".myshopify.com")) {
    return res.status(400).send("Missing or invalid shop");
  }

  // Minimal: redirect to Shopify OAuth
  const redirectUri = `${APP_URL}/auth/callback`;
  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  // In production store "state" per shop (db/redis). For now, just pass through.
  res.redirect(installUrl);
});

app.get("/auth/callback", async (req: Request, res: Response) => {
  try {
    const shop = String(req.query.shop || "").trim();
    const code = String(req.query.code || "").trim();

    if (!shop || !code) return res.status(400).send("Missing shop or code");
    if (!verifyOAuthHmac(req.query as any)) return res.status(401).send("Invalid HMAC");

    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }),
    });

    const tokenJson: any = await tokenRes.json();
    if (!tokenRes.ok) {
      throw new Error(`Token exchange failed: ${tokenRes.status} ${JSON.stringify(tokenJson)}`);
    }

    const accessToken = tokenJson.access_token as string;
    await ensureDb();
    await saveToken(shop, accessToken);

    console.log(`✅ Token saved for ${shop}. Registering webhooks...`);
    await registerWebhooks(shop, accessToken);

    res.status(200).send("Installed OK. Token obtained & saved. Webhooks registered.");
  } catch (e: any) {
    console.error("Auth callback error:", e?.message || e);
    res.status(500).send(`Auth callback error: ${e?.message || "unknown"}`);
  }
});

// ---------- Webhooks ----------
app.post("/webhooks/orders_create", async (req: Request, res: Response) => {
  try {
    const hmac = req.header("X-Shopify-Hmac-Sha256") || undefined;
    const shop = req.header("X-Shopify-Shop-Domain") || "unknown";

    const raw = req.body as Buffer;
    if (!verifyWebhookHmac(raw, hmac)) return res.status(401).send("Invalid webhook HMAC");

    const payload = JSON.parse(raw.toString("utf8"));

    // Aici detectezi COD, dacă vrei:
    // - payload.gateway / payment_gateway_names
    // - payload.financial_status
    // Exemplu:
    // const gateways = (payload.payment_gateway_names || []).join(",").toLowerCase();
    // const isCod = gateways.includes("cash") || gateways.includes("cod");

    console.log("📦 ORDERS_CREATE", shop, payload?.id, payload?.name);
    res.status(200).send("ok");
  } catch (e: any) {
    console.error("orders_create webhook error:", e?.message || e);
    res.status(500).send("error");
  }
});

app.post("/webhooks/orders_paid", async (req: Request, res: Response) => {
  try {
    const hmac = req.header("X-Shopify-Hmac-Sha256") || undefined;
    const shop = req.header("X-Shopify-Shop-Domain") || "unknown";
    const raw = req.body as Buffer;

    if (!verifyWebhookHmac(raw, hmac)) return res.status(401).send("Invalid webhook HMAC");

    const payload = JSON.parse(raw.toString("utf8"));
    console.log("💰 ORDERS_PAID", shop, payload?.id, payload?.name);

    res.status(200).send("ok");
  } catch (e: any) {
    console.error("orders_paid webhook error:", e?.message || e);
    res.status(500).send("error");
  }
});

app.post("/webhooks/fulfillments_create", async (req: Request, res: Response) => {
  try {
    const hmac = req.header("X-Shopify-Hmac-Sha256") || undefined;
    const shop = req.header("X-Shopify-Shop-Domain") || "unknown";
    const raw = req.body as Buffer;

    if (!verifyWebhookHmac(raw, hmac)) return res.status(401).send("Invalid webhook HMAC");

    const payload = JSON.parse(raw.toString("utf8"));
    console.log("🚚 FULFILLMENTS_CREATE", shop, payload?.id);

    res.status(200).send("ok");
  } catch (e: any) {
    console.error("fulfillments_create webhook error:", e?.message || e);
    res.status(500).send("error");
  }
});

// ---------- Start ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

ensureDb()
  .then(() => {
    app.listen(PORT, () => console.log(`✅ Server listening on ${PORT}`));
  })
  .catch((e) => {
    console.error("DB init failed:", e);
    process.exit(1);
  });