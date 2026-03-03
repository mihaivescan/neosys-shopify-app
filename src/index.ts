import crypto from "crypto";
import fetch from "node-fetch";
import express from "express";
import type { Request, Response } from "express";
import { Pool } from "pg";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
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
  console.log("DB initialized");
}

initDb().catch(console.error);

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop) return res.status(200).send("OK (missing ?shop=...)");
  return res.redirect(`/auth?shop=${encodeURIComponent(shop)}`);
});

// env
const APP_URL = process.env.APP_URL!;
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY!;
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET!;
const SCOPES = process.env.SCOPES!;

// helper HMAC
function verifyHmacFromQuery(query: Record<string, string>) {
  const { hmac, ...rest } = query;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${rest[k]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", SHOPIFY_API_SECRET)
    .update(message)
    .digest("hex");

  return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmac));
}

// health (util pentru Render)
app.get("/health", (_req: Request, res: Response) => res.status(200).send("ok"));

// 1) START OAUTH
app.get("/auth", (req: Request, res: Response) => {
  const shop = String(req.query.shop || "").trim();
  if (!shop.endsWith(".myshopify.com")) return res.status(400).send("Invalid shop");

  const state = crypto.randomBytes(16).toString("hex");
  const redirectUri = `${APP_URL}/auth/callback`;

  // IMPORTANT: aici ar trebui să salvezi state (cookie/db) ca să-l verifici în callback.
  // Momentan îl trimiți dar nu îl validezi (doar verifici că există).

  const installUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${encodeURIComponent(state)}`;

  return res.redirect(installUrl);
});

// 2) CALLBACK OAUTH
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
console.log("SHOPIFY ACCESS TOKEN =", accessToken);

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

  return res.send("✅ Installed OK. Token obtained (not yet saved).");
});

// ✅ FOARTE IMPORTANT pentru Render
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});