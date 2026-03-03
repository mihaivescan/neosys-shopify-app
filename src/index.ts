import crypto from "crypto";
import fetch from "node-fetch";

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

// 1) START OAUTH
app.get("/auth", (req, res) => {
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

// 2) CALLBACK OAUTH
app.get("/auth/callback", async (req, res) => {
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

  // TODO: aici salvezi in Postgres tokenul pentru shop
  // ex: await saveToken(shop, accessToken);

  return res.send("✅ Installed OK. Token obtained (not yet saved).");
});