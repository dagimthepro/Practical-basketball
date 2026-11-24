// JHub key gate -- runs on Cloudflare Workers.
//
// Replaces the old client-side-only scheme: instead of shipping a file that
// anyone with a key (or who finds any key at all) can decode offline and
// forever, the real decode happens here, server-side, on every request.
// A request without a valid key gets nothing back. The sidecar JSON this
// fetches is still fully encrypted ciphertext -- publishing it is no
// different from publishing the old .lua file; the actual gate is here.
//
// This file now also serves /freekey -- the landing page for the free,
// ad-gated tier. Linkvertise's Target-Link anti-bypass feature appends
// ?hash=<64 hex chars> to this URL only once a visitor has genuinely
// completed the ad flow (not just been redirected through it); we verify
// that hash server-to-server against Linkvertise's own API before ever
// handing out a key, which is what actually defeats bypass tools (they
// can fake the redirect, they can't fake Linkvertise's own completion
// state). See cf-worker/README_FREEKEY.md for the required bindings.
//
// Also logs every key-gate request (valid or not) as a real Discord bot
// message -- Roblox username, job ID, IP, and (if you've recorded it) which
// buyer that key belongs to -- for anti-leak tracing. See
// cf-worker/README_EXEC_LOGGING.md for setup.
//
// Needs several things this script alone can't provide: a Worker secret
// named LINKVERTISE_TOKEN (your 64-char anti-bypass token from the
// Linkvertise dashboard), a KV binding named FREE_POOL (pre-seeded with
// unused free keys), secrets DISCORD_BOT_TOKEN + DISCORD_LOG_CHANNEL_ID,
// and an optional KV binding KEY_OWNERS (key -> Discord buyer). Everything
// else deploys as-is -- any of these being unset just silently disables
// that one feature rather than breaking the gate.

const SIDECAR_URL =
  "https://raw.githubusercontent.com/dagimthepro/Practical-basketball/main/dist/jhub_sidecar.json";

const LINKVERTISE_VERIFY_URL =
  "https://publisher.linkvertise.com/api/v1/anti_bypassing";

function fnv1a32(bytes) {
  let h = 0x811c9dc5; // 2166136261
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193) >>> 0; // 16777619
  }
  return h >>> 0;
}

function xorshift32Next(state) {
  state ^= state << 13;
  state ^= state >>> 17;
  state ^= state << 5;
  return state >>> 0;
}

function seedFrom(bytes) {
  const h = fnv1a32(bytes);
  return h === 0 ? 1 : h;
}

function xorStream(data, seedBytes) {
  const n = data.length;
  const out = new Uint8Array(n);
  let state = seedFrom(seedBytes);
  let i = 0;
  while (i < n) {
    state = xorshift32Next(state);
    const bs = [
      (state >>> 24) & 0xff,
      (state >>> 16) & 0xff,
      (state >>> 8) & 0xff,
      state & 0xff,
    ];
    for (let k = 0; k < 4 && i < n; k++, i++) {
      out[i] = data[i] ^ bs[k];
    }
  }
  return out;
}

function b64DecodeCustom(s, alphabet) {
  const rev = new Int16Array(256).fill(-1);
  for (let i = 0; i < 64; i++) rev[alphabet.charCodeAt(i)] = i;
  let len = s.length;
  while (len > 0 && s.charCodeAt(len - 1) === 61 /* '=' */) len--;
  const outLen = Math.floor((len * 6) / 8);
  const out = new Uint8Array(outLen);
  let acc = 0,
    bits = 0,
    pos = 0;
  for (let i = 0; i < len; i++) {
    const v = rev[s.charCodeAt(i)];
    acc = acc * 64 + v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const shifted = Math.floor(acc / Math.pow(2, bits));
      out[pos++] = shifted % 256;
      acc = acc % Math.pow(2, bits);
    }
  }
  return out;
}

function strToBytes(s) {
  return new TextEncoder().encode(s);
}

// Compares two strings without bailing out at the first difference.
function safeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

function normKey(raw) {
  return (raw || "").replace(/\s+/g, "").toLowerCase();
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function attemptUnlock(rawKey, sidecar) {
  const norm = normKey(rawKey);
  if (!norm) return null;
  const normBytes = strToBytes(norm);
  const check2Prefix = strToBytes("check2|");
  for (const entry of sidecar.wraps) {
    const wrapped = b64DecodeCustom(entry.w, sidecar.alphabet);
    const seedBytes = concatBytes(normBytes, strToBytes("|" + entry.s));
    const candidate = xorStream(wrapped, seedBytes);
    if (
      fnv1a32(candidate) === sidecar.mhash &&
      fnv1a32(concatBytes(check2Prefix, candidate)) === sidecar.mhash2
    ) {
      return candidate;
    }
  }
  return null;
}

function reconstruct(M, sidecar) {
  const parts = [];
  for (let i = 0; i < sidecar.order.length; i++) {
    const name = sidecar.order[i];
    const raw = b64DecodeCustom(sidecar.chunks[name], sidecar.alphabet);
    const seedBytes = concatBytes(M, strToBytes("|" + (i + 1)));
    parts.push(xorStream(raw, seedBytes));
  }
  return concatBytes(...parts);
}

function htmlPage(title, bodyHtml, status) {
  return new Response(
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{background:#0f1115;color:#eee;font-family:system-ui,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#181b22;border-radius:12px;padding:32px;max-width:480px;text-align:center}
.key{font-size:20px;font-weight:700;background:#0f1115;border-radius:8px;padding:14px;
margin:16px 0;word-break:break-all;color:#7CFC7C}
button{background:#3b5bff;color:#fff;border:0;border-radius:8px;padding:10px 18px;
font-size:14px;cursor:pointer}
a{color:#7aa2ff}</style></head>
<body><div class="card">${bodyHtml}</div></body></html>`,
    { status: status || 200, headers: { "content-type": "text/html; charset=utf-8" } }
  );
}

// Calls Linkvertise's own backend to ask whether this specific hash
// corresponds to a visitor who actually completed the ad flow. A hash can
// only be confirmed once -- Linkvertise deletes it server-side on success --
// so this also can't be replayed even if someone captures the URL.
async function verifyLinkvertiseHash(hash, token) {
  const verifyUrl = `${LINKVERTISE_VERIFY_URL}?token=${encodeURIComponent(token)}&hash=${encodeURIComponent(hash)}`;
  const resp = await fetch(verifyUrl, { method: "POST" });
  const text = (await resp.text()).trim();
  return /^true$/i.test(text);
}

// Claims one "available" key from the free-tier pool. Not perfectly atomic
// under heavy concurrency (list-then-put), but the pool is small and
// low-traffic, so a rare double-claim is an acceptable tradeoff rather than
// something worth a Durable Object for.
async function claimFreeKey(pool, hash) {
  const list = await pool.list({ limit: 1000 });
  for (const entry of list.keys) {
    if (entry.metadata && entry.metadata.status === "available") {
      await pool.put(entry.name, "issued", {
        metadata: { status: "issued", at: Date.now(), hash },
      });
      return entry.name;
    }
  }
  return null;
}

async function handleFreeKey(request, env) {
  const url = new URL(request.url);
  const hash = url.searchParams.get("hash") || "";

  if (!hash) {
    return htmlPage(
      "JHub - get a free key",
      `<h2>Missing link</h2><p>Open this page through the Linkvertise link, not directly.</p>`,
      400
    );
  }
  if (!env.LINKVERTISE_TOKEN || !env.FREE_POOL) {
    return htmlPage(
      "JHub - not configured",
      `<h2>Not set up yet</h2><p>This Worker is missing its LINKVERTISE_TOKEN secret or FREE_POOL KV binding.</p>`,
      500
    );
  }

  let verified = false;
  try {
    verified = await verifyLinkvertiseHash(hash, env.LINKVERTISE_TOKEN);
  } catch (e) {
    return htmlPage(
      "JHub - verification failed",
      `<h2>Couldn't verify</h2><p>Linkvertise's check didn't respond. Try again in a moment.</p>`,
      502
    );
  }
  if (!verified) {
    return htmlPage(
      "JHub - not verified",
      `<h2>Link not completed</h2><p>This link looks like it was skipped or already used. Go back and complete the ad flow again to get a key.</p>`,
      403
    );
  }

  const key = await claimFreeKey(env.FREE_POOL, hash);
  if (!key) {
    return htmlPage(
      "JHub - out of keys",
      `<h2>Out of free keys right now</h2><p>The free-tier pool is empty. Check back soon.</p>`,
      503
    );
  }

  return htmlPage(
    "JHub - your free key",
    `<h2>You're unlocked</h2>
     <p>Paste this key into the JHub key prompt:</p>
     <div class="key" id="k">${key}</div>
     <button onclick="navigator.clipboard.writeText(document.getElementById('k').textContent)">Copy key</button>
     <p style="opacity:.6;font-size:12px;margin-top:16px">This key is yours -- don't share it, or it may get pulled from the pool.</p>`
  );
}

// Posts an execution record as an actual Discord bot message (via Discord's
// own REST API with a bot token -- not a webhook), and -- if a KEY_OWNERS KV
// binding exists -- attaches whichever Discord buyer you've recorded that
// key against. This is fire-and-forget: it never blocks or breaks the
// actual key-gate response, and silently no-ops if the bot isn't configured
// yet. Posting this way needs no 24/7 process -- it's a one-shot HTTP call
// to POST /channels/{id}/messages, same as any bot's REST call, just not
// backed by a live Gateway connection (so the bot shows offline in the
// member list, but messages are genuinely posted as it, not as a webhook).
async function logExecution(env, ctx, fields) {
  if (!env.DISCORD_BOT_TOKEN || !env.DISCORD_LOG_CHANNEL_ID) return;
  let owner = fields.ownerOverride || null;
  if (!owner && env.KEY_OWNERS) {
    try {
      owner = await env.KEY_OWNERS.get(normKey(fields.key));
    } catch (e) {
      /* ignore lookup failures, still log the rest */
    }
  }
  // key / user / job come straight from the query string, so strip anything that could break out of the
  // formatting or ping people (backticks, newlines, @everyone) and keep every field short.
  const clean = (v, max) =>
    String(v == null ? "" : v).replace(/[`\r\n]+/g, " ").replace(/@/g, "@\u200b").slice(0, max || 80);
  const lines = [
    `**${clean(fields.status, 120)}**`,
    `Key: \`${clean(fields.key, 64)}\``,
    owner ? `Discord buyer: ${owner}` : null,
    `Roblox user: ${clean(fields.user, 64)}`,
    `Job ID: \`${clean(fields.job, 64)}\``,
    `IP: ${clean(fields.ip, 64)}`,
  ].filter(Boolean);
  // Caller wraps this whole function in ctx.waitUntil -- just await here.
  await fetch(
    `https://discord.com/api/v10/channels/${env.DISCORD_LOG_CHANNEL_ID}/messages`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
      },
      body: JSON.stringify({ content: lines.join("\n"), allowed_mentions: { parse: [] } }),
    }
  ).catch(() => {});
}

// Reverse-looks-up a Discord user ID in KEY_OWNERS (which is stored the
// other way around: key -> Discord buyer). KEY_OWNERS is small and
// low-traffic, so a full scan on each lookup is fine -- no need for a
// second KV namespace just to index it the other direction.
async function findKeyByDiscordId(pool, discordId) {
  let cursor;
  do {
    const page = await pool.list({ cursor });
    for (const entry of page.keys) {
      const owner = await pool.get(entry.name);
      if (owner === discordId) return entry.name;
    }
    cursor = page.cursor;
  } while (cursor);
  return null;
}

// Internal-only endpoint the presence bot calls for the /mykey slash
// command. Gated behind a shared secret (set as the INTERNAL_SECRET
// Worker secret) -- never exposed to end users, since it would otherwise
// let anyone enumerate keys by guessing Discord IDs.
async function handleMyKey(request, env) {
  if (!env.INTERNAL_SECRET || !safeEqual(request.headers.get("x-internal-secret"), env.INTERNAL_SECRET)) {
    return new Response("unauthorized", { status: 401 });
  }
  if (!env.KEY_OWNERS && !env.KEYS) {
    return new Response(JSON.stringify({ found: false, reason: "no key store configured" }), {
      headers: { "content-type": "application/json" },
    });
  }
  const url = new URL(request.url);
  const discordId = url.searchParams.get("discord") || "";
  if (env.KEYS && discordId) {
    const hit = await findKeyRecordByDiscord(env, discordId);
    if (hit) {
      return new Response(JSON.stringify({ found: true, key: hit.key }), {
        headers: { "content-type": "application/json" },
      });
    }
  }
  if (!discordId) {
    return new Response(JSON.stringify({ found: false, reason: "missing discord id" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  const key = env.KEY_OWNERS ? await findKeyByDiscordId(env.KEY_OWNERS, discordId) : null;
  return new Response(JSON.stringify({ found: !!key, key: key || undefined }), {
    headers: { "content-type": "application/json" },
  });
}

// Internal-only endpoint for the bot's /linkkey and /unlinkkey commands.
// The bot itself decides who's allowed to call this (co-owners only); this
// endpoint only checks that the caller IS the bot, via the same shared
// secret as /api/mykey. Writing is a straight KV put/delete -- normKey
// keeps lookups consistent with how logExecution and findKeyByDiscordId
// already read this namespace.
async function handleLinkKey(request, env) {
  if (!env.INTERNAL_SECRET || !safeEqual(request.headers.get("x-internal-secret"), env.INTERNAL_SECRET)) {
    return new Response("unauthorized", { status: 401 });
  }
  if (!env.KEY_OWNERS) {
    return new Response(JSON.stringify({ ok: false, reason: "KEY_OWNERS not configured" }), {
      status: 500,
      headers: { "content-type": "application/json" },
    });
  }
  if (request.method !== "POST") {
    return new Response("method not allowed", { status: 405 });
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, reason: "invalid JSON body" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  const key = normKey(body.key);
  if (!key) {
    return new Response(JSON.stringify({ ok: false, reason: "missing key" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const url = new URL(request.url);
  if (url.pathname === "/api/unlinkkey") {
    await env.KEY_OWNERS.delete(key);
    return new Response(JSON.stringify({ ok: true, key, unlinked: true }), {
      headers: { "content-type": "application/json" },
    });
  }

  const discordId = (body.discordId || "").trim();
  if (!discordId) {
    return new Response(JSON.stringify({ ok: false, reason: "missing discordId" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  await env.KEY_OWNERS.put(key, discordId);
  return new Response(JSON.stringify({ ok: true, key, discordId }), {
    headers: { "content-type": "application/json" },
  });
}

// ---------------------------------------------------------------------
// Live key store (KEYS KV binding + MASTER_KEY secret)
//
// Each key is a KV record: { status, hwid, discord, created, note, lastReset }
//   status: "active" | "blacklisted"
//   hwid:   SHA-256 of the buyer's device id, bound on first use (or null)
//   discord: Discord user ID the key was redeemed/linked to (or null)
// The Worker holds the payload master key (MASTER_KEY, hex) as a secret, so
// the public sidecar carries no per-key data at all. When KEYS/MASTER_KEY
// aren't configured the old baked-in-wraps path below still works.
// ---------------------------------------------------------------------
const HWID_RESET_COOLDOWN_MS = 24 * 60 * 60 * 1000;

// "10m" = 10 minutes, "1h", "1d", "1w", "1mo" = 30 days, "1y", or
// "lifetime"/empty = no expiry. Returns {ms} (ms=null for lifetime) or
// {error}. The clock starts the first time the key is actually used.
function parseDuration(raw) {
  const t = String(raw || "").trim().toLowerCase().replace(/\s+/g, "");
  if (!t || t === "lifetime" || t === "life" || t === "perm" || t === "permanent" || t === "forever") {
    return { ms: null };
  }
  const m = t.match(/^(\d+)(s|sec|secs|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|wk|week|weeks|mo|month|months|y|yr|year|years)$/);
  if (!m) return { error: "bad duration (use e.g. 10m, 1h, 1d, 1w, 1mo, 1y, lifetime)" };
  const n = parseInt(m[1], 10);
  const u = m[2];
  const MIN = 60 * 1000, H = 60 * MIN, D = 24 * H;
  let unit;
  if (u[0] === "s") unit = 1000;
  else if (u === "m" || u.startsWith("min")) unit = MIN;
  else if (u[0] === "h") unit = H;
  else if (u[0] === "d") unit = D;
  else if (u[0] === "w") unit = 7 * D;
  else if (u === "mo" || u.startsWith("month")) unit = 30 * D;
  else unit = 365 * D;
  if (n < 1) return { error: "bad duration" };
  return { ms: n * unit };
}

// Rate limit for noisy "invalid attempt" Discord logs (best-effort,
// per Worker isolate): at most one log per key/ip every 5 minutes.
const noisyLogSeen = new Map();
function shouldLogNoisy(id) {
  const now = Date.now();
  const last = noisyLogSeen.get(id) || 0;
  if (now - last < 5 * 60 * 1000) return false;
  noisyLogSeen.set(id, now);
  if (noisyLogSeen.size > 500) {
    for (const [k, v] of noisyLogSeen) if (now - v > 5 * 60 * 1000) noisyLogSeen.delete(k);
  }
  return true;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function jsonResp(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "content-type": "application/json" },
  });
}

function genKeyString() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const rnd = crypto.getRandomValues(new Uint8Array(12));
  const part = (o) => [...rnd.slice(o, o + 4)].map((b) => A[b % A.length]).join("");
  return `JHUB-${part(0)}-${part(4)}-${part(8)}`;
}

async function getKeyRecord(env, key) {
  return await env.KEYS.get(key, { type: "json" });
}

async function putKeyRecord(env, key, rec) {
  await env.KEYS.put(key, JSON.stringify(rec));
}

async function findKeyRecordByDiscord(env, discordId) {
  let cursor;
  do {
    const page = await env.KEYS.list({ cursor });
    for (const entry of page.keys) {
      const rec = await getKeyRecord(env, entry.name);
      if (rec && rec.discord === discordId) return { key: entry.name, rec };
    }
    cursor = page.cursor;
  } while (cursor);
  return null;
}

// Management API used only by the Discord bot (shared-secret gated). The
// bot decides WHO may call what; this endpoint only checks the caller is
// the bot.
async function handleKeyApi(request, env) {
  if (!env.INTERNAL_SECRET || !safeEqual(request.headers.get("x-internal-secret"), env.INTERNAL_SECRET)) {
    return new Response("unauthorized", { status: 401 });
  }
  if (!env.KEYS) return jsonResp({ ok: false, reason: "KEYS not configured" }, 500);
  if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResp({ ok: false, reason: "invalid JSON body" }, 400);
  }
  const action = new URL(request.url).pathname.replace("/api/key/", "");

  if (action === "create") {
    const count = Math.min(Math.max(parseInt(body.count || 1, 10) || 1, 1), 50);
    const dur = parseDuration(body.duration);
    if (dur.error) return jsonResp({ ok: false, reason: dur.error }, 400);
    const made = [];
    for (let i = 0; i < count; i++) {
      const key = normKey(genKeyString());
      await putKeyRecord(env, key, {
        status: "active",
        hwid: null,
        discord: body.discordId || null,
        created: Date.now(),
        note: body.note || "",
        lastReset: 0,
        durationMs: dur.ms,
        expires: null,
      });
      made.push(key);
    }
    return jsonResp({ ok: true, keys: made, durationMs: dur.ms });
  }

  if (action === "import") {
    const keys = Array.isArray(body.keys) ? body.keys : [];
    let added = 0;
    for (const raw of keys) {
      const key = normKey(raw);
      if (!key || (await env.KEYS.get(key))) continue;
      await putKeyRecord(env, key, {
        status: "active", hwid: null, discord: null,
        created: Date.now(), note: "imported", lastReset: 0,
      });
      added++;
    }
    return jsonResp({ ok: true, added });
  }

  const key = normKey(body.key);

  if (action === "info") {
    let found = null;
    if (key) {
      const rec = await getKeyRecord(env, key);
      if (rec) found = { key, rec };
    } else if (body.discordId) {
      found = await findKeyRecordByDiscord(env, body.discordId);
    }
    if (!found) return jsonResp({ ok: true, found: false });
    const { key: k, rec } = found;
    return jsonResp({
      ok: true, found: true, key: k, status: rec.status,
      discord: rec.discord, hwidBound: !!rec.hwid,
      created: rec.created, lastReset: rec.lastReset || 0,
      durationMs: rec.durationMs || null, expires: rec.expires || null,
      expired: !!(rec.expires && Date.now() > rec.expires),
    });
  }

  if (!key) return jsonResp({ ok: false, reason: "missing key" }, 400);
  const rec = await getKeyRecord(env, key);
  if (!rec) return jsonResp({ ok: false, reason: "key not found" }, 404);

  if (action === "revoke") {
    rec.status = "blacklisted";
    await putKeyRecord(env, key, rec);
    return jsonResp({ ok: true, key });
  }
  if (action === "unrevoke") {
    rec.status = "active";
    await putKeyRecord(env, key, rec);
    return jsonResp({ ok: true, key });
  }
  if (action === "delete") {
    await env.KEYS.delete(key);
    return jsonResp({ ok: true, key });
  }
  if (action === "redeem") {
    const discordId = (body.discordId || "").trim();
    if (!discordId) return jsonResp({ ok: false, reason: "missing discordId" }, 400);
    if (rec.status !== "active") return jsonResp({ ok: false, reason: "this key is not active" });
    if (rec.expires && Date.now() > rec.expires) return jsonResp({ ok: false, reason: "this key has expired" });
    if (rec.discord && rec.discord !== discordId) {
      return jsonResp({ ok: false, reason: "this key is already redeemed by someone else" });
    }
    rec.discord = discordId;
    await putKeyRecord(env, key, rec);
    return jsonResp({ ok: true, key });
  }
  if (action === "link") {
    rec.discord = (body.discordId || "").trim() || null;
    await putKeyRecord(env, key, rec);
    return jsonResp({ ok: true, key, discord: rec.discord });
  }
  if (action === "resethwid") {
    // body.force (co-owner) skips the cooldown; buyers are limited to one
    // reset per 24h. When body.discordId is given, it must own the key.
    if (body.discordId && rec.discord !== body.discordId && !body.force) {
      return jsonResp({ ok: false, reason: "that key isn't linked to you" });
    }
    const wait = (rec.lastReset || 0) + HWID_RESET_COOLDOWN_MS - Date.now();
    if (!body.force && wait > 0) {
      return jsonResp({ ok: false, reason: "reset on cooldown", retryInMs: wait });
    }
    rec.hwid = null;
    rec.lastReset = Date.now();
    await putKeyRecord(env, key, rec);
    return jsonResp({ ok: true, key });
  }
  return jsonResp({ ok: false, reason: "unknown action" }, 404);
}

// Live gate: validates against KV, binds/checks the HWID, then decrypts
// with the Worker-held master key. Returns a Response (or the payload).
async function liveGate(env, key, hwidRaw) {
  const rec = await getKeyRecord(env, key);
  if (!rec) return { error: "invalid key", status: 403, rec: null };
  if (rec.status !== "active") return { error: "key is blacklisted", status: 403, rec };
  if (rec.expires && Date.now() > rec.expires) return { error: "key expired", status: 403, rec };
  if (!hwidRaw) return { error: "hwid required (update your loader)", status: 400, rec };
  const hw = await sha256Hex("jhub|" + hwidRaw);
  let dirty = false;
  if (!rec.hwid) {
    rec.hwid = hw;
    dirty = true;
  } else if (rec.hwid !== hw) {
    return { error: "hwid mismatch - reset it with /resethwid in Discord", status: 403, rec };
  }
  // Timed keys start their clock on first successful use.
  if (rec.durationMs && !rec.expires) {
    rec.expires = Date.now() + rec.durationMs;
    dirty = true;
  }
  if (dirty) await putKeyRecord(env, key, rec);
  return { rec };
}

// The decrypted script is the same for every valid key, and building it (download ~7.7MB, parse,
// base64-decode, un-XOR) is heavy. Doing that on every request, twice at once for two accounts,
// is what made the Worker hit its resource limit (Cloudflare error 1102). Build it once, keep it
// in memory for a short while, and share one build between simultaneous requests. Keys are still
// checked against KV on every request, so a revoked key stops working immediately.
const PAYLOAD_TTL_MS = 120000;
let payloadCache = null;
let payloadInflight = null;

async function buildLivePayload(env) {
  // Any failure here (GitHub hiccup, half-downloaded JSON, bad master key) must come back as an error
  // value, never as a thrown exception: a throw would take down every request that was waiting on this build.
  try {
    const resp = await fetch(SIDECAR_URL + "?_=" + Date.now(), { cf: { cacheTtl: 0 } });
    if (!resp.ok) return { error: "sidecar unavailable", status: 502 };
    const sidecar = await resp.json();
    const M = hexToBytes(env.MASTER_KEY);
    if (
      fnv1a32(M) !== sidecar.mhash ||
      fnv1a32(concatBytes(strToBytes("check2|"), M)) !== sidecar.mhash2
    ) {
      return { error: "server misconfigured (master key mismatch)", status: 500 };
    }
    return { bytes: reconstruct(M, sidecar) };
  } catch (e) {
    return { error: "sidecar unavailable", status: 502 };
  }
}

async function getLivePayload(env) {
  if (payloadCache && Date.now() - payloadCache.at < PAYLOAD_TTL_MS) return payloadCache.value;
  if (!payloadInflight) {
    payloadInflight = buildLivePayload(env)
      .then((value) => {
        if (value.bytes) payloadCache = { at: Date.now(), value };
        return value;
      })
      .finally(() => {
        payloadInflight = null;
      });
  }
  const value = await payloadInflight;
  if (!value.bytes && payloadCache) return payloadCache.value; // keep serving the last good build
  return value;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/freekey") {
      return handleFreeKey(request, env);
    }

    if (url.pathname === "/api/mykey") {
      return handleMyKey(request, env);
    }

    if (url.pathname === "/api/linkkey" || url.pathname === "/api/unlinkkey") {
      return handleLinkKey(request, env);
    }

    if (url.pathname.startsWith("/api/key/")) {
      return handleKeyApi(request, env);
    }

    const key =
      url.searchParams.get("key") ||
      request.headers.get("x-jhub-key") ||
      "";
    const robloxUser = url.searchParams.get("user") || "unknown";
    const jobId = url.searchParams.get("job") || "unknown";
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const hwidRaw = url.searchParams.get("hwid") || "";
    const live = !!(env.KEYS && env.MASTER_KEY);

    if (!key) {
      return new Response("missing key", { status: 400 });
    }

    let M;
    let liveRec = null;
    let sidecar = null;
    if (!live) {
      // Legacy mode (no live key store): the sidecar itself holds the per-key unlock data.
      const sidecarResp = await fetch(SIDECAR_URL + "?_=" + Date.now(), { cf: { cacheTtl: 0 } });
      if (!sidecarResp.ok) {
        return new Response("sidecar unavailable", { status: 502 });
      }
      sidecar = await sidecarResp.json();
    }
    if (live) {
      const g = await liveGate(env, normKey(key), hwidRaw);
      if (g.error) {
        // unknown keys are throttled per IP (an attacker can invent endless key strings); real keys per key + IP
        if (shouldLogNoisy((g.rec ? normKey(key) : "unknown") + "|" + ip + "|" + g.error)) ctx.waitUntil(
          logExecution(env, ctx, {
            status: g.status === 403 ? "INVALID/BLOCKED ATTEMPT: " + g.error : "ERROR: " + g.error,
            key, user: robloxUser, job: jobId, ip,
            ownerOverride: g.rec && g.rec.discord ? `<@${g.rec.discord}>` : null,
          })
        );
        return new Response(g.error, { status: g.status });
      }
      liveRec = g.rec;
      M = true;
    } else {
      M = attemptUnlock(key, sidecar);
    }
    if (!M) {
      ctx.waitUntil(
        logExecution(env, ctx, {
          status: "INVALID KEY ATTEMPT",
          key,
          user: robloxUser,
          job: jobId,
          ip,
        })
      );
      return new Response("invalid key", { status: 403 });
    }

    ctx.waitUntil(
      logExecution(env, ctx, {
        status: "valid execution",
        key,
        user: robloxUser,
        job: jobId,
        ip,
        ownerOverride: liveRec && liveRec.discord ? `<@${liveRec.discord}>` : null,
      })
    );

    let payload;
    if (live) {
      const built = await getLivePayload(env);
      if (!built.bytes) return new Response(built.error, { status: built.status });
      payload = built.bytes;
    } else {
      payload = reconstruct(M, sidecar);
    }
    return new Response(payload, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
