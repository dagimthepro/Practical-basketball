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
  let owner = null;
  if (env.KEY_OWNERS) {
    try {
      owner = await env.KEY_OWNERS.get(normKey(fields.key));
    } catch (e) {
      /* ignore lookup failures, still log the rest */
    }
  }
  const lines = [
    `**${fields.status}**`,
    `Key: \`${fields.key}\``,
    owner ? `Discord buyer: ${owner}` : null,
    `Roblox user: ${fields.user}`,
    `Job ID: \`${fields.job}\``,
    `IP: ${fields.ip}`,
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
      body: JSON.stringify({ content: lines.join("\n") }),
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
  if (!env.INTERNAL_SECRET || request.headers.get("x-internal-secret") !== env.INTERNAL_SECRET) {
    return new Response("unauthorized", { status: 401 });
  }
  if (!env.KEY_OWNERS) {
    return new Response(JSON.stringify({ found: false, reason: "KEY_OWNERS not configured" }), {
      headers: { "content-type": "application/json" },
    });
  }
  const url = new URL(request.url);
  const discordId = url.searchParams.get("discord") || "";
  if (!discordId) {
    return new Response(JSON.stringify({ found: false, reason: "missing discord id" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }
  const key = await findKeyByDiscordId(env.KEY_OWNERS, discordId);
  return new Response(JSON.stringify({ found: !!key, key: key || undefined }), {
    headers: { "content-type": "application/json" },
  });
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

    const key =
      url.searchParams.get("key") ||
      request.headers.get("x-jhub-key") ||
      "";
    const robloxUser = url.searchParams.get("user") || "unknown";
    const jobId = url.searchParams.get("job") || "unknown";
    const ip = request.headers.get("cf-connecting-ip") || "unknown";

    if (!key) {
      return new Response("missing key", { status: 400 });
    }

    // GitHub's raw.githubusercontent.com CDN caches by URL for several
    // minutes regardless of our own cache directives, which would delay a
    // revocation taking effect. A cache-busting query param defeats both
    // that CDN's cache and Cloudflare's own edge cache, so a key removed
    // from keys.txt stops working on the very next request, not minutes
    // later.
    const bustedUrl = SIDECAR_URL + "?_=" + Date.now();
    const sidecarResp = await fetch(bustedUrl, { cf: { cacheTtl: 0 } });
    if (!sidecarResp.ok) {
      return new Response("sidecar unavailable", { status: 502 });
    }
    const sidecar = await sidecarResp.json();

    const M = attemptUnlock(key, sidecar);
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
      })
    );

    const payload = reconstruct(M, sidecar);
    return new Response(payload, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
