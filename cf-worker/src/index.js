// JHub key gate -- runs on Cloudflare Workers.
//
// Replaces the old client-side-only scheme: instead of shipping a file that
// anyone with a key (or who finds any key at all) can decode offline and
// forever, the real decode happens here, server-side, on every request.
// A request without a valid key gets nothing back. The sidecar JSON this
// fetches is still fully encrypted ciphertext -- publishing it is no
// different from publishing the old .lua file; the actual gate is here.
//
// No bindings, no secrets, no build step needed -- deploys as-is.

const SIDECAR_URL =
  "https://raw.githubusercontent.com/dagimthepro/Practical-basketball/main/dist/jhub_sidecar.json";

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

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const key =
      url.searchParams.get("key") ||
      request.headers.get("x-jhub-key") ||
      "";

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
      return new Response("invalid key", { status: 403 });
    }

    const payload = reconstruct(M, sidecar);
    return new Response(payload, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
