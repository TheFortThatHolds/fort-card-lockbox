// Fort Card — the LAST-MILE worker.
//
// This is the thin, stateless half of a SPLIT deployment. Its one job is the last mile of a
// charge: take a SEALED secret, open it with the LOCAL master key, inject it into a single
// outbound request, and return only the response. It runs on the SECRET OWNER's own Cloudflare
// account and holds the owner's MASTER_KEY (the KEK).
//
// SELF-MINTING KEYS — nobody ever types or sees the root key. On first boot the worker MINTS
// its own MASTER_KEY and LAST_MILE_KEY (cryptographic randomness, not a human guess) and stores
// them in its own KV. A human never pastes a key into a deploy box, so a key never lands in a
// clipboard / shell history / screenshot. The KEK lives in THIS worker's KV; the ciphertext it
// opens lives in the CONTROL PLANE's KV — a different account — so the key and the data it
// protects are never co-located. (Advanced: set MASTER_KEY / LAST_MILE_KEY as Worker secrets and
// the worker uses those instead, never minting — for bring-your-own-key / migration.)
//
// WHY THE SPLIT EXISTS. In a single-worker deploy the same worker that stores the vault also
// decrypts and injects the key — so whoever operates it sees plaintext at injection time. Fine
// for SELF-HOST (you are the operator); NOT fine for a MANAGED service. Splitting the last mile
// out fixes that cryptographically:
//   • CONTROL PLANE (src/worker.js with LAST_MILE_URL set) holds ONLY ciphertext — sealed
//     secrets, KEK-wrapped DEKs, cards, the statement. No MASTER_KEY → it CANNOT decrypt.
//   • LAST-MILE WORKER (this file, on the OWNER's Cloudflare) holds MASTER_KEY. It opens the
//     ciphertext, injects the key, makes the call, returns the response — all on the owner's box.
//
// The envelope format is identical to the main worker (AES-256-GCM; per-space DEK wrapped under
// the KEK), so a secret sealed by either side opens on the other.
//
// One file, runs on Cloudflare Workers.
//
// HTTP API:
//   GET    /                                                 identity / health
//   GET    /bootstrap                                        FIRST-CALL-WINS: returns the connect
//                                                            credentials (url + LAST_MILE_KEY) once,
//                                                            then seals. How you link this worker
//                                                            to the control plane right after deploy.
//   GET    /recovery        (Bearer LAST_MILE_KEY)           reveal the MASTER_KEY for offline backup
//   POST   /seal     {plaintext, dek?}                       seal a value → {iv, ct}
//   POST   /charge   {secret, dek?, request, header, ...}    decrypt + inject + fetch → response
//   POST   /rotate   {secrets[], dek?}                       mint a fresh DEK, re-seal every secret
//   (all but / and /bootstrap require  Authorization: Bearer <LAST_MILE_KEY>)
//
// Bindings (see wrangler.toml):
//   KV namespace `LM`         the worker's own key store (holds ONLY its minted keys — never ciphertext)
//   secret `MASTER_KEY`       (optional) bring-your-own KEK; if unset the worker mints + stores one
//   secret `LAST_MILE_KEY`    (optional) bring-your-own bearer; if unset the worker mints + stores one

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (o, status = 200, extra = {}) =>
  new Response(JSON.stringify(o, null, 2), { status, headers: { "Content-Type": "application/json", ...extra } });
// CORS so the tenant's own browser can seal a value here directly. Auth is the seal ticket (a
// header), not a cookie, so Allow-Origin:* is safe — the ticket is the capability, not the origin.
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Seal-Ticket", "Access-Control-Max-Age": "86400" };
// Constant-time string compare for the bearer, so a token can't be recovered byte-by-byte via
// response-timing. Length is allowed to leak (the token length is fixed), the contents are not.
const safeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

// ── seal-ticket verify (mirror of worker/src/ticket.js — kept inline so this folder stays
// self-contained for the one-tap deploy). A short-TTL HMAC over the relay key authorizes exactly
// ONE browser-direct seal, so the control plane never has to touch the plaintext. ──
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function hmacB64(relayKey, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(relayKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
async function verifySealTicket(relayKey, ticket, now = Date.now()) {
  if (typeof ticket !== "string") return false;
  const parts = ticket.split(".");
  if (parts.length !== 3) return false;
  const [nonce, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp * 1000 < now) return false;
  return safeEqual(sig, await hmacB64(relayKey, nonce + ":" + exp));
}

// ── self-minting key resolution: a Worker secret wins (bring-your-own); else read the minted key
// from KV; else MINT one (32 random bytes), store it, and use it. Idempotent — first boot mints,
// every boot after reads. The customer never sees or supplies anything. ──
async function mintedSecret(env, name, bytes = 32) {
  if (env[name]) return env[name]; // bring-your-own beats minting
  if (!env.LM) throw new Error("no KV binding `LM` and no " + name + " secret — cannot mint or load the key");
  const existing = await env.LM.get("key:" + name);
  if (existing) return existing;
  const value = b64e(crypto.getRandomValues(new Uint8Array(bytes)).buffer);
  await env.LM.put("key:" + name, value);
  return value;
}
const masterKeyB64 = (env) => mintedSecret(env, "MASTER_KEY", 32);
const lastMileToken = (env) => mintedSecret(env, "LAST_MILE_KEY", 32);

// ── envelope crypto — same shape as the control plane ──
async function kek(env) {
  return crypto.subtle.importKey("raw", b64d(await masterKeyB64(env)), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function importRaw(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
// Unwrap a KEK-wrapped DEK ({iv, ct}) → an AES-GCM key. No DEK means the secret was sealed under
// the KEK directly (pre-rotation), so we hand back the KEK itself.
async function openKey(env, dek) {
  if (!dek) return kek(env);
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(dek.iv) }, await kek(env), b64d(dek.ct));
  return importRaw(new Uint8Array(raw));
}
async function sealWith(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  return { iv: b64e(iv.buffer), ct: b64e(ct) };
}
async function openWith(key, sealed) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(sealed.iv) }, key, b64d(sealed.ct));
  return dec.decode(pt);
}

// ── SSRF guard: this worker makes the outbound call, so it's the right place to refuse private,
// loopback, link-local, and cloud-metadata targets. Host allow-listing happens on the control
// plane (the card's allowed_hosts); this is the second, network-layer fence. ──
function ssrfBlocked(host) {
  let h = host.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  const mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/); // IPv4-mapped IPv6 → test the embedded v4
  if (mapped) h = mapped[1];
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (h === "::1" || h === "::" || h === "0.0.0.0" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true;
  if (/^\d+$/.test(h)) return true;             // integer-encoded IP (2130706433 = 127.0.0.1)
  if (/^0x[0-9a-f]+$/.test(h)) return true;     // hex-encoded IP (0x7f000001)
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.some((n) => n > 255)) return true;     // malformed octet → refuse rather than guess
    const [a, b] = o;
    if (a === 127 || a === 10 || a === 0) return true;             // loopback / private / this-host
    if (a === 169 && b === 254) return true;                       // link-local + cloud metadata (169.254.169.254)
    if (a === 192 && b === 168) return true;                       // private
    if (a === 172 && b >= 16 && b <= 31) return true;              // private
    if (a === 100 && b >= 64 && b <= 127) return true;             // carrier-grade NAT
  }
  if (/^[0-9.]+$/.test(h) && /(^|\.)0\d/.test(h)) return true;     // octal-smuggled octet (0177.0.0.1)
  return false;
}

// ── phone-home onboarding — if deployed with a CLAIM_CODE + CONTROL_PLANE_URL, the lockbox tells
// the control plane its own URL + relay token ONCE, gated by that one-time code. The control plane
// lands it PENDING for the owner to approve (their tap is the gate). This removes the URL
// copy-paste: the customer typed a short code on the deploy screen instead of copying this worker's
// URL back. Best-effort + idempotent — a KV flag (phonehome:done) ensures it fires at most once,
// and it never blocks a real request. The paste-URL /bootstrap flow stays as the fallback. ──
async function maybePhoneHome(env, selfOrigin) {
  if (!env.CLAIM_CODE || !env.CONTROL_PLANE_URL || !env.LM) return;
  if (await env.LM.get("phonehome:done")) return;
  let cp;
  try { cp = new URL(env.CONTROL_PLANE_URL); } catch { return; }
  if (cp.protocol !== "https:") return;
  const token = await lastMileToken(env); // our minted relay key — the value /bootstrap also hands out
  await masterKeyB64(env);                 // ensure the KEK is minted too
  try {
    const r = await fetch(cp.origin + "/lockbox/phone-home", {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "fort-card-lockbox" },
      body: JSON.stringify({ claim_code: env.CLAIM_CODE, url: selfOrigin, relay_token: token }),
    });
    // ok → landed pending; 403 → bad/expired/already-used code (retrying won't help). Either way, stop.
    if (r.ok || r.status === 403) await env.LM.put("phonehome:done", new Date().toISOString());
  } catch {
    // network blip — leave the flag unset so the next request retries.
  }
}

export default {
  async fetch(request, env, ctx) {
    // Either a KV binding to mint into, or both keys supplied as secrets. Otherwise we can't run.
    if (!env.LM && (!env.MASTER_KEY || !env.LAST_MILE_KEY)) {
      return json({ error: "server not configured — bind a KV namespace `LM` (keys self-mint) or set MASTER_KEY + LAST_MILE_KEY secrets" }, 500);
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // First-request onboarding: phone home once (fire-and-forget so it never blocks the response).
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(maybePhoneHome(env, url.origin));
    else await maybePhoneHome(env, url.origin);

    if (path === "/") {
      return json({ name: "fort-card-last-mile", ok: true, role: "decrypt+inject on the owner's own infra" });
    }

    // ── /bootstrap — FIRST-CALL-WINS connect credentials. Right after deploy, the owner fetches
    // this ONCE to get the worker URL + LAST_MILE_KEY to paste into the control plane. It then
    // seals permanently (a KV flag), so the credential can't be re-read off a public URL later.
    // Whoever claims first owns the link — deploy and claim immediately. (The GitHub-App handshake
    // will later broker this server-to-server and remove the manual claim + the race entirely.) ──
    if (path === "/bootstrap" && request.method === "GET") {
      if (env.MASTER_KEY && env.LAST_MILE_KEY) return json({ error: "bring-your-own keys set; no bootstrap needed" }, 400);
      if (!env.LM) return json({ error: "no KV binding" }, 500);
      if (await env.LM.get("bootstrap:sealed")) return json({ error: "bootstrap already claimed (one-time)" }, 410);
      const token = await lastMileToken(env);
      await masterKeyB64(env); // ensure the KEK is minted now too
      await env.LM.put("bootstrap:sealed", new Date().toISOString());
      return json({
        last_mile_url: url.origin,
        last_mile_key: token,
        note: "Paste these into the control plane as LAST_MILE_URL + LAST_MILE_KEY, then remove the control plane's MASTER_KEY. This is the only time these are shown.",
      });
    }

    // CORS preflight for the browser-direct seal.
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    // Auth: the control plane presents the shared bearer on every call. The tenant's BROWSER may
    // instead present a short-TTL seal ticket (X-Seal-Ticket) — but ONLY to /seal. /charge,
    // /rotate, and /recovery always require the bearer.
    const token = await lastMileToken(env);
    const bearerOk = safeEqual(request.headers.get("Authorization") || "", "Bearer " + token);
    const sealByTicket = path === "/seal" && request.method === "POST" &&
      (await verifySealTicket(token, request.headers.get("X-Seal-Ticket") || ""));
    if (!bearerOk && !sealByTicket) {
      return json({ error: "unauthorized" }, 401, CORS);
    }

    // ── /recovery — reveal the MASTER_KEY for offline disaster-recovery backup. Gated by the
    // bearer (only the linked owner holds it). Optional: a normal user never needs this; a careful
    // one stashes it so a wiped KV doesn't strand their sealed secrets. ──
    if (path === "/recovery" && request.method === "GET") {
      return json({
        master_key: await masterKeyB64(env),
        warning: "This is your root key. If your worker's KV is ever wiped, this restores it. Store it offline (NOT in a screenshot). Anyone with this key can decrypt your secrets.",
      });
    }

    const body = request.method === "GET" ? {} : await request.json().catch(() => ({}));

    // ── seal a plaintext value under the owner's active DEK (or the KEK if none) → ciphertext the
    // control plane stores. Plaintext is sealed HERE, on the owner's infra. ──
    if (path === "/seal" && request.method === "POST") {
      if (typeof body.plaintext !== "string") return json({ error: "plaintext (string) required" }, 400, CORS);
      const sealed = await sealWith(await openKey(env, body.dek || null), body.plaintext);
      return json({ sealed }, 200, CORS);
    }

    // ── the charge: open the sealed secret, inject it into ONE outbound request, return only the
    // response. The credential header is injected LAST so a caller-supplied header can't override
    // or strip it. The plaintext key never leaves this worker. ──
    if (path === "/charge" && request.method === "POST") {
      const req = body.request || {};
      if (!body.secret || !req.url) return json({ error: "secret and request.url required" }, 400);
      let host;
      try { host = new URL(req.url).host; } catch { return json({ error: "bad request.url" }, 400); }
      if (ssrfBlocked(host)) return json({ error: `host ${host} blocked (SSRF)` }, 403);

      const key = await openWith(await openKey(env, body.dek || null), body.secret);
      const header = body.header || "Authorization";
      const prefix = body.header_prefix ?? "Bearer ";
      const resp = await fetch(req.url, {
        method: req.method || "GET",
        headers: { ...(req.headers || {}), [header]: prefix + key }, // credential injected LAST
        body: req.body == null ? undefined : typeof req.body === "string" ? req.body : JSON.stringify(req.body),
      });
      const text = await resp.text();
      let out;
      try { out = JSON.parse(text); } catch { out = text; }
      return json({ status: resp.status, body: out });
    }

    // ── rotate: mint a fresh DEK (wrapped under the KEK), re-seal every secret the control plane
    // hands over, and return the new wrapped DEK + re-sealed secrets for the control plane to
    // persist. Plaintext exists only inside this worker for the duration of the re-seal. ──
    if (path === "/rotate" && request.method === "POST") {
      const secrets = Array.isArray(body.secrets) ? body.secrets : [];
      const oldKey = await openKey(env, body.dek || null);
      const rawDek = crypto.getRandomValues(new Uint8Array(32));
      const newKey = await importRaw(rawDek);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await kek(env), rawDek);
      const ref = "dek_" + crypto.randomUUID().slice(0, 8);
      const out = [];
      for (const s of secrets) {
        if (!s || !s.name || !s.sealed) continue;
        const plain = await openWith(oldKey, s.sealed);
        const sealed = await sealWith(newKey, plain);
        sealed.keyRef = ref;
        out.push({ name: s.name, sealed });
      }
      return json({ ref, dek: { ref, iv: b64e(iv.buffer), ct: b64e(wrapped) }, secrets: out });
    }

    return json({ error: "not found" }, 404);
  },
};
