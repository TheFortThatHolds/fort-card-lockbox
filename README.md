# 🔒 Fort Card — Lockbox

### The little vault that runs on **your** Cloudflare, so your API keys stay yours.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/TheFortThatHolds/fort-card-lockbox)

This is the **last-mile worker** for [Fort Card](https://thefortthatholds.com/fort-card). You run it
on your own Cloudflare account. Fort Card runs the **brain** — the wallet, approvals, audit, the UI —
and holds only ciphertext. This worker is where your key actually seals and where it's injected into a
call. The plaintext key lives only here, on your infrastructure, for the moment of one request.

> **Hosted Fort Card** = we run everything but this. **Self-host** = you run the brain too (that's the
> main [`fort-card`](https://github.com/TheFortThatHolds/fort-card) repo). This repo is just the lockbox.

## Deploy it

Tap **Deploy to Cloudflare** above. It installs this worker onto your account and provisions its KV
namespace automatically. The worker **mints its own keys on first boot** — you type nothing, and there
is no secret to set. Then, in the Fort Card wallet, paste the worker's URL and approve; the wallet
claims the connection link for you.

By hand instead of the button:

```
npm i -g wrangler
npx wrangler kv namespace create LM      # paste the id into wrangler.toml
npx wrangler deploy
```

## What it does

- `GET  /bootstrap` — one-time, first-call-wins: returns the worker URL + relay token to connect it to the wallet. Seals itself after the first read.
- `POST /seal` — seal a value under your key → ciphertext (authorized by the bearer, or a short-TTL seal ticket so your browser can seal directly).
- `POST /charge` — open a sealed secret, inject it into ONE outbound call, return only the response. The credential header is injected last; private/loopback/metadata targets are refused (SSRF fence).
- `POST /rotate` — mint a fresh data key and re-seal every secret.
- `GET  /recovery` — reveal the root key for an offline backup (bearer-gated).

## No secrets live in this repo

There are no keys, tokens, or credentials in this code. The worker generates its own root key on first
boot and stores it in **your** Cloudflare KV. That's why this repo can be fully public and forkable —
read every line, run your own.

MIT licensed. Built by [The Fort That Holds](https://thefortthatholds.com).
