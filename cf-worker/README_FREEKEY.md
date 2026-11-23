# Free-tier ad-gated keys -- deploy checklist

This adds a `/freekey` route to the existing `jhub-gate` Worker. A visitor who
completes your Linkvertise ad flow lands here, gets checked server-to-server
against Linkvertise's own anti-bypass API, and -- only if that check passes --
gets handed one real JHub key from a pre-seeded pool.

I (Claude) can't do the steps below myself: the Cloudflare tool I have can
read Workers and manage KV namespace *metadata*, but it can't deploy Worker
code, set secrets, or write KV values. Everything is written and ready --
these are the only manual steps left.

## 1. Get your Linkvertise anti-bypass token

In the Linkvertise publisher dashboard, under the Full Script API settings
where you found the "Use anti-bypassing" checkbox, there should be a 64-char
token shown once you enable it (or elsewhere in account/profile settings --
Linkvertise's own PDF doesn't say exactly where, just that it's "generated
for you"). Copy it.

## 2. Set the Worker secret

Via the Cloudflare dashboard: open the `jhub-gate` Worker -> Settings ->
Variables and Secrets -> add secret `LINKVERTISE_TOKEN` with that value.

Or via CLI, if you have `wrangler` installed locally:
```
wrangler secret put LINKVERTISE_TOKEN
```
(it'll prompt you to paste the value)

## 3. Deploy the updated Worker code

The KV binding is already in `wrangler.toml` (namespace `JHUB_FREE_POOL`,
id `b5666fabc63b45a6845816e1cea56598` -- already created). Deploy however you
normally do:
```
wrangler deploy
```
or paste `cf-worker/src/index.js`'s contents into the dashboard's online editor
for the `jhub-gate` Worker and save -- just make sure the KV binding
(`FREE_POOL` -> `JHUB_FREE_POOL`) is attached in Settings -> Bindings either
way, since pasting code alone doesn't add a binding.

## 4. Seed the free-key pool (one time)

`cf-worker/free_pool_seed.json` has 50 free keys (`jhub-free-xxxx-xxxx`
format, already wrapped into the sidecar the same way buyer keys are, so the
existing unlock code needs zero changes). **This file is gitignored and was
never pushed to the repo on purpose** -- it's 50 plaintext keys, and this
repo's `dist/` is served raw and public, so committing it would let anyone
read the whole free pool straight off GitHub and skip Linkvertise entirely.
It was sent to you directly instead; keep it local, don't commit it, and
delete it once you've loaded it into KV. Load it with:
```
wrangler kv bulk put cf-worker/free_pool_seed.json --namespace-id b5666fabc63b45a6845816e1cea56598
```

## 5. Point Linkvertise at the new route

In your Linkvertise Target-Link settings:
- Target URL: `https://practical-basketball.dagimwww.workers.dev/freekey`
- Enable "Use anti-bypassing"

## Topping up the pool later

When the pool runs low, generate more keys the same way
`bundle/build.py`/`protect.py` already do (see `bundle/free_keys.txt` for the
last batch), add them to `bundle/keys.txt`, rebuild + re-protect + push like
any other key rotation, then bulk-put the new batch into `FREE_POOL` the same
way as step 4. There's no auto-refill -- this is a manual top-up for now.

## Checking usage

`wrangler kv key list --namespace-id b5666fabc63b45a6845816e1cea56598` shows
every key's `status` metadata (`available` vs `issued`, with `at`/`hash` for
issued ones) -- that's your free-tier completions count, and a way to spot
how fast the pool is draining.
