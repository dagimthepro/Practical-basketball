# Execution logging to Discord -- deploy checklist

Every time the gate (`/?key=...`) is hit -- valid or invalid key -- it now
posts a message into a Discord channel as a real bot (via Discord's REST
API with a bot token, not a webhook), with: Roblox username, job ID, the
requester's IP, and -- if you've recorded it -- which buyer that key
belongs to. This needs no 24/7 hosting; it's a one-shot HTTP call the
Worker already makes as part of handling the request.

One limitation worth knowing: because this doesn't keep a live Gateway
connection open, the bot will show **offline** in your server's member
list. Messages still post genuinely as it (its name/avatar, not a webhook
tag) -- "online" presence and slash commands are a separate thing that
*would* need a persistent process somewhere, which isn't part of this.

## 1. Create the Discord bot application

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications) -> New Application -> name it (e.g. "JHub Logs").
2. Bot tab -> Reset Token / Copy Token. That's `DISCORD_BOT_TOKEN`. Treat it
   like a password -- anyone with it can post as your bot.
3. Still on the Bot tab, make sure "Message Content Intent" etc. aren't
   needed here (we only ever send messages, never read them), so defaults
   are fine.
4. OAuth2 -> URL Generator -> scope `bot` -> permissions `Send Messages` ->
   open the generated URL and invite it to your server.

## 2. Get the log channel's ID

In Discord, enable Developer Mode (User Settings -> Advanced), then
right-click the channel you want logs posted to -> Copy Channel ID. That's
`DISCORD_LOG_CHANNEL_ID`.

## 3. Set both as Worker secrets

Dashboard: `jhub-gate` Worker -> Settings -> Variables and Secrets -> add
`DISCORD_BOT_TOKEN` and `DISCORD_LOG_CHANNEL_ID`.

Or via CLI:
```
wrangler secret put DISCORD_BOT_TOKEN
wrangler secret put DISCORD_LOG_CHANNEL_ID
```

## 4. (Optional) Seed the key -> Discord buyer mapping

The `KEY_OWNERS` KV namespace already exists (`JHUB_KEY_OWNERS`,
id `45cf6f145c324f1cb0bc3c2c0c5c8cc0`) and is already bound in
`wrangler.toml`. To have logs show "Discord buyer: <name>", give me your
key -> buyer list (whatever form you already track it in -- a list of
`key: discord username` pairs is enough) and I'll turn it into a bulk-seed
JSON the same way I did for the free-key pool: **kept local and gitignored,
sent to you directly, never committed** -- this is buyer identity data, even
more sensitive than the free-key pool was, and this repo's dist/ is public.
Then:
```
wrangler kv bulk put cf-worker/key_owners_seed.json --namespace-id 45cf6f145c324f1cb0bc3c2c0c5c8cc0
```
This step is entirely optional -- without it, logs just won't have the
"Discord buyer" line, everything else still works.

## 5. Deploy

Same as always -- `wrangler deploy`, or paste `cf-worker/src/index.js` into
the dashboard editor (and make sure both KV bindings -- `FREE_POOL` and
`KEY_OWNERS` -- are attached under Settings -> Bindings, since pasting code
alone doesn't add bindings).

## Keeping buyer logs readable

If you end up with a lot of invalid-key attempts spamming the channel
(scanners, brute-force, old revoked keys), say so and I'll add a basic
rate limit (e.g. only log the first N invalid attempts per key per hour)
rather than logging every single one.
