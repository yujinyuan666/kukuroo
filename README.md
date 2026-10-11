# Kukuroo

Your own Web Push service, on a Cloudflare Worker.

There is no server to keep alive, no notification vendor in the path, and no app to install:
you hold the keys, and the push service relays ciphertext it cannot read.

Kukuroo uses **Declarative Web Push**, which so far has only shipped in Safari, so receiving
needs an iPhone or iPad on iOS 18.4+, or macOS Safari 18.5+. Chrome, Firefox, and Android
cannot enroll. Sending works from anything that can make a request: curl, cron, CI, or a
backend you already run.

## Install

```sh
npx kukuroo init my-push
```

It asks a few questions, writes a Worker into `my-push`, generates and uploads every secret,
and deploys. One answer is irreversible: where devices enroll, a `workers.dev` address or a
domain you have on Cloudflare, fixed once a device has enrolled. Back up
`my-push/kukuroo.credentials.json`, the only copy of your keys.

On the device: open that origin in Safari, **Add to Home Screen**, and open it **from the
icon** to allow notifications. A Safari tab does not work on iOS; [the enrollment
guide](docs/create-pwa-and-subscribe-to-push.md) has the rest. From then on, a notification
is one request:

```sh
curl -X POST https://push.example.com/push/send \
  -H "authorization: Bearer $KUKUROO_SEND_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"notification":{"title":"hello","navigate":"https://push.example.com/"}}'
```

That is Kukuroo standalone: its own Worker at its own address, serving the enrollment page
it ships with. Your own site needs nothing but the send token and that POST. Answering
**no** to the bundled front end keeps the same shape but routes no enrollment page, so you
serve your own UI and add its origin to `KUKUROO_ALLOWED_ORIGINS`.

Every question also has a flag, including `--no-deploy` and `--resume` for setting things up
before touching your Cloudflare account, and `rotate` for the send token and the invite code:
[`npx kukuroo init --help`](scripts/init.mjs). `rotate` handles the invite code; a send token is
added and retired with `wrangler secret`, [below](#more-than-one-token).

### Mounting it in a Worker you already run

Mounted instead of standalone: the push routes live inside a Worker you already have, so
they share your site's origin and a notification click lands back inside your site.

```ts
import { mountKukuroo, type KukurooEnv } from "kukuroo";

const kukuroo = mountKukuroo({ prefix: "/push", standalone: false, requireInvite: true });

export default {
  async fetch(request: Request, env: KukurooEnv): Promise<Response> {
    const hit = await kukuroo.handle(request, env);
    if (hit !== null) return hit;
    return yourExistingRouter(request, env);
  },
};
```

`handle` returns `null` for every path outside `prefix`, so your own routing is untouched.
Add the KV binding, `"kv_namespaces": [{ "binding": "KUKUROO_SUBS" }]`, whose name is not
configurable; set `KUKUROO_NAVIGATE_ORIGIN`; then run `npx kukuroo init --secrets` from the
directory holding that `wrangler.jsonc`. Serve the bundled page from any route of yours with
the exported `enrollmentPage()`, or build your own UI against `POST /push/subscribe`.

From inside that Worker, `send(env, options)` sends a notification with no token, since it
already holds the bindings. [`KukurooEnv`](src/env.ts), [`MountOptions`](src/mount.ts), and
[`SendOptions` and `SendResult`](src/send.ts) are documented where they are declared;
`requireInvite: false` is the one to read before setting, since it opens enrollment to
anyone who reaches the URL. `buildDeclarativePayload` and `importVapidKeys` are exported too.

Kukuroo ships TypeScript source rather than a build, so your `tsconfig.json` needs
`"allowImportingTsExtensions": true` or `tsc` reports errors from inside
`node_modules/kukuroo`. The scaffolded project sets this already.

Enrollment can also reach your own hostname through a Worker route or a real proxy that
rewrites `Host`; a bare DNS CNAME will not do. All that matters is which origin devices
enroll on.

## Agent Skill

Your coding agent can send these, which is most of the point of having a phone in the
loop. For Claude Code that is a plugin, and this repository is its own marketplace:

```sh
claude plugin marketplace add saiday/kukuroo
claude plugin install kukuroo@kukuroo
```

Set the environment up once per machine:

```sh
/kukuroo:kukuroo-setup
```

From then on "ping me on my phone when the tests finish" works in any project.

[The agents guide](docs/agents.md) covers the rest: what makes it fire, what it is told
about the payload, and why a scheduled push needs the session to stay open.

## API

```
POST /push/send        bearer token   RFC 8291 aes128gcm + VAPID ES256, fans out
POST /push/subscribe   invite-gated   stores the subscription in KV
GET  /push/public-key  open           the VAPID public key, for the client
GET  /push/enroll      open           the bundled enrollment page (standalone only)
```

`/push/send` takes the notification:

```sh
curl -X POST https://push.example.com/push/send \
  -H "authorization: Bearer $KUKUROO_SEND_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"notification":{"title":"Deploy finished","body":"api v2.3.1 is live","tag":"deploys","navigate":"https://push.example.com/deploys"}}'
```

`title` and `navigate` are required, and `icon`, if present, must be absolute.

### More than one token

A deployment may hold any number of send tokens, one per sender — a laptop, a CI job, a cron
box — so retiring one does not mean reissuing all of them. A token is one Worker Secret, and
the sender says which:

```sh
# A value only base64url of random bytes produces: no dot, no whitespace.
node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))'
# Paste it when prompted. This deploys immediately; no `wrangler deploy` needed.
printf '%s' '<value>' | npx wrangler secret put KUKUROO_SEND_TOKEN_CI

# Then that sender holds the single string `KUKUROO_SEND_TOKEN_CI.<value>`:
curl -X POST https://push.example.com/push/send \
  -H "authorization: Bearer KUKUROO_SEND_TOKEN_CI.<value>" \
  -d '{"notification":{"title":"Deploy finished","navigate":"https://push.example.com/"}}'
```

The credential is `Bearer <name>.<secret>`, and the name is the Worker Secret's name,
verbatim: `KUKUROO_SEND_TOKEN_CI` reads the secret `KUKUROO_SEND_TOKEN_CI`. There is no case
folding or hyphen mapping — the caller writes the secret's name exactly as `wrangler secret put`
saw it. Only the first dot splits, so a secret may contain one.

- **Every token reaches every device.** Naming separates credentials, not subscriptions.
- **An unknown name is a 401, not a 503.** Naming the missing secret would report which names
  exist to whoever asked. A 401 on a send means either half of the credential is wrong.
- **Retiring one** is `npx wrangler secret delete KUKUROO_SEND_TOKEN_CI`. It asks for
  confirmation first; there is no `--yes`. Every sender still presenting it gets a 401.
- **What you hold is one string.** A sender stores `KUKUROO_SEND_TOKEN_CI.<value>` in one
  variable and sends it as one header; nothing about the config has to change to add a sender.

Counts and sizes are Cloudflare's: each name is one more variable on the Worker (64 per Worker
on the free plan, 128 on paid) and values are capped at 5 KB. A name must start with the literal
prefix `KUKUROO_SEND_TOKEN_`, so it can only ever address a send-token binding. `wrangler secret
put` and `secret delete` both create and deploy a new version immediately, so an added token is
live at once and needs no redeploy.

## Alternatives

| | Server to run | Vendor in the path | How it reaches iOS |
|---|---|---|---|
| **Kukuroo** | none | none | [Declarative Web Push](https://webkit.org/blog/16535/meet-declarative-web-push/), a page on your Home Screen |
| [ntfy](https://ntfy.sh) | host, domain, TLS, a process | none, self-hosted | Web Push, installable PWA |
| [Bark](https://github.com/Finb/Bark) | yes, though it can be a Worker | none | App Store app via APNs |
| [Gotify](https://gotify.net) | yes | none | its own app |
| [Pushover](https://pushover.net) | none | yes, paid hosted | its own app |

If you are happy hosting and want a full app-like UI, use ntfy. It is mature, polished, and
does considerably more than this.

## Licence

MIT. See [LICENSE](LICENSE).
