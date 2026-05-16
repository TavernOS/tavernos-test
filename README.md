# tavernos-test

Cloudflare Worker + static assets for the [tavernos.ai](https://tavernos.ai) public site. Handles the trial-application intake (`/api/apply`), the stay-in-the-loop signup (`/api/loop`), and serves the marketing pages (`/apply`, `/access`, `/alpha-guide`, `/alpha-self-test`, `/privacy`).

## Architecture

- **Worker code** in `src/worker.js` handles `POST /api/apply` and `POST /api/loop`. Falls through to static asset serving for all other paths.
- **Static assets** at repo root: `apply.html`, `access.html`, `alpha-guide.html`, `alpha-self-test.html`, `privacy.html`. Served by Cloudflare's Workers Static Assets binding.
- **KV namespace** `SUBMISSIONS` durably stores every `/api/apply` and `/api/loop` submission.
- **Resend** sends confirmation emails to applicants and notifications to `dan@tavernos.ai`.
- **`run_worker_first = true`** in `wrangler.toml` ensures the Worker wraps every response (including static asset responses) with security headers via `applyHeaders()`.

## Deploy

```bash
./node_modules/.bin/wrangler deploy
```

`wrangler` is in `devDependencies`; not on `PATH` post Mac migration. `npx wrangler deploy` also works.

For substantive changes (multi-file edits, security work, anything beyond a one-line tweak), use the `deploy_*.sh` scripts in `~/Downloads/` per the deploy disciplines in `~/TavernOS/tavernos-workspace/WORKING_AGREEMENTS.md`.

## Local development

```bash
./node_modules/.bin/wrangler dev
```

Serves the Worker locally with hot reload. Note: `dev` mode does NOT enforce CF dashboard rate limits or WAF rules — those are edge-only. Test rate-limit behavior against production with a cache-buster query string.

## Bindings and secrets

Declared in `wrangler.toml`:
- `SUBMISSIONS` — KV namespace, ID `76ff03294e3145838d0f3ee4b9701b54`
- `ASSETS` — static asset binding, serves the repo root
- `NOTIFY_EMAIL` — vars, `dan@tavernos.ai`
- `CALENDLY_URL` — vars, current scheduling link

Wrangler secrets (NOT in source, set via `wrangler secret put`):
- `RESEND_API_KEY` — Resend API key for outbound email

Inventory via `./node_modules/.bin/wrangler secret list`.

## Security configuration

### Version-controlled (in this repo)

- **Security response headers** — `applyHeaders()` in `src/worker.js` sets 8 headers on every response: HSTS (1-year, includeSubDomains), 10-directive CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP. CSP uses `'unsafe-inline'` on script-src and style-src as a closed-alpha compromise — 4 of 5 HTML pages have inline scripts (real form handlers). Future hardening: refactor pages to externalize inline scripts/styles and tighten CSP.
- **Input sanitization** — `stripCRLF()` at intake on the `name` field, blocking email-header injection via crafted newlines (SEC-3, commit `a77652c`).
- **PII-minimal error logging** — KV-write-failure logs include only `{ id, email }` or `{ email }`, never the full submission (SEC-6 fold, commit `a0ad257`).
- **Privacy policy** at `/privacy` — discloses data collected, named processors (Cloudflare, Resend, Anthropic), retention windows, legal basis, full data-subject rights, complaint authorities, security commitments (SEC-1, commit `b94384c`).

### NOT version-controlled — lives in Cloudflare dashboard

**`api-rate-limit` rate-limiting rule** (SEC-5). Location: CF dashboard → tavernos.ai zone → Security → Security rules → Rate limiting rules.

Parameters:
- Expression: `(http.request.method eq "POST" and starts_with(http.request.uri.path, "/api/"))`
- Characteristics: IP source address
- Threshold: 5 requests / 10 seconds (Free plan's only available period)
- Action: Block, 10-second duration

Verification: 12 rapid POSTs from a single IP should see ~6 return 200 and ~6 return 429. Cloudflare's per-edge-datacenter counter has a small fuzz so the exact cutover can wobble by 1-2 requests.

**Anthropic API key spend caps** (SEC-2). Location: console.anthropic.com → Settings → Limits.
- Trial-user-facing key: $500/month hard cap, 50% / 80% email alerts to `dan@tavernos.ai`
- Cohort 1 workspace key: same $500/month, same alert thresholds

### Why dashboard-only for SEC-2 and SEC-5

Closed-alpha decision: rate-limit thresholds and spend caps are operational tuning parameters more than security policy. They'll change as traffic patterns become real. Codifying them in version control adds review-cycle friction without much safety gain at this scale. If we graduate past closed alpha, revisit: SEC-5 rule could move to a Terraform/OpenTofu CF provider; SEC-2 caps stay in the dashboard but get documented as policy in the rotation runbook (SEC-8).

## Known limitations

Surfaced by the SEC-7 OWASP top-10 audit (s45-b); none rise to the level of an action item at closed-alpha scale.

- **No idempotency on `/api/apply`** — A user double-clicking submit will create two KV records and send two notification emails. Notification is to Dan, not user-facing dupes, so impact is low. Reconsider when cohort 2 reaches strangers (current scope is friends-and-family).
- **No SRI on Google Fonts CSS** — Google Fonts CSS URL returns different content based on User-Agent (woff2 / woff / ttf depending on browser), incompatible with subresource integrity hashes. Recognized limitation of Google Fonts; accepted by most production sites.
- **No active alerting on KV / Resend failures** — Failures log to CF Workers logs (`wrangler tail` to view), no email/push alerting. Adequate for current traffic; revisit at cohort 2 close.

## Repository layout

```
.
├── README.md              this file
├── wrangler.toml          Worker config + bindings + run_worker_first flag
├── package.json           wrangler devDependency only
├── src/
│   └── worker.js          handleApply, handleLoop, applyHeaders, helpers
├── apply.html             trial application form (form posts to /api/apply)
├── access.html            install walkthrough for trial users
├── alpha-guide.html       trial cohort orientation
├── alpha-self-test.html   pre-install diagnostic tool
└── privacy.html           privacy policy (SEC-1)
```

## Related repos in `~/TavernOS/`

- **`tavernos/`** — inner repo, the locally-installed app
- **`tavernos-workspace/`** — outer workspace, session notes + working agreements
- **`tavernos-skills/`** — distribution mirror of `tavernos/skills/`
- **`~/TavernOS/`** umbrella — `tavernos-meta` GitHub remote, container-level config

See `~/TavernOS/tavernos-workspace/WORKING_AGREEMENTS.md` §Repo-specific deploy paths for the full deploy mechanism map.
