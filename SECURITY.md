# Security

## Reporting a problem

Email the address in [`/.well-known/security.txt`](https://halte.co.za/.well-known/security.txt)
(set by the `SECURITY_CONTACT` environment variable). Please don't open a public issue
for a vulnerability.

## What is in place

| Control | Where | Checked by |
|---|---|---|
| Content-Security-Policy: `default-src 'self'`, no `'unsafe-inline'` / `'unsafe-eval'`, map's one inline script and style allowed by hash, images only from this origin and OpenStreetMap tiles, `frame-ancestors 'self'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'` | `fastapi_app/security.py` | `tests/test_security_headers.py`, `tests/test_security_pass.py` |
| No `style=""` attributes in templates (route colours go through `data-route-color` + `static/js/route-colors.js`) | templates | `tests/test_security_pass.py` |
| X-Frame-Options `SAMEORIGIN`, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP | `fastapi_app/security.py` | `tests/test_security_headers.py` |
| HSTS `max-age=31536000; includeSubDomains; preload` (HTTPS only) | `fastapi_app/security.py` | `tests/test_security_pass.py` |
| Host allowlist: on Render only `halte.co.za` / `www.halte.co.za`, else 403 (shuts the `*.onrender.com` address) | `ALLOWED_HOSTS` | `tests/test_security_pass.py` |
| uvicorn `Server` banner off | `UVICORN_SERVER_HEADER=false` on Render | `tools/check_live_security.sh` |
| `/docs`, `/redoc`, `/openapi.json`, `/.env`, `/.git`, `render.yaml`, `Dockerfile`, `requirements.txt` all 404; `debug=False` | `fastapi_app/main.py` | `tests/test_security_pass.py` |
| Stop and search input cannot forge log lines | routes | `tests/test_log_forging.py` |
| Recent searches from `localStorage` are validated, length-limited and rendered with `textContent` | `static/js/search.js` | `tests/test_security_pass.py` |
| `/.well-known/security.txt` | `fastapi_app/main.py` | `tests/test_security_pass.py` |

Live checks against halte.co.za: `tools/check_live_security.sh`.

## Hosting

halte.co.za's DNS is at GoDaddy and points straight at Render. Render's edge (which runs
on Cloudflare) terminates TLS, redirects `www` and adds `x-render-origin-server` and
`rndr-id` to every response; those only say the site is on Render and can't be removed
without a CDN of our own in front.

Render also serves every service on a default `*.onrender.com` address. The Host
allowlist (`ALLOWED_HOSTS`, default on Render: `halte.co.za,www.halte.co.za`) answers
that address with 403. `/health` is exempt so Render's health checks keep working.

If a CDN of our own is ever put in front (for example moving the nameservers to
Cloudflare), add an origin check too: a secret request header set by the CDN and verified
by the app, so the Render address can't be used to skip the CDN's rules.

## Before shipping login or signup

Halte has no accounts and no POST routes today. `tests/test_security_pass.py` fails as
soon as a route other than GET/HEAD is added, pointing back here. Before removing that
guard, every item below must be done and tested:

- **Passwords** hashed with argon2id (preferred; `argon2-cffi`) or bcrypt. Never stored,
  logged or emailed in plain text.
- **Session cookies** with `Secure`, `HttpOnly` and `SameSite=Lax`; random session IDs;
  rotate the ID on login; real logout that invalidates the session server-side.
- **CSRF tokens** on every POST form (the CSP's `form-action 'self'` is not a substitute).
- **Rate limits** on login, signup and password reset, per IP and per account, with
  backoff. Take the client IP from what Render's proxy appends to `X-Forwarded-For`
  (the last entry), never the first entry, which the browser can set to anything.
- **Same generic error** for an unknown email and a wrong password ("Email or password is
  incorrect"), and the same response time for both. Password reset always says "If that
  address has an account, we've sent a link".
- **Secrets** only in Render environment variables: never in the repo, `render.yaml`
  values, logs or error pages. `.env` stays git-ignored and is for local use only.
- **CSP** stays as it is: no `'unsafe-inline'` for login pages either.
