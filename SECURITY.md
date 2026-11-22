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
| Host allowlist: on Render only `halte.co.za` / `www.halte.co.za`, else 403 | `ALLOWED_HOSTS` | `tests/test_security_pass.py` |
| Origin secret: 403 unless Cloudflare's `X-Halte-Origin` header matches | `ORIGIN_SECRET` | `tests/test_security_pass.py` |
| `/docs`, `/redoc`, `/openapi.json`, `/.env`, `/.git`, `render.yaml`, `Dockerfile`, `requirements.txt` all 404; `debug=False` | `fastapi_app/main.py` | `tests/test_security_pass.py` |
| Stop and search input cannot forge log lines | routes | `tests/test_log_forging.py` |
| Recent searches from `localStorage` are validated, length-limited and rendered with `textContent` | `static/js/search.js` | `tests/test_security_pass.py` |
| `/.well-known/security.txt` | `fastapi_app/main.py` | `tests/test_security_pass.py` |

Live checks against halte.co.za: `tools/check_live_security.sh`.

## Locking the origin (Render behind Cloudflare)

Render's edge is itself behind Cloudflare, so a request can reach the Render service
without passing through the halte.co.za Cloudflare zone, for example by sending
`Host: halte.co.za` straight to Render's edge. Restricting the Render service to
Cloudflare IP ranges is not reliable here, because Render sees the visitor's own IP
rather than a Cloudflare one. Two checks in the app close this off instead:

1. **Host allowlist** (`ALLOWED_HOSTS`, default on Render: `halte.co.za,www.halte.co.za`).
   Stops `*.onrender.com` serving the site. A Host header can be faked, so this alone is
   not enough.
2. **Origin secret** (`ORIGIN_SECRET`). Cloudflare adds a secret request header that
   direct visitors cannot know. Turn it on in this order, or the site goes down:
   1. Cloudflare → halte.co.za → Rules → Transform Rules → **Modify Request Header** →
      rule "Halte origin secret", *All incoming requests*, **Set static**
      `X-Halte-Origin` = a long random value (`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`).
   2. Render → service `myciti-bus-timetable` → Environment → `ORIGIN_SECRET` = the same
      value. Render redeploys.
   3. Check: `curl -s -o /dev/null -w "%{http_code}" --connect-to halte.co.za:443:myciti-bus-timetable.onrender.com:443 https://halte.co.za/`
      returns `403`, while `https://halte.co.za/` still returns `200`.

   To rotate: change the Cloudflare value and the Render variable together.
   `/health` skips both checks so Render's own health checks keep working.

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
  backoff. Behind Cloudflare, take the client IP from `CF-Connecting-IP` only once the
  origin secret is enforced; otherwise it can be faked.
- **Same generic error** for an unknown email and a wrong password ("Email or password is
  incorrect"), and the same response time for both. Password reset always says "If that
  address has an account, we've sent a link".
- **Secrets** only in Render environment variables: never in the repo, `render.yaml`
  values, logs or error pages. `.env` stays git-ignored and is for local use only.
- **CSP** stays as it is: no `'unsafe-inline'` for login pages either.
