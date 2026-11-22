#!/usr/bin/env bash
# Live security checks for halte.co.za (or another base URL).
#   tools/check_live_security.sh [https://halte.co.za]
# Read-only GET requests. Exits non-zero if any check fails.
set -u
BASE="${1:-https://halte.co.za}"
HOST="${BASE#https://}"; HOST="${HOST%%/*}"
ORIGIN="${ORIGIN:-myciti-bus-timetable.onrender.com}"
fails=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$@"; }

H=$(curl -sS -o /dev/null -D - --max-time 30 "$BASE/" | tr -d '\r')
hdr() { printf '%s\n' "$H" | grep -i "^$1:" | head -1 | cut -d' ' -f2-; }
CSP=$(hdr content-security-policy)

echo "1. Origin lock"
check "default onrender.com address refused (403)" '[ "$(code "https://$ORIGIN/")" = 403 ]'
check "Host spoofed straight to Render's edge refused (needs ORIGIN_SECRET + Cloudflare rule)" \
  '[ "$(code --connect-to "$HOST:443:$ORIGIN:443" "$BASE/")" = 403 ]'
check "site itself still 200" '[ "$(code "$BASE/")" = 200 ]'

echo "2. Hosting headers stripped (Cloudflare Transform Rule)"
check "no x-render-origin-server" '[ -z "$(hdr x-render-origin-server)" ]'
check "no rndr-id" '[ -z "$(hdr rndr-id)" ]'
check "server is only cloudflare (no uvicorn)" '[ "$(hdr server)" = cloudflare ]'

echo "3. Content-Security-Policy"
check "no 'unsafe-inline'" '! grep -q "unsafe-inline" <<<"$CSP"'
check "no 'unsafe-eval'" '! grep -q "unsafe-eval" <<<"$CSP"'
for d in "default-src 'self'" "frame-ancestors 'self'" "object-src 'none'" "base-uri 'self'" "form-action 'self'"; do
  check "$d" 'grep -q "$d" <<<"$CSP"'
done
check "outside hosts are only unpkg + OSM tiles" \
  '[ "$(grep -o "https://[^ ;]*" <<<"$CSP" | sort -u | tr "\n" " ")" = "https://tile.openstreetmap.org https://unpkg.com " ]'

echo "4. HSTS"
check "max-age=31536000; includeSubDomains; preload" \
  '[ "$(hdr strict-transport-security)" = "max-age=31536000; includeSubDomains; preload" ]'
check "X-Frame-Options SAMEORIGIN" '[ "$(hdr x-frame-options)" = SAMEORIGIN ]'
check "nosniff" '[ "$(hdr x-content-type-options)" = nosniff ]'

echo "5. /search history hygiene (served script)"
JS=$(curl -sS --max-time 30 "$BASE/static/js/search.js")
check "search.js has no innerHTML" '! grep -q innerHTML <<<"$JS"'
check "search.js validates history" 'grep -q "cleanHistory(JSON.parse(raw))" <<<"$JS"'

echo "6. Hidden files, docs, debug"
for p in /.env /.git/config /.git/HEAD /render.yaml /Dockerfile /requirements.txt /docs /redoc /openapi.json /debug; do
  check "$p is 404" '[ "$(code "$BASE$p")" = 404 ]'
done

echo "7. security.txt"
TXT=$(curl -sS --max-time 30 "$BASE/.well-known/security.txt")
check "has Contact" 'grep -q "^Contact: " <<<"$TXT"'
check "has Expires" 'grep -q "^Expires: " <<<"$TXT"'

echo "8. No accounts yet"
check "no login/signup endpoints answer" \
  '[ "$(code -X POST "$BASE/login")" != 200 ] && [ "$(code -X POST "$BASE/signup")" != 200 ]'

echo
if [ "$fails" -eq 0 ]; then echo "All checks passed."; else echo "$fails check(s) failed."; fi
exit $((fails > 0))
