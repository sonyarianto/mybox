#!/usr/bin/env bash
# Exercise local auth (no external provider): sign-up, session, entitlement
# compat, OAuth provider discovery, refresh, and logout.
set -euo pipefail

api="${TASK_SPACE_LOCAL_AUTH_URL:-http://127.0.0.1:3000}"
jar="$(mktemp -t task-space-local-auth-cookies.XXXXXX)"
trap 'rm -f "$jar"' EXIT

email="local-auth-$(date +%s)-$$@example.com"
password="correct-horse-battery-staple-$$"

code="$(curl -sS -o /tmp/task-space-signup.json -w '%{http_code}' --max-time 10 \
  -X POST "$api/auth/sign-up" \
  -H 'Content-Type: application/json' \
  --cookie-jar "$jar" \
  --data "{\"email\":\"$email\",\"password\":\"$password\"}")"
echo "signup -> HTTP $code"
test "$code" = "201" || { cat /tmp/task-space-signup.json; exit 1; }

code="$(curl -sS -o /tmp/task-space-session.json -w '%{http_code}' --max-time 10 \
  --cookie "$jar" "$api/auth/session")"
echo "session -> HTTP $code"
test "$code" = "200" || { cat /tmp/task-space-session.json; exit 1; }

code="$(curl -sS -o /tmp/task-space-entitlement.json -w '%{http_code}' --max-time 10 \
  --cookie "$jar" "$api/account/entitlement")"
echo "entitlement -> HTTP $code"
test "$code" = "200" || { cat /tmp/task-space-entitlement.json; exit 1; }
grep -q '"sync_enabled"[[:space:]]*:[[:space:]]*true' /tmp/task-space-entitlement.json

code="$(curl -sS -o /tmp/task-space-oauth.json -w '%{http_code}' --max-time 10 \
  "$api/auth/oauth-providers")"
echo "oauth-providers -> HTTP $code"
test "$code" = "200" || { cat /tmp/task-space-oauth.json; exit 1; }

code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST "$api/auth/refresh" --cookie "$jar" --cookie-jar "$jar")"
echo "refresh -> HTTP $code"
test "$code" = "200" || exit 1

code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
  -X POST "$api/auth/logout" --cookie "$jar" --cookie-jar "$jar")"
echo "logout -> HTTP $code"
test "$code" = "200" || exit 1

echo "local-auth acceptance passed"
