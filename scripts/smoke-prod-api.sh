#!/usr/bin/env bash
set -euo pipefail

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "Error: jq is required."
  exit 1
fi

API_URL="${API_URL:-https://www.omniwatch.hustlerati.com/api}"
PHONE="${PHONE:-}"
PASSWORD="${PASSWORD:-}"

if [[ -z "$PHONE" || -z "$PASSWORD" ]]; then
  echo "Usage:"
  echo "  PHONE='+254712345678' PASSWORD='YourPass@123' [API_URL='https://www.omniwatch.hustlerati.com/api'] $0"
  exit 1
fi

echo "1) Testing login: ${API_URL}/login"
login_raw="$(
  curl -sSL -w '\n%{http_code}' \
    --post301 --post302 --post303 \
    -H 'Content-Type: application/json' \
    -X POST "${API_URL}/login" \
    -d "{\"phone\":\"${PHONE}\",\"password\":\"${PASSWORD}\"}"
)"
login_status="$(echo "$login_raw" | tail -n1)"
login_body="$(echo "$login_raw" | sed '$d')"

if [[ "$login_status" != "200" ]]; then
  echo "Login failed (HTTP ${login_status})"
  if echo "$login_body" | jq -e . >/dev/null 2>&1; then
    echo "$login_body" | jq .
  else
    echo "$login_body"
  fi
  exit 1
fi

token="$(echo "$login_body" | jq -r '.token // empty')"
if [[ -z "$token" ]]; then
  echo "Login succeeded but no token was returned."
  echo "$login_body" | jq .
  exit 1
fi

echo "2) Testing token verification: ${API_URL}/verify-token"
verify_raw="$(
  curl -sSL -w '\n%{http_code}' \
    --post301 --post302 --post303 \
    -H 'Content-Type: application/json' \
    -X POST "${API_URL}/verify-token" \
    -d "{\"token\":\"${token}\"}"
)"
verify_status="$(echo "$verify_raw" | tail -n1)"
verify_body="$(echo "$verify_raw" | sed '$d')"
verify_valid="$(echo "$verify_body" | jq -r '.valid // false')"

if [[ "$verify_status" != "200" || "$verify_valid" != "true" ]]; then
  echo "Token verify failed (HTTP ${verify_status})"
  if echo "$verify_body" | jq -e . >/dev/null 2>&1; then
    echo "$verify_body" | jq .
  else
    echo "$verify_body"
  fi
  exit 1
fi

echo "3) Testing authenticated user endpoint: ${API_URL}/me"
me_raw="$(
  curl -sSL -w '\n%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    -X GET "${API_URL}/me"
)"
me_status="$(echo "$me_raw" | tail -n1)"
me_body="$(echo "$me_raw" | sed '$d')"
me_authenticated="$(echo "$me_body" | jq -r '.authenticated // false')"

if [[ "$me_status" != "200" || "$me_authenticated" != "true" ]]; then
  echo "/me failed (HTTP ${me_status})"
  if echo "$me_body" | jq -e . >/dev/null 2>&1; then
    echo "$me_body" | jq .
  else
    echo "$me_body"
  fi
  exit 1
fi

echo "Smoke test passed."
echo "$me_body" | jq '{authenticated, user: {id: .user.id, role: .user.role, phone: .user.phone}}'
