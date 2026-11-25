#!/usr/bin/env bash
# End-to-end curl test script for per-user sensor & data isolation (Tests 1-4)
# Prerequisite: start auth-service with TEST_AUTO_VERIFY=true (automated tests only, never for production):
#   TEST_AUTO_VERIFY=true docker compose up -d auth
# Usage:
#   BASE_URL="http://localhost:8088" LEGACY_KEY="<your-env-SENSOR_KEY>" bash tests/test_isolation.sh

set -euo pipefail

BASE="${BASE_URL:-http://localhost:8088}"
STAMP="$(date +%s)"
USER_A="iso_a_${STAMP}"
EMAIL_A="${USER_A}@example.com"
USER_B="iso_b_${STAMP}"
EMAIL_B="${USER_B}@example.com"
PASS="TestPass123"

echo "=== 1. Registering & logging in User A (${USER_A}) and User B (${USER_B}) (requires TEST_AUTO_VERIFY=true on auth-service) ==="
REG_A=$(curl -sS -X POST "${BASE}/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER_A}\",\"email\":\"${EMAIL_A}\",\"password\":\"${PASS}\"}")
echo "${REG_A}"
if echo "${REG_A}" | grep -q '"verify"[[:space:]]*:[[:space:]]*true'; then
  echo "ERROR: auth-service returned verify:true. Restart auth with TEST_AUTO_VERIFY=true for automated script runs." >&2
  exit 1
fi

curl -sS -X POST "${BASE}/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${USER_B}\",\"email\":\"${EMAIL_B}\",\"password\":\"${PASS}\"}"
echo ""

TOKEN_A=$(curl -sS -X POST "${BASE}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${EMAIL_A}\",\"password\":\"${PASS}\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

TOKEN_B=$(curl -sS -X POST "${BASE}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${EMAIL_B}\",\"password\":\"${PASS}\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "=== Fetching User A's sensor (lazy creation returns full key ONCE) ==="
SENSOR_A_JSON=$(curl -sS "${BASE}/api/sensors/me" -H "Authorization: Bearer ${TOKEN_A}")
echo "User A /api/sensors/me (1st call): ${SENSOR_A_JSON}"
KEY_A=$(echo "${SENSOR_A_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")

SENSOR_A_SECOND=$(curl -sS "${BASE}/api/sensors/me" -H "Authorization: Bearer ${TOKEN_A}")
echo "User A /api/sensors/me (2nd call, no raw key): ${SENSOR_A_SECOND}"

echo "=== Posting an alert with User A's sensor key ==="
INGEST_A=$(curl -sS -X POST "${BASE}/api/alerts/ingest" \
  -H "Content-Type: application/json" \
  -H "X-Service-Key: ${KEY_A}" \
  -d '{"type":"DoS/SYN Flood","src":"203.0.113.77","dst":"192.0.2.10","dport":"80","detail":"Test A isolation"}')
echo "Ingest A response: ${INGEST_A}"
ALERT_A_ID=$(echo "${INGEST_A}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "User A alerts:"
curl -sS "${BASE}/api/alerts/" -H "Authorization: Bearer ${TOKEN_A}"
echo ""
echo "User B alerts (must be empty, total=0):"
curl -sS "${BASE}/api/alerts/" -H "Authorization: Bearer ${TOKEN_B}"
echo ""
echo "User B stats (must be total=0):"
curl -sS "${BASE}/api/alerts/stats" -H "Authorization: Bearer ${TOKEN_B}"
echo ""
echo "User B analytics summary (must be total=0):"
curl -sS "${BASE}/api/analytics/summary?hours=24" -H "Authorization: Bearer ${TOKEN_B}"
echo ""
echo "User B blocked-ips (must be empty):"
curl -sS "${BASE}/api/alerts/blocked-ips" -H "Authorization: Bearer ${TOKEN_B}"
echo ""

echo "===User A blocks 203.0.113.77 on Alert #${ALERT_A_ID} ==="
BLOCK_A=$(curl -sS -X POST "${BASE}/api/alerts/block-ip" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN_A}" \
  -d "{\"ip\":\"203.0.113.77\",\"alert_id\":${ALERT_A_ID},\"minutes\":10}")
echo "Block A response: ${BLOCK_A}"
BLOCK_A_ID=$(echo "${BLOCK_A}" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")

echo "=== 2. Cross-User Access Checks (As User B on User A's resources -> all must return 404) ==="
echo -n "GET /api/alerts/${ALERT_A_ID} as B -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" "${BASE}/api/alerts/${ALERT_A_ID}" -H "Authorization: Bearer ${TOKEN_B}"

echo -n "PATCH /api/alerts/${ALERT_A_ID}/status as B -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X PATCH "${BASE}/api/alerts/${ALERT_A_ID}/status" \
  -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_B}" -d '{"status":"resolved"}'

echo -n "POST /api/alerts/${ALERT_A_ID}/explain as B -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/${ALERT_A_ID}/explain" \
  -H "Authorization: Bearer ${TOKEN_B}"

echo -n "POST /api/alerts/block-ip on A's alert_id as B -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/block-ip" \
  -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN_B}" \
  -d "{\"ip\":\"203.0.113.77\",\"alert_id\":${ALERT_A_ID},\"minutes\":10}"

echo -n "POST /api/alerts/blocked-ips/${BLOCK_A_ID}/unblock as B -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/blocked-ips/${BLOCK_A_ID}/unblock" \
  -H "Authorization: Bearer ${TOKEN_B}"

echo "=== 3. Legacy SENSOR_KEY Check ==="
if [ -n "${LEGACY_KEY:-}" ]; then
  echo -n "POST /api/alerts/ingest with legacy SENSOR_KEY -> HTTP "
  curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/ingest" \
    -H "Content-Type: application/json" \
    -H "X-Service-Key: ${LEGACY_KEY}" \
    -d '{"type":"PortScan","src":"203.0.113.99","dst":"192.0.2.5","dport":"22","detail":"Legacy Pi sensor check"}'
else
  echo "Skipped (set LEGACY_KEY=<your-env-SENSOR_KEY> to test legacy key ingest)"
fi

echo "=== 4. Regenerate User A's Sensor Key ==="
REGEN_A=$(curl -sS -X POST "${BASE}/api/sensors/me/regenerate" -H "Authorization: Bearer ${TOKEN_A}")
NEW_KEY_A=$(echo "${REGEN_A}" | python3 -c "import sys,json; print(json.load(sys.stdin)['key'])")

echo -n "Old Key A ingest (must be 401) -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/ingest" \
  -H "Content-Type: application/json" -H "X-Service-Key: ${KEY_A}" \
  -d '{"type":"PortScan","src":"203.0.113.78","dst":"192.0.2.10"}'

echo -n "New Key A ingest (must be 201) -> HTTP "
curl -sS -o /dev/null -w "%{http_code}\n" -X POST "${BASE}/api/alerts/ingest" \
  -H "Content-Type: application/json" -H "X-Service-Key: ${NEW_KEY_A}" \
  -d '{"type":"PortScan","src":"203.0.113.78","dst":"192.0.2.10"}'

echo "=== All isolation checks completed ==="
