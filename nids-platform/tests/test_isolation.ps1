# PowerShell curl.exe test script for per-user sensor & data isolation (Tests 1-4)
# Prerequisite: start auth-service with TEST_AUTO_VERIFY=true (automated tests only, never for production):
#   $env:TEST_AUTO_VERIFY="true"; docker compose up -d auth
# Usage (from nids-platform):
#   powershell -ExecutionPolicy Bypass -File .\tests\test_isolation.ps1

param(
  [string]$BaseUrl = "http://localhost:8088",
  [string]$LegacyKey = $env:SENSOR_KEY
)

$ErrorActionPreference = "Stop"
$stamp = [int][double]::Parse((Get-Date -UFormat %s))
$userA = "iso_a_$stamp"
$emailA = "$userA@example.com"
$userB = "iso_b_$stamp"
$emailB = "$userB@example.com"
$pass = "TestPass123"

Write-Host "=== 1. Registering & logging in User A ($userA) and User B ($userB) (requires TEST_AUTO_VERIFY=true on auth-service) ===" -ForegroundColor Cyan
$regA = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/register" -ContentType "application/json" `
  -Body (@{ username = $userA; email = $emailA; password = $pass } | ConvertTo-Json)
if ($regA.verify -eq $true) {
  throw "auth-service returned verify=true. Start auth container with TEST_AUTO_VERIFY=true for automated CLI tests."
}
Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/register" -ContentType "application/json" `
  -Body (@{ username = $userB; email = $emailB; password = $pass } | ConvertTo-Json) | Out-Null

$loginA = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -ContentType "application/json" `
  -Body (@{ email = $emailA; password = $pass } | ConvertTo-Json)
$tokenA = $loginA.token

$loginB = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/auth/login" -ContentType "application/json" `
  -Body (@{ email = $emailB; password = $pass } | ConvertTo-Json)
$tokenB = $loginB.token

$sensorA1 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/sensors/me" -Headers @{ Authorization = "Bearer $tokenA" }
$keyA = $sensorA1.key
Write-Host "User A 1st /api/sensors/me returned prefix=$($sensorA1.key_prefix) and full key (len=$($keyA.Length))"

$sensorA2 = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/sensors/me" -Headers @{ Authorization = "Bearer $tokenA" }
Write-Host "User A 2nd /api/sensors/me has key property? $($null -ne $sensorA2.key) (expected: False)"

$ingestA = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/alerts/ingest" -ContentType "application/json" `
  -Headers @{ "X-Service-Key" = $keyA } `
  -Body (@{ type = "DoS/SYN Flood"; src = "203.0.113.77"; dst = "192.0.2.10"; dport = "80"; detail = "User A alert" } | ConvertTo-Json)
$alertAId = $ingestA.id
Write-Host "Posted alert id=$alertAId with User A's sensor key"

$alertsA = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/alerts/" -Headers @{ Authorization = "Bearer $tokenA" }
$alertsB = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/alerts/" -Headers @{ Authorization = "Bearer $tokenB" }
$statsB = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/alerts/stats" -Headers @{ Authorization = "Bearer $tokenB" }
$summaryB = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/analytics/summary?hours=24" -Headers @{ Authorization = "Bearer $tokenB" }
$blocksB = Invoke-RestMethod -Method Get -Uri "$BaseUrl/api/alerts/blocked-ips" -Headers @{ Authorization = "Bearer $tokenB" }

Write-Host "User A total alerts: $($alertsA.total) (expected: 1)"
Write-Host "User B total alerts: $($alertsB.total), stats.total: $($statsB.total), analytics.total: $($summaryB.total), blocked: $($blocksB.blocked.Count) (all expected: 0)"

$blockA = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/alerts/block-ip" -ContentType "application/json" `
  -Headers @{ Authorization = "Bearer $tokenA" } `
  -Body (@{ ip = "203.0.113.77"; alert_id = $alertAId; minutes = 10 } | ConvertTo-Json)
$blockAId = $blockA.id
Write-Host "User A created block id=$blockAId"

Write-Host "`n=== 2. As User B, call GET/PATCH/POST on A's alert id, block A's alert, unblock A's block (all must return 404) ===" -ForegroundColor Cyan
$s1 = curl.exe -s -o NUL -w "%{http_code}" "$BaseUrl/api/alerts/$alertAId" -H "Authorization: Bearer $tokenB"
$s2 = curl.exe -s -o NUL -w "%{http_code}" -X PATCH "$BaseUrl/api/alerts/$alertAId/status" -H "Content-Type: application/json" -H "Authorization: Bearer $tokenB" -d "{\"status\":\"resolved\"}"
$s3 = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/$alertAId/explain" -H "Authorization: Bearer $tokenB"
$s4 = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/block-ip" -H "Content-Type: application/json" -H "Authorization: Bearer $tokenB" -d "{\"ip\":\"203.0.113.77\",\"alert_id\":$alertAId,\"minutes\":10}"
$s5 = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/blocked-ips/$blockAId/unblock" -H "Authorization: Bearer $tokenB"

Write-Host "GET A's alert as B:     $s1 (expected 404)"
Write-Host "PATCH A's status as B:  $s2 (expected 404)"
Write-Host "POST A's explain as B:  $s3 (expected 404)"
Write-Host "Block A's alert as B:   $s4 (expected 404)"
Write-Host "Unblock A's block as B: $s5 (expected 404)"

Write-Host "`n=== 3. Legacy SENSOR_KEY Check ===" -ForegroundColor Cyan
if ($LegacyKey) {
  $sLegacy = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/ingest" -H "Content-Type: application/json" -H "X-Service-Key: $LegacyKey" -d "{\"type\":\"PortScan\",\"src\":\"203.0.113.99\",\"dst\":\"192.0.2.5\",\"dport\":\"22\",\"detail\":\"Legacy key check\"}"
  Write-Host "Legacy SENSOR_KEY ingest status: $sLegacy (expected 201)"
} else {
  Write-Host "Pass -LegacyKey <SENSOR_KEY> to verify legacy key ingest"
}

Write-Host "`n=== 4. Regenerate User A's Key ===" -ForegroundColor Cyan
$regenA = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/sensors/me/regenerate" -Headers @{ Authorization = "Bearer $tokenA" }
$newKeyA = $regenA.key
$sOld = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/ingest" -H "Content-Type: application/json" -H "X-Service-Key: $keyA" -d "{\"type\":\"PortScan\",\"src\":\"203.0.113.78\",\"dst\":\"192.0.2.10\"}"
$sNew = curl.exe -s -o NUL -w "%{http_code}" -X POST "$BaseUrl/api/alerts/ingest" -H "Content-Type: application/json" -H "X-Service-Key: $newKeyA" -d "{\"type\":\"PortScan\",\"src\":\"203.0.113.78\",\"dst\":\"192.0.2.10\"}"
Write-Host "Old key A ingest: $sOld (expected 401)"
Write-Host "New key A ingest: $sNew (expected 201)"
