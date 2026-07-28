<#
.SYNOPSIS
    End-to-end manual test for per-account brute-force lockout (issue #72).

.DESCRIPTION
    Exercises every acceptance criterion on a RUNNING server and prints a
    detailed verdict per check, including the exact reason a check failed and
    what that failure implies. Nothing is mocked — this drives the real HTTP API.

    Read scripts/LOCKOUT_TESTING.md before running: the server MUST be started
    with a raised login rate limit, or the AUTH-07 limiter returns 429 before the
    lockout tiers can engage and most checks below will report a false failure.

.PARAMETER BaseUrl
    Server root. Default http://localhost:9090

.PARAMETER AdminEmail / AdminPassword
    Seeded super-admin used for the admin unlock + audit checks.

.PARAMETER SoftThreshold / HardThreshold
    Must match the server's AUTH_LOGIN_SOFT_LOCK_THRESHOLD /
    AUTH_LOGIN_HARD_LOCK_THRESHOLD. Defaults match the shipped defaults.

.EXAMPLE
    .\scripts\test-lockout.ps1
    .\scripts\test-lockout.ps1 -SoftThreshold 3 -HardThreshold 5 -Verbose
#>
[CmdletBinding()]
param(
    [string]$BaseUrl       = 'http://localhost:9090',
    [string]$TenantSlug    = 'emc',
    [string]$AdminEmail    = 'admin@emc.local',
    [string]$AdminPassword = 'ChangeMe123!',
    [int]$SoftThreshold    = 5,
    [int]$HardThreshold    = 10
)

$ErrorActionPreference = 'Stop'

# ── Result tracking ──────────────────────────────────────────────────────────
$script:Results = [System.Collections.ArrayList]::new()
$script:StepNo  = 0

function Write-Section($Title) {
    Write-Host ''
    Write-Host ('─' * 78) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('─' * 78) -ForegroundColor DarkGray
}

function Write-Info($Msg)   { Write-Host "    $Msg" -ForegroundColor DarkGray }
function Write-Detail($Msg) { Write-Host "      → $Msg" -ForegroundColor Gray }

# Record and print one assertion. $Why explains what a failure MEANS, so a red
# line is actionable without re-reading the implementation.
function Assert-That {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][bool]$Condition,
        [string]$Expected = '',
        [string]$Actual   = '',
        [string]$Why      = ''
    )
    $script:StepNo++
    $null = $script:Results.Add([pscustomobject]@{
        Step = $script:StepNo; Name = $Name; Passed = $Condition
        Expected = $Expected; Actual = $Actual; Why = $Why
    })
    if ($Condition) {
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
        Write-Host $Name
        if ($Actual -and $VerbosePreference -eq 'Continue') { Write-Detail "got: $Actual" }
    } else {
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host $Name -ForegroundColor Red
        if ($Expected) { Write-Host "      expected : $Expected" -ForegroundColor Yellow }
        if ($Actual)   { Write-Host "      actual   : $Actual"   -ForegroundColor Yellow }
        if ($Why)      { Write-Host "      meaning  : $Why"      -ForegroundColor Magenta }
    }
}

# Invoke-RestMethod throws on 4xx/5xx, which is the NORMAL case here (401s are
# what we are testing). This wrapper always returns a inspectable result object
# instead, including response headers so the Retry-After check can run.
function Invoke-Api {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        $Body = $null,
        [hashtable]$Headers = @{}
    )
    $uri = "$BaseUrl$Path"
    $h   = @{ 'Content-Type' = 'application/json' }
    foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }

    $params = @{ Uri = $uri; Method = $Method; Headers = $h; UseBasicParsing = $true }
    if ($null -ne $Body) { $params.Body = ($Body | ConvertTo-Json -Depth 8 -Compress) }

    try {
        $resp = Invoke-WebRequest @params
        $parsed = $null
        if ($resp.Content) { try { $parsed = $resp.Content | ConvertFrom-Json } catch {} }
        return [pscustomobject]@{
            StatusCode = [int]$resp.StatusCode
            Raw        = $resp.Content
            Json       = $parsed
            Headers    = $resp.Headers
            Ok         = $true
        }
    } catch {
        $r = $_.Exception.Response
        if (-not $r) {
            # No response at all — server down, wrong port, TLS mismatch.
            return [pscustomobject]@{
                StatusCode = 0; Raw = $_.Exception.Message; Json = $null
                Headers = @{}; Ok = $false
            }
        }
        $code = [int]$r.StatusCode
        $raw  = ''
        try {
            $sr  = New-Object System.IO.StreamReader($r.GetResponseStream())
            $raw = $sr.ReadToEnd(); $sr.Close()
        } catch {}
        $parsed = $null
        if ($raw) { try { $parsed = $raw | ConvertFrom-Json } catch {} }
        $hdrs = @{}
        try { foreach ($k in $r.Headers.AllKeys) { $hdrs[$k] = $r.Headers[$k] } } catch {}
        return [pscustomobject]@{
            StatusCode = $code; Raw = $raw; Json = $parsed; Headers = $hdrs; Ok = $false
        }
    }
}

function Try-Login {
    param([string]$Email, [string]$Password)
    Invoke-Api -Method POST -Path '/api/v1/auth/login' -Body @{ email = $Email; password = $Password }
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Host ''
Write-Host '╔══════════════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║  EMC Auth — Account Lockout (issue #72) end-to-end test                   ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Info "target        : $BaseUrl"
Write-Info "soft / hard   : $SoftThreshold / $HardThreshold failures"

# ── 0. Preflight ─────────────────────────────────────────────────────────────
Write-Section '0. Preflight — server reachable, rate limit headroom'

$health = Invoke-Api -Method GET -Path '/health'
if ($health.StatusCode -eq 0) {
    Write-Host "  [ABORT] Cannot reach $BaseUrl" -ForegroundColor Red
    Write-Host "          $($health.Raw)" -ForegroundColor Yellow
    Write-Host "          Start the server first — see scripts/LOCKOUT_TESTING.md" -ForegroundColor Yellow
    exit 1
}
Assert-That -Name 'Server responds on /health' -Condition ($health.StatusCode -eq 200) `
    -Expected '200' -Actual "$($health.StatusCode)" `
    -Why 'Every later check needs a live server; nothing below is meaningful.'

# The rate limiter is the single most common cause of confusing results, so it
# is probed explicitly BEFORE any real assertion, using a throwaway address.
Write-Info 'Probing the AUTH-07 login rate limiter for headroom...'
$probeEmail = "rl-probe-$(Get-Random)@lockout.test"
$probe429 = $false
$probeCount = 0
for ($i = 1; $i -le ($HardThreshold + 2); $i++) {
    $r = Try-Login -Email $probeEmail -Password 'definitely-wrong'
    $probeCount++
    if ($r.StatusCode -eq 429) { $probe429 = $true; break }
}
if ($probe429) {
    Write-Host ''
    Write-Host "  [ABORT] Hit HTTP 429 after $probeCount attempts from this IP." -ForegroundColor Red
    Write-Host '          The AUTH-07 rate limiter is throttling before the lockout' -ForegroundColor Yellow
    Write-Host '          tiers can engage, so the tests below would report false' -ForegroundColor Yellow
    Write-Host '          failures (429 where a 401 is expected).' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '          FIX — restart the server with headroom:' -ForegroundColor Cyan
    Write-Host '            $env:AUTH_LOGIN_RATE_LIMIT_PER_IP=1000' -ForegroundColor White
    Write-Host '            $env:AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT=1000' -ForegroundColor White
    Write-Host ''
    Write-Host '          This is a TEST-ONLY setting. Production keeps 5/10.' -ForegroundColor DarkGray
    exit 1
}
Assert-That -Name "Rate limiter has headroom for $($HardThreshold + 2) attempts" -Condition $true `
    -Actual "no 429 in $probeCount attempts" `
    -Why 'Without headroom the limiter masks lockout behaviour.'

# ── 1. Admin token ───────────────────────────────────────────────────────────
Write-Section '1. Authenticate as super-admin (needed for unlock + audit checks)'

$adminLogin = Try-Login -Email $AdminEmail -Password $AdminPassword
$adminToken = $null
if ($adminLogin.StatusCode -eq 200 -and $adminLogin.Json.access_token) {
    $adminToken = $adminLogin.Json.access_token
}
Assert-That -Name 'Super-admin login succeeds' -Condition ($null -ne $adminToken) `
    -Expected '200 + access_token' -Actual "$($adminLogin.StatusCode) $($adminLogin.Raw)" `
    -Why "Wrong SEED_ADMIN_PASSWORD, or the admin account is itself locked. Pass -AdminPassword, or clear its lock in Redis/DB."
if (-not $adminToken) {
    Write-Host '  [ABORT] No admin token — unlock and audit checks cannot run.' -ForegroundColor Red
    exit 1
}
$AuthHdr = @{ Authorization = "Bearer $adminToken" }

# ── 2. Create the victim account ─────────────────────────────────────────────
Write-Section '2. Register a fresh victim account'

$victimEmail = "victim-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())@lockout.test"
$victimPass  = 'SecPass123!'
$reg = Invoke-Api -Method POST -Path '/api/v1/auth/register' `
    -Headers @{ 'X-Tenant-Slug' = $TenantSlug } `
    -Body @{ email = $victimEmail; password = $victimPass; first_name = 'Lock'; last_name = 'Victim' }
Assert-That -Name 'Victim registered' -Condition ($reg.StatusCode -in 200,201) `
    -Expected '201' -Actual "$($reg.StatusCode) $($reg.Raw)" `
    -Why "Tenant slug '$TenantSlug' may not exist — run the seed, or pass -TenantSlug."
Write-Info "victim: $victimEmail / $victimPass"

# Baseline: the correct password works BEFORE any failures. If this fails, every
# later 'refused' assertion is meaningless (it was never working to begin with).
$baseline = Try-Login -Email $victimEmail -Password $victimPass
Assert-That -Name 'Baseline: correct password works before any failures' `
    -Condition ($baseline.StatusCode -eq 200) `
    -Expected '200' -Actual "$($baseline.StatusCode) $($baseline.Raw)" `
    -Why 'Without a working baseline, later refusals prove nothing about lockout.'

# ── 3. Soft tier ─────────────────────────────────────────────────────────────
Write-Section "3. SOFT tier — $SoftThreshold failures must refuse even the correct password"

# The successful baseline login above reset the counter, so this starts at zero.
$softStatuses = @()
for ($i = 1; $i -le $SoftThreshold; $i++) {
    $r = Try-Login -Email $victimEmail -Password 'WrongPass!'
    $softStatuses += $r.StatusCode
    Write-Detail "failure $i/$SoftThreshold -> HTTP $($r.StatusCode) $($r.Raw)"
}
Assert-That -Name "All $SoftThreshold wrong-password attempts returned 401" `
    -Condition (($softStatuses | Where-Object { $_ -ne 401 }).Count -eq 0) `
    -Expected 'every attempt 401' -Actual ($softStatuses -join ', ') `
    -Why 'A 429 means the rate limiter interfered; a 500 means the lockout path errored.'

$softLocked = Try-Login -Email $victimEmail -Password $victimPass
Assert-That -Name 'Correct password is REFUSED while soft-locked' `
    -Condition ($softLocked.StatusCode -eq 401) `
    -Expected '401' -Actual "$($softLocked.StatusCode) $($softLocked.Raw)" `
    -Why 'A 200 here means the soft lock is not engaging at all — the counter is not being read, or Redis is unreachable and the code failed open.'

# Enumeration safety: the locked response must be byte-identical to a plain
# wrong-password response, and must NOT carry Retry-After.
$plainWrong = Try-Login -Email "nobody-$(Get-Random)@lockout.test" -Password 'WrongPass!'
Assert-That -Name 'Locked response body is identical to unknown-email response' `
    -Condition ($softLocked.Raw -eq $plainWrong.Raw) `
    -Expected "identical to: $($plainWrong.Raw)" -Actual "$($softLocked.Raw)" `
    -Why 'Any difference is an oracle: an attacker can distinguish "locked" from "wrong password" and thereby confirm the address exists.'

$retryAfter = $null
try { $retryAfter = $softLocked.Headers['Retry-After'] } catch {}
Assert-That -Name 'No Retry-After header on the account-lock path' `
    -Condition ([string]::IsNullOrEmpty($retryAfter)) `
    -Expected 'absent' -Actual "Retry-After: $retryAfter" `
    -Why 'The header''s mere presence reveals lock state — the same oracle the generic error exists to close. (429s from the rate limiter DO carry it; that is a different path.)'

# Soft tier must not have written to the users row.
$userList = Invoke-Api -Method GET -Path "/api/v1/users?search=$([uri]::EscapeDataString($victimEmail))&limit=5" -Headers $AuthHdr
$victimRow = $null
if ($userList.Json.users) { $victimRow = $userList.Json.users | Where-Object { $_.email -eq $victimEmail } | Select-Object -First 1 }
Assert-That -Name 'Victim visible via admin API' -Condition ($null -ne $victimRow) `
    -Expected 'one user row' -Actual "$($userList.StatusCode) $($userList.Raw)" `
    -Why 'Needed to inspect locked_until; check the users:read permission on the admin token.'
if ($victimRow) {
    Assert-That -Name 'SOFT tier wrote nothing to the database (locked_until still null)' `
        -Condition ($null -eq $victimRow.locked_until) `
        -Expected 'locked_until = null' -Actual "locked_until = $($victimRow.locked_until)" `
        -Why 'A soft lock must live only in Redis; persisting it here would make a 5-attempt burst survive the window.'
    Assert-That -Name 'SOFT tier left is_active untouched' -Condition ($victimRow.is_active -eq $true) `
        -Expected 'is_active = true' -Actual "is_active = $($victimRow.is_active)" `
        -Why 'is_active is the ADMIN block flag; the brute-force guard must never touch it.'
}

# ── 4. Hard tier ─────────────────────────────────────────────────────────────
Write-Section "4. HARD tier — reaching $HardThreshold failures must persist the lock"

$remaining = $HardThreshold - $SoftThreshold
Write-Info "$remaining more failures needed (attempts continue to be counted while soft-locked)"
for ($i = 1; $i -le $remaining; $i++) {
    $r = Try-Login -Email $victimEmail -Password 'WrongPass!'
    Write-Detail "failure $($SoftThreshold + $i)/$HardThreshold -> HTTP $($r.StatusCode)"
}

$userList2 = Invoke-Api -Method GET -Path "/api/v1/users?search=$([uri]::EscapeDataString($victimEmail))&limit=5" -Headers $AuthHdr
$victimRow2 = $null
if ($userList2.Json.users) { $victimRow2 = $userList2.Json.users | Where-Object { $_.email -eq $victimEmail } | Select-Object -First 1 }

Assert-That -Name 'HARD tier persisted locked_until to the database' `
    -Condition ($null -ne $victimRow2.locked_until) `
    -Expected 'locked_until = a future timestamp' -Actual "locked_until = $($victimRow2.locked_until)" `
    -Why 'Null means the escalation never fired: attempts stopped being counted once soft-locked, so the hard threshold was unreachable.'

if ($victimRow2.locked_until) {
    $until = [datetime]::Parse($victimRow2.locked_until).ToUniversalTime()
    $now   = [datetime]::UtcNow
    Assert-That -Name 'locked_until is in the future' -Condition ($until -gt $now) `
        -Expected "> $now (UTC)" -Actual "$until (UTC)" `
        -Why 'A past timestamp means the lock is already expired and enforces nothing.'
    Assert-That -Name 'locked_until is bounded (self-healing, not permanent)' `
        -Condition ($until -lt $now.AddDays(1)) `
        -Expected '< 24h out' -Actual "$([math]::Round(($until - $now).TotalMinutes,1)) minutes out" `
        -Why 'An unbounded lock is an attacker-triggered permanent DoS requiring admin intervention.'
}

Assert-That -Name 'HARD tier still left is_active = true' -Condition ($victimRow2.is_active -eq $true) `
    -Expected 'is_active = true' -Actual "is_active = $($victimRow2.is_active)" `
    -Why 'Setting is_active=false would let anyone who knows an email permanently disable that account with N requests.'

# ── 5. Admin unlock ──────────────────────────────────────────────────────────
Write-Section '5. Admin unlock — POST /api/v1/users/{id}/unlock'

$unauth = Invoke-Api -Method POST -Path "/api/v1/users/$($victimRow2.id)/unlock"
Assert-That -Name 'Unlock without a token is rejected' -Condition ($unauth.StatusCode -in 401,403) `
    -Expected '401 or 403' -Actual "$($unauth.StatusCode) $($unauth.Raw)" `
    -Why 'An unauthenticated unlock would hand attackers a way to undo the protection.'

$unlock = Invoke-Api -Method POST -Path "/api/v1/users/$($victimRow2.id)/unlock" -Headers $AuthHdr
Assert-That -Name 'Admin unlock returns 200' -Condition ($unlock.StatusCode -eq 200) `
    -Expected '200' -Actual "$($unlock.StatusCode) $($unlock.Raw)" `
    -Why 'Check the token carries users:write or admin:access.'
Assert-That -Name 'Unlock response reports locked_until = null' `
    -Condition ($null -eq $unlock.Json.locked_until) `
    -Expected 'null' -Actual "$($unlock.Json.locked_until)" `
    -Why 'The admin UI drives its badge off this field; a stale value keeps the badge lit.'
Assert-That -Name 'Unlock did not silently change is_active' -Condition ($unlock.Json.is_active -eq $true) `
    -Expected 'is_active = true (unchanged)' -Actual "is_active = $($unlock.Json.is_active)" `
    -Why 'Unlock must not double as un-blocking an administratively disabled user.'

# The real proof: login works again immediately. This only passes if BOTH the DB
# column and the Redis counter were cleared.
$afterUnlock = Try-Login -Email $victimEmail -Password $victimPass
Assert-That -Name 'Victim can log in immediately after unlock' `
    -Condition ($afterUnlock.StatusCode -eq 200) `
    -Expected '200' -Actual "$($afterUnlock.StatusCode) $($afterUnlock.Raw)" `
    -Why 'A 401 here means only half the lock was cleared — almost certainly the Redis failure counter still holds the soft lock, so WithLockoutReset is not wired up.'

$unlockAgain = Invoke-Api -Method POST -Path "/api/v1/users/$($victimRow2.id)/unlock" -Headers $AuthHdr
Assert-That -Name 'Unlock is idempotent on an unlocked user' -Condition ($unlockAgain.StatusCode -eq 200) `
    -Expected '200' -Actual "$($unlockAgain.StatusCode) $($unlockAgain.Raw)" `
    -Why 'The UI may fire unlock on an already-expired lock; that must not error.'

$missing = Invoke-Api -Method POST -Path '/api/v1/users/99999999/unlock' -Headers $AuthHdr
Assert-That -Name 'Unlock of a nonexistent user returns 404' -Condition ($missing.StatusCode -eq 404) `
    -Expected '404' -Actual "$($missing.StatusCode) $($missing.Raw)" `
    -Why 'A 500 would mean the not-found path is unhandled.'

# ── 6. Counter reset on success ──────────────────────────────────────────────
Write-Section '6. Window reset — a successful login clears accumulated failures'

for ($i = 1; $i -le ($SoftThreshold - 1); $i++) {
    $null = Try-Login -Email $victimEmail -Password 'WrongPass!'
}
Write-Detail "$($SoftThreshold - 1) failures recorded (one below threshold)"
$stillOk = Try-Login -Email $victimEmail -Password $victimPass
Assert-That -Name 'One below threshold: correct password still works' `
    -Condition ($stillOk.StatusCode -eq 200) `
    -Expected '200' -Actual "$($stillOk.StatusCode) $($stillOk.Raw)" `
    -Why 'Locking one attempt early would lock users out sooner than configured.'

for ($i = 1; $i -le ($SoftThreshold - 1); $i++) {
    $null = Try-Login -Email $victimEmail -Password 'WrongPass!'
}
$afterReset = Try-Login -Email $victimEmail -Password $victimPass
Assert-That -Name "Counter reset: another $($SoftThreshold - 1) failures do not lock" `
    -Condition ($afterReset.StatusCode -eq 200) `
    -Expected '200' -Actual "$($afterReset.StatusCode) $($afterReset.Raw)" `
    -Why 'A 401 means the successful login did not clear the counter, so failures accumulate across sessions and users get locked out unexpectedly.'

# ── 7. Case-folding bypass ───────────────────────────────────────────────────
Write-Section '7. Bypass check — varying email case must not mint a fresh counter'

$caseEmail = "case-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())@lockout.test"
$null = Invoke-Api -Method POST -Path '/api/v1/auth/register' `
    -Headers @{ 'X-Tenant-Slug' = $TenantSlug } `
    -Body @{ email = $caseEmail; password = $victimPass; first_name = 'Case'; last_name = 'Fold' }

for ($i = 1; $i -le $SoftThreshold; $i++) {
    # Alternate case every other attempt.
    $variant = if ($i % 2 -eq 0) { $caseEmail.ToUpper() } else { $caseEmail }
    $null = Try-Login -Email $variant -Password 'WrongPass!'
}
$caseLocked = Try-Login -Email $caseEmail -Password $victimPass
Assert-That -Name 'Case-varied attempts share one counter (no bypass)' `
    -Condition ($caseLocked.StatusCode -eq 401) `
    -Expected '401 (locked)' -Actual "$($caseLocked.StatusCode) $($caseLocked.Raw)" `
    -Why 'A 200 means each casing gets its own counter — an attacker gets unlimited attempts just by toggling capitalisation.'

# ── 8. Audit trail ───────────────────────────────────────────────────────────
Write-Section '8. Audit trail — lock events recorded'

Write-Info 'Waiting 3s for the async audit writer to flush...'
Start-Sleep -Seconds 3

$expectedActions = @(
    'auth.account_soft_locked',
    'auth.account_hard_locked',
    'auth.login_blocked_account_locked',
    'admin.account_unlocked'
)
foreach ($action in $expectedActions) {
    $logs = Invoke-Api -Method GET -Path "/api/v1/audit-logs?action=$action&limit=5" -Headers $AuthHdr
    $count = 0
    if ($logs.Json.logs) { $count = @($logs.Json.logs).Count }
    elseif ($logs.Json.total) { $count = $logs.Json.total }
    Assert-That -Name "Audit rows exist for '$action'" -Condition ($count -gt 0) `
        -Expected 'at least 1 row' -Actual "$count rows (HTTP $($logs.StatusCode))" `
        -Why 'Without these an operator cannot see that the guard fired, or how long an attack kept running.'
}

# ── 9. Metrics ───────────────────────────────────────────────────────────────
Write-Section '9. Prometheus metrics'

$metrics = Invoke-Api -Method GET -Path '/metrics'
if ($metrics.StatusCode -eq 200) {
    foreach ($m in @('emc_auth_account_lockouts_total', 'emc_auth_logins_blocked_by_lockout_total')) {
        $line = ($metrics.Raw -split "`n" | Where-Object { $_ -match "^$m\{" } | Select-Object -First 3) -join ' | '
        Assert-That -Name "Metric $m is exported with samples" -Condition ($line -ne '') `
            -Expected 'at least one labelled sample' -Actual "$line" `
            -Why 'Lockout spikes are the alertable signal; the refusal is invisible to clients by design.'
    }
} else {
    Write-Info "/metrics returned $($metrics.StatusCode) — skipped (may be auth-gated or loopback-bound)"
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Section 'SUMMARY'

$passed = @($script:Results | Where-Object Passed).Count
$failed = @($script:Results | Where-Object { -not $_.Passed }).Count
$total  = $script:Results.Count

Write-Host ''
Write-Host "  Total: $total   " -NoNewline
Write-Host "Passed: $passed   " -ForegroundColor Green -NoNewline
if ($failed -gt 0) { Write-Host "Failed: $failed" -ForegroundColor Red }
else               { Write-Host "Failed: 0" -ForegroundColor Green }

if ($failed -gt 0) {
    Write-Host ''
    Write-Host '  Failed checks:' -ForegroundColor Red
    foreach ($r in ($script:Results | Where-Object { -not $_.Passed })) {
        Write-Host "    #$($r.Step) $($r.Name)" -ForegroundColor Red
        if ($r.Expected) { Write-Host "        expected: $($r.Expected)" -ForegroundColor DarkYellow }
        if ($r.Actual)   { Write-Host "        actual  : $($r.Actual)"   -ForegroundColor DarkYellow }
        if ($r.Why)      { Write-Host "        meaning : $($r.Why)"      -ForegroundColor Magenta }
    }
    Write-Host ''
    Write-Host "  Victim account kept for inspection: $victimEmail" -ForegroundColor DarkGray
    exit 1
}

Write-Host ''
Write-Host '  All lockout acceptance criteria satisfied.' -ForegroundColor Green
Write-Host ''
exit 0
