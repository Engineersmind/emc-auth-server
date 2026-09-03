<#
.SYNOPSIS
    End-to-end verification for issue #130 (token type moves from "aud" to "gty").

.DESCRIPTION
    Drives the running server over HTTP exactly as Swagger would, then verifies the
    same facts against Postgres. Prints every token's decoded claims so they can be
    cross-checked on jwt.io, and ends with a PASS / FAIL summary.

    What it proves is NOT "gty appears". It is that nothing else moved: the same
    roles, the same permission arrays, the same 401s and - critically - the same
    403s. A 403 means the route gate let the token through and the PERMISSION check
    refused it, which is the only evidence that #130 changed the gate without
    disturbing RBAC underneath it.

    ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less UTF-8 file as
    cp1252, where an em dash decodes to a character the parser treats as a string
    delimiter. Keep it ASCII and it runs on 5.1 and 7 alike.

.EXAMPLE
    .\scripts\verify-issue-130.ps1

.EXAMPLE
    .\scripts\verify-issue-130.ps1 -LegacyToken "eyJhbGciOi..." -IncludeCrossTenant

.NOTES
    Creates only throwaway objects, all prefixed "gty130-": two OAuth applications,
    one end user, one API key, and (with -IncludeCrossTenant) a second tenant.
    Cleanup SQL is printed at the end.
#>

[CmdletBinding()]
param(
    [string] $BaseUrl       = "http://localhost:9090",
    [string] $AdminEmail    = "admin@emc.local",
    [string] $AdminPassword = "ChangeMe123!",
    [string] $TenantSlug    = "emc",

    # A token minted by the PREVIOUS build (no gty claim). Optional, but this is
    # the single most important check in the script - see Phase 8.
    [string] $LegacyToken   = "",

    # Only needed if METRICS_TOKEN is set in your .env.
    [string] $MetricsToken  = "",

    # Creates a second tenant to prove cross-tenant isolation still holds.
    [switch] $IncludeCrossTenant,

    # Waits out the per-IP token rate-limit window before the negative login
    # checks in Phase 6, so they get a real 401 instead of a 429. Adds ~65s.
    [switch] $SlowNegatives,

    [switch] $SkipSql,
    [string] $PgContainer   = "emc-auth-server-postgres-1",
    [string] $PgUser        = "emc_auth",
    [string] $PgDb          = "emc_auth"
)

$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

# --------------------------------------------------------------- output helpers

$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0
$script:Failures  = New-Object System.Collections.ArrayList
$script:Warnings  = New-Object System.Collections.ArrayList

# Counts requests deliberately made with the wrong grant for a route. Phase 11
# can only demand that the rejection counter moved if at least one was sent.
$script:WrongGrantProbes = 0

function Write-Head($text) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Write-Step($text) { Write-Host ""; Write-Host "-- $text" -ForegroundColor White }
function Write-Info($text) { Write-Host "   $text" -ForegroundColor Gray }
function Write-Val($label, $value) {
    Write-Host ("   {0,-26}" -f $label) -ForegroundColor DarkGray -NoNewline
    Write-Host $value -ForegroundColor Yellow
}

function Pass($label) {
    $script:PassCount++
    Write-Host "   [PASS] " -ForegroundColor Green -NoNewline
    Write-Host $label
}

function Fail($label, $detail) {
    $script:FailCount++
    [void]$script:Failures.Add(("{0} :: {1}" -f $label, $detail))
    Write-Host "   [FAIL] " -ForegroundColor Red -NoNewline
    Write-Host $label -ForegroundColor Red
    if ($detail) { Write-Host ("          " + $detail) -ForegroundColor DarkRed }
}

# Warn is for facts worth recording that are not regressions: a known gap, an
# environment-dependent result, an inconclusive check. Kept separate from Fail so
# the summary still reads clean when the only findings are documented gaps.
function Warn($label, $detail) {
    $script:WarnCount++
    [void]$script:Warnings.Add(("{0} :: {1}" -f $label, $detail))
    Write-Host "   [WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $label -ForegroundColor Yellow
    if ($detail) { Write-Host ("          " + $detail) -ForegroundColor DarkYellow }
}

function Assert-Equal($label, $expected, $actual) {
    if ("$actual" -eq "$expected") { Pass ("{0} = {1}" -f $label, $actual) }
    else { Fail $label ("expected '{0}', got '{1}'" -f $expected, $actual) }
}

function Assert-Status($label, $expected, $response) {
    if ($response.Status -eq $expected) {
        Pass ("{0} -> HTTP {1}" -f $label, $response.Status)
    } else {
        $body = ""
        if ($response.Raw) { $body = $response.Raw.Substring(0, [Math]::Min(200, $response.Raw.Length)) }
        Fail $label ("expected HTTP {0}, got {1}. Body: {2}" -f $expected, $response.Status, $body)
    }
}

# Assert-OneOf exists because a few real-world refusals are legitimately reported
# with more than one status depending on which layer refuses first, and pinning
# the wrong one would produce a false failure that hides real ones.
function Assert-OneOf($label, $expected, $response) {
    if ($expected -contains $response.Status) {
        Pass ("{0} -> HTTP {1}" -f $label, $response.Status)
    } else {
        $body = ""
        if ($response.Raw) { $body = $response.Raw.Substring(0, [Math]::Min(200, $response.Raw.Length)) }
        Fail $label ("expected one of [{0}], got {1}. Body: {2}" -f ($expected -join ", "), $response.Status, $body)
    }
}

function Assert-SameSet($label, $expected, $actual) {
    $e = ""; $a = ""
    if ($expected) { $e = (($expected | Sort-Object) -join ",") }
    if ($actual)   { $a = (($actual   | Sort-Object) -join ",") }
    if ($e -eq $a) { Pass ("{0} unchanged [{1}]" -f $label, $e) }
    else { Fail $label ("expected [{0}], got [{1}]" -f $e, $a) }
}

# ------------------------------------------------------------------- http + jwt

# Invoke-Api never throws on 4xx/5xx. Windows PowerShell 5.1 has no
# -SkipHttpErrorCheck, and the negative cases here (401, 403) are the POINT of
# this script, so the error response has to be read out of the exception.
function Invoke-Api {
    param(
        [string] $Method,
        [string] $Path,
        $Body,
        [string] $BearerToken,
        [string] $RawAuthHeader,
        [string] $BasicUser,
        [string] $BasicPass,
        [hashtable] $ExtraHeaders,
        [switch] $FormEncoded
    )

    $url = $Path
    if ($Path -notlike "http*") { $url = "$BaseUrl$Path" }

    $headers = @{}
    if ($BearerToken)   { $headers["Authorization"] = "Bearer $BearerToken" }
    if ($RawAuthHeader) { $headers["Authorization"] = $RawAuthHeader }
    if ($BasicUser) {
        $pair = "{0}:{1}" -f $BasicUser, $BasicPass
        $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
        $headers["Authorization"] = "Basic $b64"
    }
    if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }

    $params = @{
        Uri             = $url
        Method          = $Method
        Headers         = $headers
        UseBasicParsing = $true
        TimeoutSec      = 30
        ErrorAction     = 'Stop'
    }
    if ($null -ne $Body) {
        if ($FormEncoded) {
            $params["Body"]        = $Body
            $params["ContentType"] = "application/x-www-form-urlencoded"
        } else {
            $params["Body"]        = ($Body | ConvertTo-Json -Depth 6 -Compress)
            $params["ContentType"] = "application/json"
        }
    }

    # A per-call session, never reused, so response cookies can be read without
    # any of them being sent on a later request. Sending them back would change
    # what is being tested: the CSRF middleware engages on cookie-bearing
    # mutations, and JWTRenew treats a cookie as a renewable session.
    $params["SessionVariable"] = "callSession"

    $status = 0
    $raw    = ""
    $cookies = @{}
    try {
        $r      = Invoke-WebRequest @params
        $status = [int] $r.StatusCode
        $raw    = $r.Content
    } catch {
        # ErrorDetails.Message, NOT GetResponseStream(). Invoke-WebRequest has
        # already consumed and disposed the stream by the time it throws, so
        # reading it returns "" - which is why every negative case in the first
        # run reported an empty body.
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $raw = $_.ErrorDetails.Message }

        $resp = $null
        if ($_.Exception -and ($_.Exception.PSObject.Properties.Name -contains 'Response')) {
            $resp = $_.Exception.Response
        }
        if ($null -ne $resp) {
            $status = [int] $resp.StatusCode
        } else {
            Fail ("HTTP {0} {1}" -f $Method, $Path) $_.Exception.Message
            return [pscustomobject]@{ Status = -1; Raw = $_.Exception.Message; Json = $null; Cookies = @{} }
        }
    }

    if (Get-Variable -Name callSession -Scope Local -ErrorAction SilentlyContinue) {
        $sess = Get-Variable -Name callSession -Scope Local -ValueOnly
        if ($sess -and $sess.Cookies) {
            foreach ($ck in $sess.Cookies.GetCookies($url)) { $cookies[$ck.Name] = $ck.Value }
        }
    }

    $json = $null
    if ($raw) { try { $json = $raw | ConvertFrom-Json } catch { $json = $null } }
    return [pscustomobject]@{ Status = $status; Raw = $raw; Json = $json; Cookies = $cookies }
}

# Get-Challenge reads the RFC 6750 WWW-Authenticate header via HttpClient.
#
# It cannot be read from Invoke-WebRequest: HttpWebRequest treats
# WWW-Authenticate as a restricted header and consumes it for its own
# authentication negotiation, so it never reaches the header collection. The
# first run reported "no challenge on a 401" for that reason alone, which was
# wrong - the server does send it.
function Get-Challenge([string] $Path) {
    $url = $Path
    if ($Path -notlike "http*") { $url = "$BaseUrl$Path" }
    try {
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $client = New-Object System.Net.Http.HttpClient
        $resp   = $client.GetAsync($url).Result
        $out    = ""
        if ($resp.Headers.Contains("WWW-Authenticate")) {
            $out = ($resp.Headers.GetValues("WWW-Authenticate")) -join "; "
        }
        $code = [int] $resp.StatusCode
        $client.Dispose()
        return [pscustomobject]@{ Status = $code; Challenge = $out }
    } catch {
        return [pscustomobject]@{ Status = -1; Challenge = "" }
    }
}

function ConvertFrom-Base64Url([string] $segment) {
    $p = $segment.Replace('-', '+').Replace('_', '/')
    while ($p.Length % 4 -ne 0) { $p += '=' }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
}

function ConvertTo-Base64Url([string] $text) {
    $b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text))
    return $b.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Decode-Jwt([string] $token) {
    if (-not $token) { return $null }
    $parts = $token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    return (ConvertFrom-Base64Url $parts[1]) | ConvertFrom-Json
}

# Set-JwtClaim rewrites one claim and leaves the ORIGINAL signature in place.
#
# That is the whole point: the resulting token is what an attacker can actually
# build - they can read and edit the payload freely, but cannot re-sign it. Every
# such token must be refused, which is what proves gty is protected by the
# signature rather than merely read from it.
function Set-JwtClaim([string] $token, [string] $name, $value) {
    $parts = $token.Split('.')
    $obj = (ConvertFrom-Base64Url $parts[1]) | ConvertFrom-Json
    if ($obj.PSObject.Properties.Name -contains $name) { $obj.$name = $value }
    else { $obj | Add-Member -MemberType NoteProperty -Name $name -Value $value }
    $json = $obj | ConvertTo-Json -Depth 12 -Compress
    return ("{0}.{1}.{2}" -f $parts[0], (ConvertTo-Base64Url $json), $parts[2])
}

function Remove-JwtClaim([string] $token, [string] $name) {
    $parts = $token.Split('.')
    $obj = (ConvertFrom-Base64Url $parts[1]) | ConvertFrom-Json
    $obj.PSObject.Properties.Remove($name)
    $json = $obj | ConvertTo-Json -Depth 12 -Compress
    return ("{0}.{1}.{2}" -f $parts[0], (ConvertTo-Base64Url $json), $parts[2])
}

function Show-Claims($label, $token) {
    if (-not $token) { Write-Info ("no token to show for '{0}'" -f $label); return $null }
    $c = Decode-Jwt $token
    if (-not $c) { Write-Info ("could not decode token for '{0}'" -f $label); return $null }

    $perms = "(none)";  if ($c.permissions) { $perms = (($c.permissions | Sort-Object) -join ", ") }
    $ascope = "(absent)"; if ($c.admin_scope) { $ascope = $c.admin_scope }
    $aapps = "(absent)"; if ($c.admin_apps) { $aapps = (($c.admin_apps) -join ", ") }
    $appid = "(absent - tenant-level)"; if ($c.app_id) { $appid = $c.app_id }
    $sid   = "(absent - not session-scoped)"; if ($c.sid) { $sid = $c.sid }
    $scope = "(absent - unscoped)"; if ($c.scope) { $scope = $c.scope }
    $gty   = "(ABSENT - legacy shape)"; if ($c.gty) { $gty = $c.gty }

    Write-Host ""
    Write-Host ("   +-- " + $label) -ForegroundColor Magenta
    Write-Val "gty (NEW in #130)"  $gty
    Write-Val "aud (unchanged)"    (($c.aud) -join ", ")
    Write-Val "iss"                $c.iss
    Write-Val "role"               $c.role
    Write-Val "permissions"        $perms
    Write-Val "admin_scope"        $ascope
    Write-Val "admin_apps"         $aapps
    Write-Val "app_id"             $appid
    Write-Val "sid"                $sid
    Write-Val "scope"              $scope
    Write-Val "sub / tenant_id"    ("{0} / {1}" -f $c.sub, $c.tenant_id)
    Write-Host "   +-- paste the token into jwt.io to confirm this decode" -ForegroundColor DarkGray
    return $c
}

function Get-MetricValue([string] $metricsText, [string] $name) {
    $total = 0.0
    if (-not $metricsText) { return $total }
    foreach ($line in ($metricsText -split "`n")) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith("#")) { continue }
        if ($line -match ("^" + [regex]::Escape($name) + "(\{[^}]*\})?\s+([0-9.eE+-]+)$")) {
            $total += [double] $Matches[2]
        }
    }
    return $total
}

function Get-Metrics {
    $r = Invoke-Api -Method GET -Path "/metrics" -BearerToken $MetricsToken
    if ($r.Status -ne 200) {
        Write-Info ("metrics endpoint returned HTTP {0} (pass -MetricsToken if METRICS_TOKEN is set)" -f $r.Status)
        return ""
    }
    return $r.Raw
}

$script:PsqlError = "__PSQL_ERROR__"

function Invoke-Psql([string] $sql) {
    # No 2>&1 on a native executable. Windows PowerShell turns each stderr line
    # into an ErrorRecord, and with $ErrorActionPreference = 'Stop' that aborts
    # the entire script - which is exactly what one wrong column name did on the
    # first run, taking the whole of Phase 12 with it. Failures are returned as a
    # value instead, so a bad query costs one check rather than the run.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = $sql | docker exec -i $PgContainer psql -U $PgUser -d $PgDb -t -A -F "|" -v ON_ERROR_STOP=1
        if ($LASTEXITCODE -ne 0) { return $script:PsqlError }
        return ($out -join "`n")
    } catch {
        return $script:PsqlError
    } finally {
        $ErrorActionPreference = $prev
    }
}

# ============================================================ PHASE 0 preflight

Write-Head "PHASE 0 . Preflight"

Write-Val "base url"    $BaseUrl
Write-Val "admin"       $AdminEmail
Write-Val "tenant slug" $TenantSlug
Write-Val "run id"      $stamp
Write-Val "PS version"  $PSVersionTable.PSVersion.ToString()

$health = Invoke-Api -Method GET -Path "/health"
Assert-Status "GET /health" 200 $health
if ($health.Status -ne 200) {
    Write-Host ""
    Write-Host "Server is not answering. Start it, then re-run:" -ForegroundColor Red
    Write-Host "  cd c:\projects\EMC_AUTH\emc-auth-server; go run ./cmd/server" -ForegroundColor Yellow
    exit 1
}

$metricsBefore    = Get-Metrics
$legacyBefore     = Get-MetricValue $metricsBefore "emc_auth_legacy_audience_verifications_total"
$rejectionsBefore = Get-MetricValue $metricsBefore "emc_auth_token_audience_rejections_total"
Write-Val "legacy-verifications" $legacyBefore
Write-Val "audience-rejections"  $rejectionsBefore

if (-not $LegacyToken) {
    Write-Host ""
    Write-Host "   NOTE: no -LegacyToken supplied, so Phase 8 (a pre-#130 token still" -ForegroundColor Yellow
    Write-Host "   verifying) will be SKIPPED. That is the one check this script cannot" -ForegroundColor Yellow
    Write-Host "   synthesise - only the old binary can mint a legacy-shaped token." -ForegroundColor Yellow
}

# ==================================================== PHASE 1 admin / password

Write-Head "PHASE 1 . Admin login (grant: password)"

$login = Invoke-Api -Method POST -Path "/api/v1/auth/login" -Body @{
    email    = $AdminEmail
    password = $AdminPassword
}
Assert-Status "POST /api/v1/auth/login" 200 $login
if ($login.Status -ne 200) {
    Write-Host ""
    Write-Host "Admin login failed - everything below depends on it." -ForegroundColor Red
    Write-Host "Check SEED_ADMIN_PASSWORD in .env, and whether MFA is enrolled for this account." -ForegroundColor Red
    exit 1
}

$adminToken   = $login.Json.access_token
$adminRefresh = $login.Json.refresh_token
$adminClaims  = Show-Claims "ADMIN access token" $adminToken

Assert-Equal "gty" "password"     $adminClaims.gty
Assert-Equal "aud" "emc-auth-api" (($adminClaims.aud) -join ",")
if ($adminClaims.role)        { Pass ("role present: " + $adminClaims.role) }
else                          { Fail "role claim" "empty - RBAC data missing" }
if ($adminClaims.permissions) { Pass ("permissions present: " + $adminClaims.permissions.Count + " entries") }
else                          { Fail "permissions claim" "empty - the admin should hold permissions" }
if ($adminClaims.sid)         { Pass "sid present (session-scoped)" }
else                          { Fail "sid claim" "absent on a password login" }

$basePerms  = $adminClaims.permissions
$baseRole   = $adminClaims.role
$baseScope  = $adminClaims.admin_scope
$baseIssuer = $adminClaims.iss

# ================================================== PHASE 2 refresh rotation

Write-Head "PHASE 2 . Refresh rotation (grant: refresh_token)"

$usedRefresh = $adminRefresh
$refresh = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $adminRefresh }
Assert-Status "POST /api/v1/auth/refresh" 200 $refresh

if ($refresh.Status -eq 200) {
    # The first-party contract, and it is deliberate: for a caller with no app_id
    # the rotated pair goes into HttpOnly cookies and the BODY carries no tokens
    # at all, so portal JavaScript can never read a refresh token. Only an
    # app-scoped caller gets the pair in the body (issue #108) - Phase 6 covers
    # that half. Reading access_token from this body is what made the first run
    # of this script blank out its own admin token and 401 everything after.
    if ($refresh.Json.access_token) {
        Warn "first-party refresh contract" "the body carried an access_token; first-party responses are supposed to withhold the pair and set cookies instead"
    } else {
        Pass "first-party refresh body carries NO tokens (cookies only, by design)"
    }
    if ($refresh.Json.message) { Write-Val "body.message" $refresh.Json.message }
    if ($refresh.Json.expires_in) { Write-Val "body.expires_in" $refresh.Json.expires_in }

    $rotToken   = $refresh.Cookies["emc_access_token"]
    $rotRefresh = $refresh.Cookies["emc_refresh_token"]

    if (-not $rotToken) {
        Fail "rotated access token" "not found in the body or in the emc_access_token cookie - the caller got a 200 with nothing usable, which is the shape of issue #108"
    } else {
        Pass "rotated access token recovered from the emc_access_token cookie"
        $rotClaims = Show-Claims "ROTATED access token" $rotToken

        Assert-Equal "gty" "refresh_token" $rotClaims.gty
        Write-Info "not 'password': the originating grant is not stored on the refresh-token"
        Write-Info "row, which is exactly why refresh_token is a member of HumanGrants."

        Assert-SameSet "permissions across rotation" $basePerms $rotClaims.permissions
        Assert-Equal   "role across rotation"        $baseRole   $rotClaims.role
        Assert-Equal   "admin_scope across rotation" $baseScope  $rotClaims.admin_scope
        Assert-Equal   "iss across rotation"         $baseIssuer $rotClaims.iss

        # Prove the rotated token is functional, not merely well-formed.
        $probe = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $rotToken
        Assert-Status "rotated token -> /tenants" 200 $probe

        $adminToken = $rotToken
        if ($rotRefresh) { $adminRefresh = $rotRefresh }
    }
}

Write-Info "The refresh-replay test is DELIBERATELY not here - see Phase 8b. Replay"
Write-Info "detection revokes the entire session family, so running it on this session"
Write-Info "would sign the admin out and 401 every phase after it."

# ================================================ PHASE 3 RBAC still intact

Write-Head "PHASE 3 . The admin token still reaches every route it used to"

if (-not $adminToken) {
    Fail "Phase 3" "no usable admin token after Phase 2 - every route below would 401 for that reason alone, so the results would be meaningless"
}

$adminRoutes = @(
    @{ Path = "/api/v1/auth/me";      Label = "identity: /auth/me" },
    @{ Path = "/api/v1/tenants";      Label = "admin: /tenants" },
    @{ Path = "/api/v1/applications"; Label = "admin: /applications (apps:read)" },
    @{ Path = "/api/v1/roles";        Label = "admin: /roles (roles:read)" },
    @{ Path = "/api/v1/permissions";  Label = "admin: /permissions" },
    @{ Path = "/api/v1/users";        Label = "admin: /users (users:read)" },
    @{ Path = "/api/v1/audit-logs";   Label = "admin: /audit-logs (audit:read)" },
    @{ Path = "/api/v1/auth/my-tenants"; Label = "identity: /auth/my-tenants" },
    @{ Path = "/oauth/userinfo";      Label = "oidc: /oauth/userinfo (HumanGrants only)" }
)
foreach ($r in $adminRoutes) {
    $resp = Invoke-Api -Method GET -Path $r.Path -BearerToken $adminToken
    Assert-Status $r.Label 200 $resp
}
Write-Info "All 200 means the grant sets in routes.go admit a password token everywhere"
Write-Info "the legacy AudienceAPI did, and RequirePermission still passes for this role."

# ============================================ PHASE 4 client_credentials

Write-Head "PHASE 4 . Machine client (grant: client_credentials)"

$m2mToken = $null
$m2mClientId = $null
$m2mClientSecret = $null

$m2mName = "gty130-m2m-$stamp"
$createM2M = Invoke-Api -Method POST -Path "/api/v1/applications" -BearerToken $adminToken -Body @{
    name     = $m2mName
    app_type = "m2m"
    scopes   = @("apps:read", "users:read")
}
Assert-OneOf "POST /api/v1/applications (m2m)" @(200, 201) $createM2M

if ($createM2M.Status -eq 200 -or $createM2M.Status -eq 201) {
    $m2mClientId     = $createM2M.Json.client_id
    $m2mClientSecret = $createM2M.Json.client_secret
    $m2mAppRowId     = $createM2M.Json.id

    Write-Host ""
    Write-Host "   +-- CREDENTIALS (returned once - copy for Swagger)" -ForegroundColor Magenta
    Write-Val "application row id" $m2mAppRowId
    Write-Val "client_id"          $m2mClientId
    Write-Val "client_secret"      $m2mClientSecret
    Write-Host "   +-- send as Authorization: Basic base64(client_id:client_secret)" -ForegroundColor DarkGray

    $m2m = Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded `
        -Body "grant_type=client_credentials" `
        -BasicUser $m2mClientId -BasicPass $m2mClientSecret
    Assert-Status "POST /oauth/token (client_credentials)" 200 $m2m

    if ($m2m.Status -eq 200) {
        $m2mToken  = $m2m.Json.access_token
        $m2mClaims = Show-Claims "M2M access token" $m2mToken

        Assert-Equal "gty"  "client_credentials" $m2mClaims.gty
        Assert-Equal "aud"  "emc-auth-m2m"       (($m2mClaims.aud) -join ",")
        Assert-Equal "role" "service"            $m2mClaims.role
        Assert-SameSet "permissions = registered scopes" @("apps:read", "users:read") $m2mClaims.permissions
        if (-not $m2m.Json.refresh_token) { Pass "no refresh_token (RFC 6749 4.4.3)" }
        else { Fail "client_credentials refresh token" "one was issued; RFC 6749 4.4.3 says it SHOULD NOT be" }
    }

    $m2mAlias = Invoke-Api -Method POST -Path "/api/v1/auth/token" `
        -Body @{ grant_type = "client_credentials" } `
        -BasicUser $m2mClientId -BasicPass $m2mClientSecret
    Assert-Status "POST /api/v1/auth/token (deprecated JSON alias)" 200 $m2mAlias
    if ($m2mAlias.Status -eq 200) {
        Assert-Equal "alias gty" "client_credentials" (Decode-Jwt $m2mAlias.Json.access_token).gty
    }

    Write-Step "NEGATIVE: wrong client secret"
    $bad = Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded `
        -Body "grant_type=client_credentials" `
        -BasicUser $m2mClientId -BasicPass "definitely-not-the-secret"
    Assert-OneOf "wrong secret is refused" @(400, 401) $bad
    if ($bad.Json -and $bad.Json.error) { Write-Val "error" $bad.Json.error }

    Write-Step "NEGATIVE: unknown client id"
    $bad = Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded `
        -Body "grant_type=client_credentials" `
        -BasicUser "no-such-client-$stamp" -BasicPass "whatever"
    Assert-OneOf "unknown client is refused" @(400, 401) $bad

    Write-Step "NEGATIVE: credentials in the body instead of the Basic header"
    $bad = Invoke-Api -Method POST -Path "/api/v1/auth/token" -Body @{
        grant_type    = "client_credentials"
        client_id     = $m2mClientId
        client_secret = $m2mClientSecret
    }
    Assert-OneOf "body credentials are refused" @(400, 401) $bad
    Write-Info "RFC 6749 2.3.1 puts them in the header. Accepting them in the body would"
    Write-Info "log the secret in every access log and proxy along the way."

    Write-Step "NEGATIVE: unsupported grant_type"
    $bad = Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded `
        -Body "grant_type=implicit" `
        -BasicUser $m2mClientId -BasicPass $m2mClientSecret
    Assert-OneOf "unsupported grant is refused" @(400, 401) $bad
}

# =============================================== PHASE 5 issue #84 boundary

Write-Head "PHASE 5 . Issue #84's boundary, now enforced by gty"

if ($m2mToken) {
    Write-Step "A machine token must NOT act as a user"
    $script:WrongGrantProbes += 3
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $m2mToken
    Assert-Status "m2m -> /auth/me" 401 $r
    if ($r.Json -and $r.Json.code) {
        Assert-Equal "error code (must not name the reason)" "token_invalid" $r.Json.code
        Write-Info "'token_invalid' rather than 'wrong audience': naming it would hand back"
        Write-Info "the oracle the generic body withholds (issue #84)."
    }
    if ($r.Challenge) { Write-Val "WWW-Authenticate" $r.Challenge }

    $r = Invoke-Api -Method GET -Path "/oauth/userinfo" -BearerToken $m2mToken
    Assert-Status "m2m -> /oauth/userinfo" 401 $r

    $r = Invoke-Api -Method GET -Path "/api/v1/auth/my-activity" -BearerToken $m2mToken
    Assert-Status "m2m -> /auth/my-activity" 401 $r

    Write-Step "NEGATIVE: a machine token must not be able to rotate a session"
    $r = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $m2mToken }
    Assert-OneOf "m2m access token used as a refresh token" @(400, 401) $r
    Write-Info "An access token is not a refresh token. A 200 would mean the two are"
    Write-Info "interchangeable and a leaked access token becomes a permanent session."

    Write-Step "But a machine token IS a legitimate admin caller"
    $r = Invoke-Api -Method GET -Path "/api/v1/applications" -BearerToken $m2mToken
    Assert-Status "m2m -> /applications" 200 $r
    Write-Info "If this 401s, the admin route policy lost MachineGrants and every"
    Write-Info "client_credentials integration is broken."

    Write-Step "and it is still bounded by its scopes, not just its grant"
    $r = Invoke-Api -Method GET -Path "/api/v1/audit-logs" -BearerToken $m2mToken
    if ($r.Status -eq 403) {
        Pass "m2m -> /audit-logs -> 403 (gate passed, permission refused)"
        Write-Info "403 not 401 is the important part: the grant gate admitted it and"
        Write-Info "RequirePermission did the refusing. That is RBAC working normally."
    } elseif ($r.Status -eq 200) {
        Fail "m2m -> /audit-logs" "200 - this client has no audit:read scope"
    } else {
        Warn "m2m -> /audit-logs" ("HTTP {0} (expected 403)" -f $r.Status)
    }
} else {
    Write-Info "skipped - no m2m token was obtained in Phase 4"
}

# ============================================ PHASE 6 app-scoped end user

Write-Head "PHASE 6 . App-scoped end user (grant: password, with app_id)"

$userToken = $null
$webClientId = $null
$webClientSecret = $null
$endUserEmail = $null
$endUserPass = "Password123!"

$webName = "gty130-web-$stamp"
$createWeb = Invoke-Api -Method POST -Path "/api/v1/applications" -BearerToken $adminToken -Body @{
    name          = $webName
    app_type      = "web"
    scopes        = @("openid", "profile", "email")
    redirect_uris = @("http://localhost:3000/callback")
}
Assert-OneOf "POST /api/v1/applications (web)" @(200, 201) $createWeb

if ($createWeb.Status -eq 200 -or $createWeb.Status -eq 201) {
    $webClientId     = $createWeb.Json.client_id
    $webClientSecret = $createWeb.Json.client_secret
    $webAppRowId     = $createWeb.Json.id

    Write-Host ""
    Write-Host "   +-- CREDENTIALS (returned once - copy for Swagger)" -ForegroundColor Magenta
    Write-Val "application row id" $webAppRowId
    Write-Val "client_id"          $webClientId
    Write-Val "client_secret"      $webClientSecret
    Write-Host "   +--" -ForegroundColor DarkGray

    $endUserEmail = "gty130-user-$stamp@test.example.com"

    $reg = Invoke-Api -Method POST -Path "/api/v1/auth/apps/register" `
        -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
            email      = $endUserEmail
            password   = $endUserPass
            first_name = "Gty"
            last_name  = "Probe"
        }
    Assert-OneOf "POST /auth/apps/register" @(200, 201) $reg

    $appLogin = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
        -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
            email    = $endUserEmail
            password = $endUserPass
        }
    Assert-Status "POST /auth/apps/login" 200 $appLogin

    if ($appLogin.Status -eq 200) {
        $userToken  = $appLogin.Json.access_token
        $userClaims = Show-Claims "END-USER access token (app-scoped)" $userToken

        Assert-Equal "gty"    "password"   $userClaims.gty
        Assert-Equal "app_id" $webAppRowId $userClaims.app_id
        Write-Info "app_id carries the application boundary today, and NOTHING in any JWT"
        Write-Info "library validates it. That is precisely the gap issue #131 closes."

        Write-Step "The end user reaches identity routes"
        $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $userToken
        Assert-Status "user -> /auth/me" 200 $r

        Write-Step "and is refused admin routes by PERMISSION, not by grant"
        foreach ($p in @("/api/v1/users", "/api/v1/roles", "/api/v1/audit-logs", "/api/v1/applications")) {
            $r = Invoke-Api -Method GET -Path $p -BearerToken $userToken
            if ($r.Status -eq 403) {
                Pass ("user -> {0} -> 403 (gate passed, permission refused)" -f $p)
            } elseif ($r.Status -eq 401) {
                Fail ("user -> {0}" -f $p) "401 - the grant gate refused a valid human token (a #130 regression)"
            } elseif ($r.Status -eq 200) {
                Fail ("user -> {0}" -f $p) "200 - an end user reached an admin route"
            } else {
                Warn ("user -> {0}" -f $p) ("HTTP {0} (expected 403)" -f $r.Status)
            }
        }
        Write-Info "403 not 401 is the most informative result in this script: it proves the"
        Write-Info "grant gate admitted a human token and RBAC did the refusing. A 401 would"
        Write-Info "mean #130 broke the gate; a 200 would mean RBAC broke."

        Write-Step "GET /tenants is unguarded BY DESIGN - so check the filtering instead"
        $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $userToken
        Assert-Status "user -> /tenants" 200 $r
        if ($r.Status -eq 200) {
            $count = 0
            if ($null -ne $r.Json.total) { $count = [int] $r.Json.total }
            elseif ($r.Json.data) { $count = @($r.Json.data).Count }
            if ($count -eq 0) {
                Pass "user -> /tenants returns an EMPTY list (total = 0)"
            } else {
                Fail "user -> /tenants" ("returned {0} tenant(s) to a user with no permissions - ListTenants should return only tenants tied to the caller's own email" -f $count)
            }
            Write-Info "This route carries no RequirePermission on purpose - it is the tenant"
            Write-Info "picker, and ListTenants branches internally: tenant:manage sees every"
            Write-Info "tenant, everyone else sees only tenants tied to their own email. So the"
            Write-Info "protection here is the QUERY, not a guard, and the count is what has to"
            Write-Info "be asserted. Expecting 403 would test a guard that deliberately is not"
            Write-Info "there, and would fail on correct behaviour."
        }

        Write-Step "NEGATIVE: same user, a DIFFERENT application's credentials"
        if ($m2mClientId) {
            $r = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
                -BasicUser $m2mClientId -BasicPass $m2mClientSecret -Body @{
                    email    = $endUserEmail
                    password = $endUserPass
                }
            if ($r.Status -eq 200) {
                Fail "cross-app login" "app B authenticated app A's user - application isolation is broken"
            } else {
                Pass ("cross-app login refused -> HTTP {0}" -f $r.Status)
                Write-Info "An app-scoped user belongs to ONE application. This is the login-time"
                Write-Info "half of the boundary; the token-time half is what #131 adds."
            }
        }

        Write-Step "KNOWN GAP (#131): this app's token reaching another app's API"
        Write-Info "There is nothing to call here yet - no tenant resource server exists in"
        Write-Info "this deployment. The point on record is that the token carries"
        Write-Info "aud=emc-auth-api, byte-identical to every other app's token in this"
        Write-Info "tenant, so a second app validating aud would ACCEPT it. Only app_id"
        Write-Info "differs, and no standard library checks app_id. Closed by #131."
        Warn "per-application audience" "not yet enforced - tracked as issue #131 (expected at this stage)"

        Write-Step "App-scoped refresh returns the pair IN THE BODY (issue #108)"
        $appRef = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $appLogin.Json.refresh_token }
        Assert-Status "app-scoped POST /auth/refresh" 200 $appRef
        if ($appRef.Status -eq 200) {
            if ($appRef.Json.access_token) {
                Pass "app-scoped refresh body carries the token pair"
                $appRotClaims = Show-Claims "APP-SCOPED ROTATED token" $appRef.Json.access_token
                Assert-Equal "gty"    "refresh_token" $appRotClaims.gty
                Assert-Equal "app_id" $webAppRowId    $appRotClaims.app_id
                Write-Info "app_id survives rotation. If it did not, an app-scoped session would"
                Write-Info "silently become tenant-level on its first refresh."
                $userToken = $appRef.Json.access_token
                $appLogin.Json.refresh_token = $appRef.Json.refresh_token
            } else {
                Fail "app-scoped refresh" "200 with no tokens in the body - this is issue #108 exactly, and a client that retries with the old refresh token gets its whole family revoked as a replay"
            }
        }

        Write-Step "Session revocation: logout, then reuse the access token"
        $lo = Invoke-Api -Method POST -Path "/api/v1/auth/logout" -BearerToken $userToken -Body @{
            refresh_token = $appLogin.Json.refresh_token
        }
        Assert-OneOf "POST /auth/logout" @(200, 204) $lo
        $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $userToken
        if ($r.Status -eq 401) {
            Pass "revoked session's access token -> 401 (sid denylist works)"
        } else {
            Warn "revoked session's access token" ("HTTP {0} - expected 401. The sid denylist is what makes one session revocable; if this is 200, a logged-out token still works until it expires." -f $r.Status)
        }
        $r = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $appLogin.Json.refresh_token }
        Assert-OneOf "revoked refresh token" @(400, 401, 403) $r

        # Re-login so later phases have a live user token.
        $appLogin2 = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
            -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
                email    = $endUserEmail
                password = $endUserPass
            }
        if ($appLogin2.Status -eq 200) { $userToken = $appLogin2.Json.access_token }
    }

    # TokenRateLimiter is 5 requests/minute per IP, and the sequence above has
    # already spent that budget, so these three arrive at a limiter rather than at
    # the check they are testing. -SlowNegatives waits the window out so the real
    # status can be asserted; without it a 429 is reported as inconclusive.
    if ($SlowNegatives) {
        Write-Step "Waiting 65s for the per-IP token rate limit window to reset"
        Write-Info "TokenRateLimiter allows 5 requests/minute per IP. Without this wait the"
        Write-Info "three checks below get a 429 instead of the refusal they are testing."
        Start-Sleep -Seconds 65
    }

    Write-Step "NEGATIVE: wrong password, and an unknown email"
    $r = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
        -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
            email = $endUserEmail; password = "WrongPassword123!"
        }
    if ($r.Status -eq 429) {
        Warn "wrong password refused" "HTTP 429 - the per-IP token rate limiter answered first, so the credential check was never reached. The limiter working is not a #130 finding; re-run with -SlowNegatives to assert the real status."
    } else {
        Assert-OneOf "wrong password refused" @(401, 403) $r
    }
    $wrongStatus = $r.Status
    $wrongBody   = $r.Raw

    $r = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
        -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
            email = "nobody-$stamp@test.example.com"; password = $endUserPass
        }
    if ($r.Status -eq 429) {
        Warn "unknown email refused" "HTTP 429 - rate limited before the lookup; see above"
    } else {
        Assert-OneOf "unknown email refused" @(401, 403) $r
    }

    # Only meaningful when BOTH requests actually reached the credential check.
    # Two identical 429s prove nothing about enumeration, and reporting that as a
    # pass would be worse than reporting nothing.
    if ($wrongStatus -eq 429 -or $r.Status -eq 429) {
        Warn "login enumeration" "not asserted - one or both probes were rate limited, and two matching 429s say nothing about whether the real responses differ. Re-run with -SlowNegatives."
    } elseif ($r.Raw -eq $wrongBody -and $r.Status -eq $wrongStatus) {
        Pass "identical response for wrong password and unknown email (no enumeration)"
    } else {
        Warn "login enumeration" "wrong-password and unknown-email responses differ, which lets a caller discover which emails exist"
    }

    Write-Step "NEGATIVE: registering the same email twice in one application"
    $r = Invoke-Api -Method POST -Path "/api/v1/auth/apps/register" `
        -BasicUser $webClientId -BasicPass $webClientSecret -Body @{
            email = $endUserEmail; password = $endUserPass; first_name = "Dup"; last_name = "Probe"
        }
    if ($r.Status -eq 429) {
        Warn "duplicate registration refused" "HTTP 429 - rate limited before the uniqueness check; see above"
    } else {
        Assert-OneOf "duplicate registration refused" @(400, 409) $r
    }
}

# ================================================= PHASE 7 api_key grant

Write-Head "PHASE 7 . API key exchange (grant: api_key)"

$mgmtToken = $null
$keyName = "gty130-key-$stamp"
$createKey = Invoke-Api -Method POST -Path "/api/v1/api-keys" -BearerToken $adminToken -Body @{
    name        = $keyName
    permissions = @("apps:read")
}

if ($createKey.Status -eq 200 -or $createKey.Status -eq 201) {
    Pass ("POST /api/v1/api-keys -> HTTP {0}" -f $createKey.Status)
    $rawKey = $createKey.Json.key
    $keyId  = $createKey.Json.id

    Write-Host ""
    Write-Host "   +-- API KEY (returned once - copy for Swagger)" -ForegroundColor Magenta
    Write-Val "id"  $keyId
    Write-Val "key" $rawKey
    Write-Host "   +-- send as header  X-API-Key: <key>" -ForegroundColor DarkGray

    $mgmt = Invoke-Api -Method POST -Path "/api/v1/auth/management-token" `
        -ExtraHeaders @{ "X-API-Key" = $rawKey }
    Assert-Status "POST /auth/management-token" 200 $mgmt

    if ($mgmt.Status -eq 200) {
        $mgmtToken  = $mgmt.Json.access_token
        $mgmtClaims = Show-Claims "MANAGEMENT access token" $mgmtToken

        Assert-Equal "gty"         "api_key"             $mgmtClaims.gty
        Assert-Equal "aud"         "emc-auth-management" (($mgmtClaims.aud) -join ",")
        Assert-Equal "role"        "api_key"             $mgmtClaims.role
        Assert-Equal "admin_scope" "tenant"              $mgmtClaims.admin_scope
        Write-Info "admin_scope=tenant is deliberate: a key belongs to the tenant, not an app."

        $r = Invoke-Api -Method GET -Path "/api/v1/applications" -BearerToken $mgmtToken
        Assert-Status "management -> /applications" 200 $r

        $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $mgmtToken
        Assert-Status "management -> /auth/me (no user behind it)" 401 $r

        $r = Invoke-Api -Method GET -Path "/api/v1/audit-logs" -BearerToken $mgmtToken
        if ($r.Status -eq 403) { Pass "management -> /audit-logs -> 403 (key has no audit:read)" }
        else { Warn "management -> /audit-logs" ("HTTP {0} (expected 403)" -f $r.Status) }
    }

    Write-Step "NEGATIVE: a bogus API key, and a revoked one"
    $r = Invoke-Api -Method POST -Path "/api/v1/auth/management-token" `
        -ExtraHeaders @{ "X-API-Key" = "not-a-real-key-$stamp" }
    Assert-Status "bogus API key refused" 401 $r

    $r = Invoke-Api -Method POST -Path "/api/v1/auth/management-token"
    Assert-Status "missing API key refused" 401 $r

    if ($keyId) {
        $del = Invoke-Api -Method DELETE -Path ("/api/v1/api-keys/{0}" -f $keyId) -BearerToken $adminToken
        Assert-OneOf "DELETE /api/v1/api-keys/:id" @(200, 204) $del
        $r = Invoke-Api -Method POST -Path "/api/v1/auth/management-token" `
            -ExtraHeaders @{ "X-API-Key" = $rawKey }
        Assert-Status "revoked API key refused" 401 $r
        Write-Info "Revocation must take effect at the exchange. Tokens already minted from"
        Write-Info "the key live out their 15 minutes - that is the documented trade-off."
    }
} else {
    Warn "POST /api/v1/api-keys" ("HTTP {0} - skipping the api_key grant. A 501 means API keys are not configured here." -f $createKey.Status)
}

# ======================================= PHASE 8 tampering and malformed input

Write-Head "PHASE 8 . Tampering: gty must be signature-protected, not just read"

if (-not $adminToken) {
    Warn "Phase 8" "no admin token available - the tampering cases need a real signed token to mutate. Skipping."
}

Write-Step "No credential at all"
$r = Invoke-Api -Method GET -Path "/api/v1/auth/me"
Assert-Status "no Authorization header" 401 $r
if ($r.Json -and $r.Json.code) { Assert-Equal "code" "token_missing" $r.Json.code }

# Read via HttpClient - see Get-Challenge for why Invoke-WebRequest cannot see
# this header at all.
$ch = Get-Challenge "/api/v1/tenants"
if ($ch.Challenge) {
    Write-Val "WWW-Authenticate" $ch.Challenge
    if ($ch.Challenge -notmatch "error=") {
        Pass "JWTRequired route emits a challenge with no error code (RFC 6750 3.1)"
    } else {
        Warn "RFC 6750 3.1" "the challenge names an error although no credential was presented"
    }
} else {
    Fail "RFC 6750 3" "no WWW-Authenticate challenge on a 401 from a JWTRequired route"
}

$ch = Get-Challenge "/api/v1/auth/me"
if (-not $ch.Challenge) {
    Warn "RFC 6750 on /auth/me" "no challenge - /auth/me is guarded by JWTRenew, which returns a bare 401. Pre-existing on master and NOT a #130 regression; the challenge fix for this path is on the unmerged #7b branch."
} else {
    Pass "JWTRenew route also emits a challenge"
}

Write-Step "Malformed and garbage tokens"
foreach ($bad in @("abc", "a.b.c", "", "Bearer", "null")) {
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -RawAuthHeader ("Bearer " + $bad)
    Assert-Status ("garbage token '{0}'" -f $bad) 401 $r
}

if ($adminToken) {
    Write-Step "Tampered signature"
    $parts = $adminToken.Split('.')
    if ($parts.Count -eq 3 -and $parts[2].Length -gt 4) {
        $flipped = $parts[2].Substring(0, $parts[2].Length - 4)
        if ($parts[2].EndsWith("AAAA")) { $flipped += "BBBB" } else { $flipped += "AAAA" }
        $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken ("{0}.{1}.{2}" -f $parts[0], $parts[1], $flipped)
        Assert-Status "tampered signature" 401 $r
    }
}

if ($mgmtToken) {
    Write-Step "PRIVILEGE ESCALATION ATTEMPT: rewrite gty on a management token"
    $forged = Set-JwtClaim $mgmtToken "gty" "password"
    Write-Val "forged gty" (Decode-Jwt $forged).gty
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $forged
    Assert-Status "gty rewritten api_key -> password" 401 $r
    Write-Info "This is the attack #130 has to be immune to. gty decides the route policy,"
    Write-Info "so if a rewritten gty were honoured, any token could claim any grant. It is"
    Write-Info "inside the signed payload, so the edit invalidates the signature."
}

if ($m2mToken) {
    Write-Step "PRIVILEGE ESCALATION ATTEMPT: machine token claiming to be human"
    $forged = Set-JwtClaim $m2mToken "gty" "password"
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $forged
    Assert-Status "gty rewritten client_credentials -> password" 401 $r

    Write-Step "DOWNGRADE ATTEMPT: strip gty to fall into the legacy fallback"
    $forged = Remove-JwtClaim $m2mToken "gty"
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $forged
    Assert-Status "gty removed (legacy-shape forgery)" 401 $r
    Write-Info "The fallback widens one aud value into a whole grant set, so removing gty"
    Write-Info "is the obvious way to try to widen a token. Also signature-protected."

    Write-Step "Rewriting aud, role, and permissions"
    foreach ($case in @(
        @{ Name = "aud";         Value = "emc-auth-api" },
        @{ Name = "role";        Value = "super_admin" },
        @{ Name = "admin_scope"; Value = "tenant" }
    )) {
        $forged = Set-JwtClaim $m2mToken $case.Name $case.Value
        $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $forged
        Assert-Status ("rewritten {0}={1}" -f $case.Name, $case.Value) 401 $r
    }
}

if ($adminToken) {
    Write-Step "alg=none substitution"
    $hdr = ConvertTo-Base64Url '{"alg":"none","typ":"JWT"}'
    $noneToken = "{0}.{1}." -f $hdr, $adminToken.Split('.')[1]
    $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $noneToken
    Assert-Status "alg=none unsigned token" 401 $r
    Write-Info "Two independent algorithm pins guard this - the parser option and the"
    Write-Info "keyfunc's own method check. Both must list an algorithm for it to be used."

    Write-Step "Bearer header shapes that must still work"
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -RawAuthHeader ("bearer " + $adminToken)
    Assert-Status "lowercase 'bearer' scheme" 200 $r
    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -RawAuthHeader $adminToken
    Assert-Status "raw JWT with no scheme (Swagger apiKey flow)" 200 $r
}

# =============================== PHASE 8b destructive session tests

Write-Head "PHASE 8b . Replay detection and family revocation (throwaway session)"

# Its own login, because everything here is destructive by design: replay
# detection revokes the whole family, so the session used for it must be one
# nothing else depends on.
$throw = Invoke-Api -Method POST -Path "/api/v1/auth/login" -Body @{
    email    = $AdminEmail
    password = $AdminPassword
}
Assert-Status "throwaway login" 200 $throw

if ($throw.Status -eq 200) {
    $thAccess  = $throw.Json.access_token
    $thRefresh = $throw.Json.refresh_token

    $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $thAccess
    Assert-Status "throwaway token works before rotation" 200 $r

    $rot = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $thRefresh }
    Assert-Status "rotate the throwaway session" 200 $rot
    $thRotated = $rot.Cookies["emc_access_token"]

    Write-Step "NEGATIVE: replay the consumed refresh token"
    $replay = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $thRefresh }
    Assert-OneOf "replayed refresh token is refused" @(401, 403) $replay
    if ($replay.Json -and $replay.Json.error) { Write-Val "error" $replay.Json.error }
    Write-Info "Rotation revokes the presented token. A 200 here would make one stolen"
    Write-Info "refresh token permanent access."

    Write-Step "and the replay must take the WHOLE family down with it"
    if ($thRotated) {
        $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $thRotated
        if ($r.Status -eq 401) {
            $code = ""
            if ($r.Json -and $r.Json.code) { $code = $r.Json.code }
            Pass ("post-replay access token refused -> 401 " + $code)
            Write-Info "session_revoked, not token_invalid: the signature is still perfectly"
            Write-Info "good, so only the sid denylist can refuse this. A replay anywhere in"
            Write-Info "the family kills every live token in it - which is why this test needs"
            Write-Info "its own session, and why it is the last thing this phase does."
        } else {
            Fail "post-replay access token" ("HTTP {0} - a live access token survived a detected replay" -f $r.Status)
        }
    }
}

# ============================================ PHASE 9 the legacy fallback

Write-Head "PHASE 9 . Pre-#130 token still verifies (the non-breaking claim)"

if ($LegacyToken) {
    $legacyClaims = Show-Claims "LEGACY token (minted by the previous build)" $LegacyToken

    if (-not $legacyClaims.gty) {
        Pass "the supplied token carries no gty - it really is the legacy shape"
    } else {
        Fail "legacy token shape" ("it carries gty='{0}', so it came from the NEW build. Phase 9 proves nothing with it." -f $legacyClaims.gty)
    }

    $r = Invoke-Api -Method GET -Path "/api/v1/auth/me" -BearerToken $LegacyToken
    if ($r.Status -eq 200) {
        Pass "legacy token -> /auth/me -> 200"
    } elseif ($r.Status -eq 401 -and $r.Json -and $r.Json.code -eq "token_expired") {
        Warn "legacy token" "EXPIRED (access tokens live 15 minutes) - inconclusive, not a failure. Capture a fresh one from the old build and re-run."
    } else {
        Fail "legacy token -> /auth/me" ("HTTP {0} - deploying this would sign out every live session" -f $r.Status)
    }

    $r = Invoke-Api -Method GET -Path "/api/v1/tenants" -BearerToken $LegacyToken
    if ($r.Status -eq 200) { Pass "legacy token -> /tenants -> 200" }
    elseif ($r.Status -eq 401 -and $r.Json -and $r.Json.code -eq "token_expired") { Warn "legacy token on /tenants" "expired - inconclusive" }
    else { Fail "legacy token -> /tenants" ("HTTP {0}" -f $r.Status) }
} else {
    Write-Info "SKIPPED - no -LegacyToken supplied."
    Write-Host ""
    Write-Host "   To run this check properly:" -ForegroundColor Yellow
    Write-Host "     1. git stash            (or check out master)" -ForegroundColor Gray
    Write-Host "     2. start the server, POST /api/v1/auth/login, copy access_token" -ForegroundColor Gray
    Write-Host "     3. restore the #130 branch, restart, then run:" -ForegroundColor Gray
    Write-Host "        .\scripts\verify-issue-130.ps1 -LegacyToken '<that token>'" -ForegroundColor Gray
    Write-Host "     Do it within 15 minutes - access tokens expire." -ForegroundColor Gray
}

# ========================================== PHASE 10 cross-tenant isolation

Write-Head "PHASE 10 . Cross-tenant isolation"

if ($IncludeCrossTenant) {
    $tSlug = "gty130t$stamp".ToLower() -replace '[^a-z0-9]', ''
    if ($tSlug.Length -gt 30) { $tSlug = $tSlug.Substring(0, 30) }

    # owner_email is required alongside name and slug - CreateTenant rejects the
    # request outright without it.
    $ct = Invoke-Api -Method POST -Path "/api/v1/tenants" -BearerToken $adminToken -Body @{
        name         = "gty130-tenant-$stamp"
        slug         = $tSlug
        display_name = "GTY130 Probe Tenant"
        owner_email  = "gty130-owner-$stamp@test.example.com"
    }
    Assert-OneOf "POST /api/v1/tenants" @(200, 201) $ct

    if ($ct.Status -eq 200 -or $ct.Status -eq 201) {
        # The id lives under .tenant - CreateTenantResult wraps it.
        $ctId = $null
        if ($ct.Json.tenant -and $ct.Json.tenant.id) { $ctId = $ct.Json.tenant.id }
        elseif ($ct.Json.id) { $ctId = $ct.Json.id }

        Write-Val "tenant id"   $ctId
        Write-Val "tenant slug" $tSlug

        if (-not $ctId) {
            Fail "tenant B id" "could not be read from the CreateTenant response. Without it the URL below becomes /api/v1/tenants//applications, and an empty :tid falls back to the CALLER's tenant - so everything after would be built in tenant A and this phase would silently test nothing."
            $ctId = $null
        }
    }

    if ($ctId) {

        $ctApp = Invoke-Api -Method POST -Path ("/api/v1/tenants/{0}/applications" -f $ctId) -BearerToken $adminToken -Body @{
            name     = "gty130-crossapp-$stamp"
            app_type = "web"
            scopes   = @("openid")
            redirect_uris = @("http://localhost:3000/cb")
        }
        if ($ctApp.Status -ne 200 -and $ctApp.Status -ne 201) {
            Warn "cross-tenant application" ("HTTP {0} - the tenant-scoped path may differ in this build; skipping the rest of Phase 10" -f $ctApp.Status)
        } else {
            $ctClientId     = $ctApp.Json.client_id
            $ctClientSecret = $ctApp.Json.client_secret
            $ctEmail = "gty130-ctuser-$stamp@test.example.com"
            Write-Val "tenant B client_id" $ctClientId

            $r = Invoke-Api -Method POST -Path "/api/v1/auth/apps/register" `
                -BasicUser $ctClientId -BasicPass $ctClientSecret -Body @{
                    email = $ctEmail; password = $endUserPass; first_name = "Cross"; last_name = "Tenant"
                }
            Assert-OneOf "register user in tenant B" @(200, 201) $r

            $ctLogin = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
                -BasicUser $ctClientId -BasicPass $ctClientSecret -Body @{
                    email = $ctEmail; password = $endUserPass
                }
            Assert-Status "login in tenant B" 200 $ctLogin

            if ($ctLogin.Status -eq 200) {
                $ctClaims = Show-Claims "TENANT-B user token" $ctLogin.Json.access_token
                Assert-Equal "gty" "password" $ctClaims.gty

                # Checked before anything else is concluded: if this token names
                # tenant A, the application was created in the wrong tenant and
                # every comparison below is between a tenant and itself.
                if ("$($ctClaims.tenant_id)" -eq "$ctId") {
                    Pass ("tenant B token names tenant B (tenant_id = {0})" -f $ctId)

                    if ($ctClaims.iss -ne $baseIssuer) {
                        Pass ("per-tenant issuer differs: '{0}' vs '{1}'" -f $ctClaims.iss, $baseIssuer)
                        Write-Info "Each tenant has its own iss and its own signing keys (#7a, #95)."
                        Write-Info "The TENANT boundary is real. The APPLICATION boundary is not - #131."
                    } else {
                        Warn "per-tenant issuer" "both tenants share iss despite different tenant_ids - check JWT_ALLOW_LEGACY_ISSUER and the TenantIssuerResolver"
                    }
                } else {
                    Fail "tenant B token" ("names tenant {0}, not tenant {1} - the application was created in the wrong tenant, so nothing below compares two different tenants" -f $ctClaims.tenant_id, $ctId)
                }

                $r = Invoke-Api -Method GET -Path ("/api/v1/tenants/{0}/users" -f $ctId) -BearerToken $userToken
                Assert-OneOf "tenant-A user reading tenant B's users" @(401, 403, 404) $r
                Write-Info "A token names its own tenant and that claim is authoritative. Reaching"
                Write-Info "another tenant's data must be refused whatever the path says."

                $r = Invoke-Api -Method GET -Path ("/api/v1/tenants/{0}/applications" -f $ctId) -BearerToken $userToken
                Assert-OneOf "tenant-A user reading tenant B's applications" @(401, 403, 404) $r
            }
        }
    }
} else {
    Write-Info "SKIPPED - pass -IncludeCrossTenant to create a second tenant and prove"
    Write-Info "the tenant boundary (separate iss and signing keys) is still enforced."
}

# ================================================================ PHASE 11 metrics

Write-Head "PHASE 11 . Metrics"

$metricsAfter    = Get-Metrics
$legacyAfter     = Get-MetricValue $metricsAfter "emc_auth_legacy_audience_verifications_total"
$rejectionsAfter = Get-MetricValue $metricsAfter "emc_auth_token_audience_rejections_total"

Write-Val "legacy-verifications" ("{0} -> {1}" -f $legacyBefore, $legacyAfter)
Write-Val "audience-rejections"  ("{0} -> {1}" -f $rejectionsBefore, $rejectionsAfter)

if ($script:WrongGrantProbes -eq 0) {
    Warn "emc_auth_token_audience_rejections_total" "not asserted - no wrong-grant request was sent this run (Phase 5 did not run), so 0 -> 0 is the correct result rather than a dead counter"
} elseif ($rejectionsAfter -gt $rejectionsBefore) {
    Pass "audience rejections were counted (Phase 5's refusals are visible in Prometheus)"
} else {
    Fail "emc_auth_token_audience_rejections_total" ("did not move despite {0} wrong-grant requests - the counter is not wired on that path" -f $script:WrongGrantProbes)
}
Write-Info "Only grant/audience refusals count here. The Phase 8 forgeries fail on the"
Write-Info "SIGNATURE, which is a different rejection and deliberately not counted."

if ($LegacyToken) {
    if ($legacyAfter -gt $legacyBefore) {
        Pass ("legacy fallback was counted ({0} -> {1})" -f $legacyBefore, $legacyAfter)
        Write-Info "This counter is the gate before #132. A flat zero would let the cutover"
        Write-Info "ship on no evidence - the trap CLAUDE.md deferred #12 is stuck in."
    } else {
        Fail "emc_auth_legacy_audience_verifications_total" "did not increment although a legacy token verified - the metric is dead"
    }
} else {
    if ($legacyAfter -eq 0) {
        Pass "legacy counter is 0 - correct: every token in this run carries gty"
    } else {
        Warn "legacy counter" ("is {0} - something else on this server is still presenting legacy tokens. Check the client_id labels below to see who." -f $legacyAfter)
    }
}

Write-Host ""
foreach ($line in ($metricsAfter -split "`n")) {
    if ($line -match "^emc_auth_(legacy_audience_verifications|token_audience_rejections)_total") {
        Write-Host ("   " + $line.Trim()) -ForegroundColor DarkYellow
    }
}

# ==================================================== PHASE 12 database checks

Write-Head "PHASE 12 . Database verification"

if ($SkipSql) {
    Write-Info "skipped (-SkipSql)"
} else {
    $ping = Invoke-Psql "SELECT 1;"
    if ($ping -notmatch "1") {
        Warn "psql" ("could not reach Postgres through docker exec. Output: {0}" -f $ping)
        Write-Host "   Find the container name with:  docker ps --format '{{.Names}}'" -ForegroundColor Yellow
        Write-Host "   Then re-run with:  -PgContainer <name>" -ForegroundColor Yellow
    } else {
        Pass ("psql reachable via container '{0}'" -f $PgContainer)

        Write-Step "Schema version (must be 86 - #130 adds no migration)"
        $ver = (Invoke-Psql "SELECT version_id FROM goose_db_version ORDER BY id DESC LIMIT 1;").Trim()
        Assert-Equal "goose version_id" "86" $ver

        Write-Step "JWT permissions vs the database's own answer"
        # deleted_at IS NULL, NOT is_deleted: the boolean was dropped in migration
        # 00021 in favour of a timestamp. CLAUDE.md's non-negotiable #5 still names
        # the boolean and is therefore stale - worth fixing in the brief.
        $sql = "SELECT COALESCE(STRING_AGG(name, ',' ORDER BY name), '') FROM (" +
               "SELECT p.name FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id " +
               "JOIN users u ON u.role_id = rp.role_id WHERE u.email = '" + $AdminEmail + "' AND u.deleted_at IS NULL " +
               "UNION " +
               "SELECT p.name FROM permissions p JOIN user_permissions up ON up.permission_id = p.id " +
               "JOIN users u2 ON u2.id = up.user_id AND u2.tenant_id = up.tenant_id " +
               "WHERE u2.email = '" + $AdminEmail + "' AND u2.deleted_at IS NULL) x;"
        $dbPerms  = (Invoke-Psql $sql).Trim()
        $jwtPerms = ""
        if ($basePerms) { $jwtPerms = (($basePerms | Sort-Object) -join ",") }
        Write-Val "from database" $dbPerms
        Write-Val "from JWT"      $jwtPerms
        if ($dbPerms -eq $script:PsqlError) {
            Warn "admin permissions (DB == JWT)" "the query failed - see the psql error above"
        } else {
            Assert-Equal "admin permissions (DB == JWT)" $dbPerms $jwtPerms
        }
        Write-Info "Same UNION that loadPermissions() runs. A mismatch means the claim and"
        Write-Info "the source of truth have diverged - the real 'did RBAC break' question."

        Write-Step "Role"
        $roleRow = (Invoke-Psql ("SELECT COALESCE(r.name,'(none)') FROM users u LEFT JOIN roles r ON r.id = u.role_id WHERE u.email = '" + $AdminEmail + "' AND u.deleted_at IS NULL LIMIT 1;")).Trim()
        if ($roleRow -eq $script:PsqlError) {
            Warn "admin role (DB == JWT)" "the query failed - see the psql error above"
        } else {
            Assert-Equal "admin role (DB == JWT)" $roleRow $baseRole
        }

        Write-Step "admin_grants (drives admin_scope / admin_apps)"
        Write-Info "Empty is normal here: the seeded super_admin holds tenant:manage as an"
        Write-Info "RBAC permission and needs no admin_grants row, which is why admin_scope"
        Write-Info "is absent from its token."
        Write-Host (Invoke-Psql "SELECT u.email || ' | ' || t.slug || ' | ' || g.admin_role || ' | app=' || COALESCE(g.application_id::text,'ALL') || ' | activated=' || (g.activated_at IS NOT NULL)::text FROM admin_grants g JOIN users u ON u.id=g.user_id JOIN tenants t ON t.id=g.tenant_id WHERE g.deleted_at IS NULL ORDER BY g.tenant_id;") -ForegroundColor DarkYellow

        Write-Step "Objects this run created"
        Write-Host (Invoke-Psql "SELECT id || ' | ' || client_id || ' | ' || COALESCE(name,'') || ' | ' || app_type || ' | first_party=' || first_party::text || ' | scopes=' || scopes::text FROM oauth_clients WHERE name LIKE 'gty130-%' AND deleted_at IS NULL ORDER BY id;") -ForegroundColor DarkYellow

        Write-Step "Live refresh tokens (the population the fallback protects)"
        Write-Host (Invoke-Psql "SELECT 'live=' || COUNT(*) || ' users=' || COUNT(DISTINCT user_id) || ' last_expiry=' || COALESCE(MAX(expires_at)::text,'-') FROM refresh_tokens WHERE revoked_at IS NULL AND expires_at > NOW();") -ForegroundColor DarkYellow

        Write-Step "Sessions revoked by this run's logout"
        Write-Host (Invoke-Psql "SELECT 'revoked=' || COUNT(*) FROM user_sessions WHERE revoked_at IS NOT NULL AND revoked_at > NOW() - INTERVAL '10 minutes';") -ForegroundColor DarkYellow

        Write-Step "Duplicate emails across tenants (CLAUDE.md deferred #17)"
        $dupes = (Invoke-Psql "SELECT COALESCE(STRING_AGG(email, ', '), '(none)') FROM (SELECT email FROM users WHERE deleted_at IS NULL GROUP BY email HAVING COUNT(*) > 1) d;").Trim()
        if ($dupes -eq "(none)") {
            Pass "no email is reused across tenants"
        } else {
            Warn "duplicate emails" ("these exist in more than one tenant and will fail /auth/login with 'invalid credentials' for reasons unrelated to #130: {0}" -f $dupes)
        }

        Write-Step "No audience column yet (#131 has not run)"
        $audCol = (Invoke-Psql "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'oauth_clients' AND column_name = 'audience';").Trim()
        Assert-Equal "oauth_clients.audience absent" "0" $audCol

        Write-Step "Audit trail recorded this run"
        Write-Host (Invoke-Psql "SELECT action || ' x' || COUNT(*) FROM audit_logs WHERE created_at > NOW() - INTERVAL '10 minutes' GROUP BY action ORDER BY COUNT(*) DESC LIMIT 15;") -ForegroundColor DarkYellow
        Write-Info "Auditing is fire-and-forget by design, so an empty result is not a failure"
        Write-Info "- but a login with no audit row is worth knowing about."
    }
}

# ========================================================================= SUMMARY

Write-Head "SUMMARY"

Write-Host ""
Write-Host ("   Passed:   {0}" -f $script:PassCount) -ForegroundColor Green
if ($script:WarnCount -gt 0) { Write-Host ("   Warnings: {0}" -f $script:WarnCount) -ForegroundColor Yellow }
if ($script:FailCount -gt 0) { Write-Host ("   Failed:   {0}" -f $script:FailCount) -ForegroundColor Red }
else                         { Write-Host  "   Failed:   0" -ForegroundColor Green }

if ($script:FailCount -gt 0) {
    Write-Host ""
    Write-Host "   FAILURES" -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host ("     - " + $f) -ForegroundColor Red }
}
if ($script:WarnCount -gt 0) {
    Write-Host ""
    Write-Host "   WARNINGS (not regressions - known gaps or inconclusive checks)" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) { Write-Host ("     - " + $w) -ForegroundColor DarkYellow }
}

Write-Host ""
if ($script:FailCount -eq 0) {
    Write-Host "   +--------------------------------------------------------------+" -ForegroundColor Green
    Write-Host "   |  ISSUE #130 VERIFIED                                         |" -ForegroundColor Green
    Write-Host "   |  gty is minted on every path exercised; aud is unchanged;     |" -ForegroundColor Green
    Write-Host "   |  roles, permissions and every 401/403 match the old shape;    |" -ForegroundColor Green
    Write-Host "   |  a rewritten or stripped gty is refused.                      |" -ForegroundColor Green
    Write-Host "   +--------------------------------------------------------------+" -ForegroundColor Green
} else {
    Write-Host "   VERIFICATION INCOMPLETE - see the failures above." -ForegroundColor Red
}

if (-not $LegacyToken) {
    Write-Host ""
    Write-Host "   Still owed: Phase 9. Until a pre-#130 token has been replayed against" -ForegroundColor Yellow
    Write-Host "   this build, 'non-breaking' is untested - and that is #130's whole claim." -ForegroundColor Yellow
}
if (-not $IncludeCrossTenant) {
    Write-Host "   Also skipped: Phase 10 (cross-tenant). Re-run with -IncludeCrossTenant." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "   Cleanup for this run's throwaway objects (optional):" -ForegroundColor DarkGray
Write-Host "     UPDATE oauth_clients SET deleted_at = NOW() WHERE name LIKE 'gty130-%';" -ForegroundColor DarkGray
Write-Host "     UPDATE api_keys      SET revoked_at = NOW() WHERE name LIKE 'gty130-%';" -ForegroundColor DarkGray
Write-Host "     UPDATE users         SET deleted_at = NOW() WHERE email LIKE 'gty130-%';" -ForegroundColor DarkGray
Write-Host "     UPDATE tenants       SET deleted_at = NOW() WHERE name LIKE 'gty130-%';" -ForegroundColor DarkGray
Write-Host ""

exit $(if ($script:FailCount -gt 0) { 1 } else { 0 })
