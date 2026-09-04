<#
.SYNOPSIS
    End-to-end verification for issue #131 (per-application audience with
    explicit client grants).

.DESCRIPTION
    Drives the running server over HTTP exactly as an integrator would, then
    verifies the same facts against Postgres. Prints every token's decoded
    claims so they can be cross-checked on jwt.io, and ends with a PASS / FAIL
    summary.

    The phases run BEST CASE FIRST and WORST CASE LAST, deliberately:

      Phases 1-6    the happy paths, in the order a real deployment meets them.
                    A failure here means the feature does not work.
      Phases 7-11   the negative paths - what must be REFUSED. A failure here
                    means the feature works but does not protect anything, which
                    is worse, because it looks fine on a dashboard.
      Phases 12-13  the states that only appear under enforcement or after a
                    delete. These are the ones that bite in production weeks
                    later, not on the day of the deploy.
      Phase 14      the database, because a claim about a column is not evidence
                    about a column.

    WHAT IT IS ACTUALLY PROVING. Not "aud changed" - that is one line of the
    output. The claims worth the run are:

      * An audience cannot be obtained without a grant, and the refusal for
        "not granted" is BYTE-IDENTICAL to the refusal for "does not exist".
        Any difference is an enumeration oracle for every tenant's API list.
      * An audience is never recycled, so a grant or token cannot be silently
        redirected to a different application.
      * A refresh cannot move its own audience.
      * A client that asks for NOTHING keeps working exactly as before. This is
        the whole compatibility claim, and it is what phases 3 and 4 exist for.

    ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less UTF-8 file as
    cp1252, where an em dash decodes to a character the parser treats as a string
    delimiter. Keep it ASCII and it runs on 5.1 and 7 alike.

.EXAMPLE
    .\scripts\verify-issue-131.ps1

.EXAMPLE
    .\scripts\verify-issue-131.ps1 -IncludeCrossTenant -IncludeEnforcement

.NOTES
    Creates only throwaway objects, all prefixed "aud131-": several OAuth
    applications, one end user, and (with -IncludeCrossTenant) a second tenant.
    Cleanup SQL is printed at the end.

    IMPORTANT: audience identifiers are NEVER released, by design (migration
    00087 uses a FULL unique index, not a partial one). So the throwaway
    applications this script creates permanently reserve their audiences even
    after the cleanup SQL runs. That is the feature working, not a leak - every
    name is stamped with a run id so re-runs never collide.
#>

[CmdletBinding()]
param(
    [string] $BaseUrl       = "http://localhost:9090",
    [string] $AdminEmail    = "admin@emc.local",
    [string] $AdminPassword = "ChangeMe123!",
    [string] $TenantSlug    = "emc",

    # Only needed if METRICS_TOKEN is set in your .env.
    [string] $MetricsToken  = "",

    # Creates a second tenant to prove a client cannot be granted another
    # tenant's audience. Adds ~5s.
    [switch] $IncludeCrossTenant,

    # Flips require_audience on a throwaway client to prove enforcement refuses
    # a token it cannot resolve an audience for. Touches only objects this run
    # created.
    [switch] $IncludeEnforcement,

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
    Write-Val "aud (NEW in #131)"  (($c.aud) -join ", ")
    Write-Val "gty (from #130)"    $gty
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
# ---------------------------------------------------------------- #131 helpers

# Assert-SameBody is the anti-enumeration assertion, and it is the single most
# important check in this script.
#
# RFC 8707 gives ONE error code for a refused audience, and the response for
# "you hold no grant for this" must be indistinguishable from the response for
# "no such audience exists anywhere". If they differ by so much as a word, any
# client with credentials can enumerate every audience in the deployment by
# diffing the errors - a map of every tenant's internal API surface.
#
# Compared as raw bytes, not as parsed JSON: a difference in key ORDER or
# whitespace is just as distinguishable to an attacker as a difference in words.
function Assert-SameBody($label, $responses) {
    $bodies = @()
    foreach ($r in $responses) { $bodies += [string] $r.Raw }
    $statuses = @()
    foreach ($r in $responses) { $statuses += [string] $r.Status }

    # @(...) is load-bearing. Sort-Object -Unique returns a bare STRING when
    # exactly one value survives, and indexing [0] into a string yields its
    # first CHARACTER - which is how a passing assertion printed "HTTP 4" and
    # "body: {" instead of the status and body it had actually compared.
    $distinctBodies  = @($bodies    | Sort-Object -Unique)
    $distinctStatus  = @($statuses  | Sort-Object -Unique)

    if (@($distinctBodies).Count -eq 1 -and @($distinctStatus).Count -eq 1) {
        Pass ("{0}: all {1} refusals byte-identical (HTTP {2})" -f $label, $bodies.Count, $distinctStatus[0])
        Write-Info ("body: " + $distinctBodies[0])
    } else {
        Fail $label ("refusals DIFFER, which is an enumeration oracle. statuses=[{0}] bodies=[{1}]" -f `
            (($distinctStatus) -join " | "), (($distinctBodies) -join " || "))
    }
}

# Get-Aud returns the single aud value on a token, or a marker for the two
# states that are not one value. Both markers are deliberate: "(ABSENT)" is a
# legal state for a client with no stored audience (#131 s7 case 4), while
# "(MULTI: ...)" must never occur, because a multi-valued aud means "valid at
# all of these" - the shared audience this issue exists to abolish.
function Get-Aud([string] $token) {
    $c = Decode-Jwt $token
    if (-not $c) { return "(UNDECODABLE)" }
    $aud = @($c.aud)
    if ($aud.Count -eq 0 -or -not $c.aud) { return "(ABSENT)" }
    if ($aud.Count -gt 1) { return ("(MULTI: " + ($aud -join ",") + ")") }
    return [string] $aud[0]
}

function Assert-Aud($label, $expected, $token) {
    $got = Get-Aud $token
    if ($got -eq $expected) { Pass ("{0} aud = {1}" -f $label, $got) }
    else { Fail ("{0} aud" -f $label) ("expected '{0}', got '{1}'" -f $expected, $got) }
}

# New-App creates a throwaway application and returns its credentials plus the
# audience the server assigned it. The audience is returned at CREATION and
# never again - there is no update path - so a script that does not capture it
# here cannot recover it except from the database.
function New-App($token, $name, $type, $scopes) {
    $body = @{ name = $name; app_type = $type }
    if ($scopes) { $body["scopes"] = $scopes }
    $r = Invoke-Api -Method POST -Path "/api/v1/applications" -BearerToken $token -Body $body
    if ($r.Status -ne 200 -and $r.Status -ne 201) {
        Fail ("create application '{0}'" -f $name) ("HTTP {0}: {1}" -f $r.Status, $r.Raw)
        return $null
    }
    return [pscustomobject]@{
        Id       = $r.Json.id
        ClientId = $r.Json.client_id
        Secret   = $r.Json.client_secret
        Audience = $r.Json.audience
        Name     = $name
    }
}

# Get-M2MToken performs a client_credentials exchange, optionally naming an
# audience. $null audience means the parameter is OMITTED entirely, which is
# the case that must keep working unchanged - not the same as sending an empty
# one.
function Get-M2MToken($app, $audience, $useResourceParam) {
    $form = "grant_type=client_credentials"
    if ($audience) {
        $key = "audience"
        if ($useResourceParam) { $key = "resource" }
        $form = $form + "&" + $key + "=" + [uri]::EscapeDataString($audience)
    }
    return Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded -Body $form `
        -BasicUser $app.ClientId -BasicPass $app.Secret
}

$script:Cleanup = New-Object System.Collections.ArrayList

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

# The migration must be applied, or every phase below fails for one boring
# reason and the real signal is buried. Checked first, and by version rather
# than by probing a column, because that is the answer an operator needs.
if (-not $SkipSql) {
    $ver = Invoke-Psql "SELECT max(version_id) FROM goose_db_version;"
    if ($ver -eq $script:PsqlError) {
        Warn "goose version" "could not read it (is the postgres container named '$PgContainer'?)"
    } elseif ([int] $ver -ge 87) {
        Pass ("migration 00087 applied (goose at {0})" -f $ver)
    } else {
        Fail "migration 00087" ("goose is at {0}; #131 needs 87. Start the server against this database to apply it." -f $ver)
        Write-Host ""
        Write-Host "Nothing below can pass without the migration. Stopping." -ForegroundColor Red
        exit 1
    }
}

# Baseline for phase 14. Leftovers from a previous run are normal - the cleanup
# SQL is optional and every object is stamped with a run id - so phase 14 must
# assert the DELTA this run caused, not an absolute count. Without this, the
# second run of the script warns about the pre-#131 row the FIRST run created.
$script:BareBefore = 0
if (-not $SkipSql) {
    $b = Invoke-Psql "SELECT count(*) FROM oauth_clients WHERE deleted_at IS NULL AND audience IS NULL;"
    if ($b -ne $script:PsqlError -and $b) { $script:BareBefore = [int] $b }
}
Write-Val "apps w/o audience (before)" $script:BareBefore

$metricsBefore = Get-Metrics
$denialsBefore = Get-MetricValue $metricsBefore "emc_auth_audience_grant_denials_total"
$legacyBefore  = Get-MetricValue $metricsBefore "emc_auth_legacy_audience_verifications_total"
Write-Val "audience-grant-denials" $denialsBefore
Write-Val "legacy-verifications"   $legacyBefore
Write-Info "The legacy counter is the #132 gate and is NOT this script's business."
Write-Info "It is printed so a run leaves a record of it; it must be flat at zero"
Write-Info "for a full 30-day refresh lifetime before #132 removes the fallback."

# ====================================== PHASE 1 (BEST CASE) the admin console

Write-Head "PHASE 1 . BEST CASE: the console login the server must assign an audience for"

# This is issue #131 s7 case 3, and it is not optional.
#
# The admin console signs in with an email and a password. It carries no
# client_id, never calls /oauth/token, and therefore CANNOT supply an audience.
# If the server did not assign one, enforcement (#132) would lock every operator
# out of their own console - which is exactly how this feature could ship
# looking correct and take the deployment down a week later.
$login = Invoke-Api -Method POST -Path "/api/v1/auth/login" -Body @{
    email    = $AdminEmail
    password = $AdminPassword
}
Assert-Status "POST /api/v1/auth/login" 200 $login
if ($login.Status -ne 200) {
    Write-Host ""
    Write-Host "Admin login failed - everything below depends on it." -ForegroundColor Red
    Write-Host "Check SEED_ADMIN_PASSWORD in .env, and whether MFA is enrolled." -ForegroundColor Red
    exit 1
}

$adminToken   = $login.Json.access_token
$adminRefresh = $login.Json.refresh_token
$adminClaims  = Show-Claims "ADMIN access token (no client_id)" $adminToken

Assert-Aud "console login" "api://emc-auth" $adminToken
Assert-Equal "gty (unchanged by #131)" "password" $adminClaims.gty
Write-Info "aud was 'emc-auth-api' before #131. The token type did not vanish - it"
Write-Info "moved to gty in #130, which is why aud was free to become a real"
Write-Info "audience here. Nothing in this server reads aud to make a decision."

# The reserved namespace, from the other direction: the value the server assigns
# itself is the value no tenant may register. Phase 7 proves the refusal.
if ((Get-Aud $adminToken) -eq "api://emc-auth") {
    Write-Info "This is the audience no tenant can claim. A tenant that could register"
    Write-Info "api://emc-auth would receive a legitimately signed token bearing this"
    Write-Info "server's own management audience - issue #84 reopened in a new form."
}

# ================================== PHASE 2 application creation

Write-Head "PHASE 2 . Application creation assigns an immutable audience and a self-grant"

$apiApp = New-App $adminToken ("aud131-orders-api-" + $stamp) "m2m" @("orders:read", "orders:write")
if (-not $apiApp) { Write-Host "Cannot continue without an application." -ForegroundColor Red; exit 1 }
[void]$script:Cleanup.Add($apiApp.Name)

Write-Host ""
Write-Host "   +-- CREDENTIALS (returned once - copy for Swagger)" -ForegroundColor Magenta
Write-Val "application row id" $apiApp.Id
Write-Val "client_id"          $apiApp.ClientId
Write-Val "client_secret"      $apiApp.Secret
Write-Val "audience"           $apiApp.Audience
Write-Host "   +-- the audience is what a resource server puts in its audience: config" -ForegroundColor DarkGray

$expectedAud = "api://" + $TenantSlug + "/aud131-orders-api-" + $stamp.Replace("-", "-")
if ($apiApp.Audience) {
    Pass ("audience returned at creation: " + $apiApp.Audience)
} else {
    Fail "audience at creation" "the create response carried no audience. There is NO update path, so a caller that does not get it here cannot get it at all."
}
if ($apiApp.Audience -like ("api://" + $TenantSlug + "/*")) {
    Pass "audience is namespaced under the tenant slug"
} else {
    Fail "audience namespace" ("expected api://{0}/<app-slug>, got '{1}'" -f $TenantSlug, $apiApp.Audience)
}

# The self-grant. Without it this application could not obtain a token for its
# OWN api once enforcement is on, and the admin API would show it holding no
# grants at all - a state an operator would reasonably try to "fix" by hand.
$grants = Invoke-Api -Method GET -Path ("/api/v1/applications/" + $apiApp.Id + "/grants") -BearerToken $adminToken
Assert-Status "GET /applications/:id/grants" 200 $grants
if ($grants.Status -eq 200) {
    $rows = @($grants.Json)
    if ($rows.Count -eq 1 -and $rows[0].audience -eq $apiApp.Audience) {
        Pass "exactly one self-grant, for the application's own audience"
    } else {
        Fail "self-grant" ("expected one grant for {0}, got: {1}" -f $apiApp.Audience, $grants.Raw)
    }
}

# Read it back through GET, so the value is not merely something the create
# response invented.
$detail = Invoke-Api -Method GET -Path ("/api/v1/applications/" + $apiApp.Id) -BearerToken $adminToken
Assert-Status "GET /applications/:id" 200 $detail
if ($detail.Status -eq 200) {
    Assert-Equal "audience (read back)" $apiApp.Audience $detail.Json.audience
    Assert-Equal "require_audience defaults false" "False" ([string] $detail.Json.require_audience)
    Write-Info "require_audience = false on every client is what makes this migration"
    Write-Info "non-breaking. Flipping it per client is the #132 rollout, and rollback"
    Write-Info "is flipping it back - configuration, not a deploy."
}

# ============ PHASE 3 the compatibility claim: a client that asks for NOTHING

Write-Head "PHASE 3 . THE COMPATIBILITY CLAIM: client_credentials with NO audience parameter"

Write-Info "This is the emc-insurance-platform case. A live integrator sends exactly"
Write-Info "what they sent before #131 - no audience, no resource - and must keep"
Write-Info "working, receiving a token whose aud now names their own API."

$m2m = Get-M2MToken $apiApp $null $false
Assert-Status "POST /oauth/token (client_credentials, no audience param)" 200 $m2m
if ($m2m.Status -eq 200) {
    $m2mClaims = Show-Claims "M2M token (audience parameter OMITTED)" $m2m.Json.access_token
    Assert-Aud "client_credentials, no parameter" $apiApp.Audience $m2m.Json.access_token
    Assert-Equal "gty" "client_credentials" $m2mClaims.gty
    Assert-Equal "role" "service" $m2mClaims.role
    Assert-SameSet "permissions = registered scopes (no grant narrowing applied)" `
        @("orders:read", "orders:write") $m2mClaims.permissions
    if (-not $m2m.Json.refresh_token) { Pass "no refresh_token (RFC 6749 4.4.3)" }
    else { Fail "client_credentials refresh token" "one was issued; RFC 6749 4.4.3 says it SHOULD NOT be" }
}

# The deprecated JSON alias must behave identically - CLAUDE.md deferred #21
# says its consumers are documented and live, so it is the one endpoint where a
# regression would be silent until a batch job failed.
$alias = Invoke-Api -Method POST -Path "/api/v1/auth/token" -Body @{ grant_type = "client_credentials" } `
    -BasicUser $apiApp.ClientId -BasicPass $apiApp.Secret
Assert-Status "POST /api/v1/auth/token (deprecated alias)" 200 $alias
if ($alias.Status -eq 200) {
    Assert-Aud "deprecated alias" $apiApp.Audience $alias.Json.access_token
    Write-Info "Same audience as /oauth/token. The alias is documented in"
    Write-Info "CLIENT_CREDENTIALS_FLOW.md and has live consumers (deferred #21)."
}

# ============================ PHASE 4 app-scoped end user, and the refresh pin

Write-Head "PHASE 4 . App-scoped end user gets the application's audience, and keeps it"

$webApp = New-App $adminToken ("aud131-portal-" + $stamp) "web" @("openid", "profile", "email")
if ($webApp) {
    [void]$script:Cleanup.Add($webApp.Name)
    Write-Val "portal audience" $webApp.Audience

    $userEmail = "aud131-user-" + $stamp + "@test.example.com"
    $reg = Invoke-Api -Method POST -Path "/api/v1/auth/apps/register" `
        -BasicUser $webApp.ClientId -BasicPass $webApp.Secret -Body @{
            email = $userEmail; password = "Password123!"; first_name = "Aud"; last_name = "Test"
        }
    Assert-OneOf "POST /auth/apps/register" @(200, 201) $reg

    $appLogin = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
        -BasicUser $webApp.ClientId -BasicPass $webApp.Secret -Body @{
            email = $userEmail; password = "Password123!"
        }
    Assert-Status "POST /auth/apps/login" 200 $appLogin

    if ($appLogin.Status -eq 200) {
        $userToken  = $appLogin.Json.access_token
        $userClaims = Show-Claims "END-USER token (app-scoped)" $userToken
        Assert-Aud "app-scoped user login" $webApp.Audience $userToken
        Assert-Equal "app_id present" $webApp.Id ([string] $userClaims.app_id)
        Write-Info "Before #131 this token read aud=emc-auth-api, byte-identical to every"
        Write-Info "other application's token in the tenant. A second application doing"
        Write-Info "textbook JWT validation would have ACCEPTED it: same signature (same"
        Write-Info "tenant key), same iss, same exp, same aud. Only app_id differed, and no"
        Write-Info "standard JWT library checks app_id. That is the bug #131 closes."

        # The refresh pin. A rotation must not be able to move the audience: a
        # client could otherwise obtain a token for API A, then rotate while
        # naming API B and walk from one grant to another without ever
        # presenting a credential for B.
        Write-Step "The audience survives a refresh rotation (the pin)"
        $rot = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $appLogin.Json.refresh_token }
        Assert-Status "POST /auth/refresh (app-scoped)" 200 $rot
        if ($rot.Status -eq 200 -and $rot.Json.access_token) {
            Assert-Aud "after rotation" $webApp.Audience $rot.Json.access_token
            $script:appRefreshToken = $rot.Json.refresh_token
        } elseif ($rot.Status -eq 200) {
            # Known P1, unrelated to #131: an app-scoped refresh can answer 200
            # with no tokens in the body. Recorded as a warning rather than a
            # failure so it does not masquerade as an audience regression.
            Warn "app-scoped refresh returned no tokens" "pre-existing P1, not an audience fault"
        }
    }
}

# ================================= PHASE 5 the admin grant API (both shapes)

Write-Head "PHASE 5 . Admin grant API - catalogue, create, list, update, delete"

# The catalogue an administrator grants FROM. Tenant-scoped with no cross-tenant
# read, which is the point: a tenant has no business enumerating another
# tenant's API inventory. That is also WHY phase 7's refusals must be
# byte-identical - this endpoint is the only legitimate way to learn what
# exists.
$cat = Invoke-Api -Method GET -Path "/api/v1/audiences" -BearerToken $adminToken
Assert-Status "GET /api/v1/audiences" 200 $cat
if ($cat.Status -eq 200) {
    $found = @($cat.Json | Where-Object { $_.audience -eq $apiApp.Audience })
    if ($found.Count -eq 1) { Pass "the new application's audience appears in the catalogue" }
    else { Fail "audience catalogue" ("expected " + $apiApp.Audience + " in the list; got " + @($cat.Json).Count + " entries total") }
}

# A caller application that will be granted access to the orders API.
$caller = New-App $adminToken ("aud131-caller-" + $stamp) "m2m" @("orders:read", "orders:write")
if ($caller) {
    [void]$script:Cleanup.Add($caller.Name)

    Write-Step "POST a grant: the caller may request the orders API, read-only"
    $mk = Invoke-Api -Method POST -Path ("/api/v1/applications/" + $caller.Id + "/grants") `
        -BearerToken $adminToken -Body @{ audience = $apiApp.Audience; scopes = @("orders:read") }
    Assert-OneOf "POST /applications/:id/grants" @(200, 201) $mk
    if ($mk.Status -eq 200 -or $mk.Status -eq 201) {
        $script:grantId = $mk.Json.id
        Assert-Equal "granted audience" $apiApp.Audience $mk.Json.audience
        Assert-SameSet "granted scopes" @("orders:read") $mk.Json.scopes
        Write-Info "The grant permits ONE of the two scopes the caller is registered for."
        Write-Info "Phase 6 proves the token carries only the granted one."
    }

    Write-Step "The tenant-scoped mirror serves the same resource"
    $tid = $adminClaims.tenant_id
    $mirror = Invoke-Api -Method GET -BearerToken $adminToken `
        -Path ("/api/v1/tenants/" + $tid + "/applications/" + $caller.Id + "/grants")
    Assert-Status "GET /tenants/:tid/applications/:id/grants" 200 $mirror
    if ($mirror.Status -eq 200) {
        $flat = Invoke-Api -Method GET -BearerToken $adminToken `
            -Path ("/api/v1/applications/" + $caller.Id + "/grants")
        if ($flat.Raw -eq $mirror.Raw) { Pass "flat and tenant-scoped paths return identical bodies" }
        else { Fail "addressing shapes" "the two paths disagree; tenantFromClaimsOrPath should make them identical" }
    }

    Write-Step "PUT narrows the grant's scopes"
    $upd = Invoke-Api -Method PUT -BearerToken $adminToken `
        -Path ("/api/v1/applications/" + $caller.Id + "/grants/" + $script:grantId) `
        -Body @{ scopes = @() }
    Assert-Status "PUT /applications/:id/grants/:gid" 200 $upd
    if ($upd.Status -eq 200) {
        Write-Info "An empty scope list is a real decision, not a mistake: it means the"
        Write-Info "grant permits nothing. Fail-closed, matching how oauth_clients.scopes"
        Write-Info "already behaves at /oauth/authorize."
    }

    Write-Step "NEGATIVE: PUT cannot re-point a grant at a different audience"
    $repoint = Invoke-Api -Method PUT -BearerToken $adminToken `
        -Path ("/api/v1/applications/" + $caller.Id + "/grants/" + $script:grantId) `
        -Body @{ audience = ("api://" + $TenantSlug + "/somewhere-else"); scopes = @("orders:read") }
    Assert-Status "PUT with an audience in the body" 400 $repoint
    Write-Info "Refused, not ignored. Ignoring it would answer 200 next to a grant that"
    Write-Info "still points where it always did, and the caller would believe the"
    Write-Info "re-point happened."

    # Restore the useful grant for phase 6.
    $upd2 = Invoke-Api -Method PUT -BearerToken $adminToken `
        -Path ("/api/v1/applications/" + $caller.Id + "/grants/" + $script:grantId) `
        -Body @{ scopes = @("orders:read") }
    Assert-Status "PUT restores scopes for the next phase" 200 $upd2
}

# ============================== PHASE 6 an explicit audience, and scope narrowing

Write-Head "PHASE 6 . An explicitly requested, granted audience - and scope intersection"

if ($caller) {
    $tok = Get-M2MToken $caller $apiApp.Audience $false
    Assert-Status "POST /oauth/token (audience=<granted>)" 200 $tok
    if ($tok.Status -eq 200) {
        $c = Show-Claims "CALLER token for the orders API" $tok.Json.access_token
        Assert-Aud "explicit granted audience" $apiApp.Audience $tok.Json.access_token
        # The intersection. The caller is REGISTERED for orders:read and
        # orders:write; the grant permits only orders:read. A token must never
        # carry a scope the grant omits.
        Assert-SameSet "permissions intersected with the grant" @("orders:read") $c.permissions
        if (@($c.permissions) -contains "orders:write") {
            Fail "scope intersection" "the token carries orders:write, which the grant does not permit"
        }
    }

    Write-Step "RFC 8707 spelling: resource= is accepted as well as audience="
    $tok2 = Get-M2MToken $caller $apiApp.Audience $true
    Assert-Status "POST /oauth/token (resource=<granted>)" 200 $tok2
    if ($tok2.Status -eq 200) {
        Assert-Aud "resource= parameter" $apiApp.Audience $tok2.Json.access_token
        Write-Info "audience= is Auth0's name and is what integrators arriving from there"
        Write-Info "send; resource= is RFC 8707 and is what a conformant library sends."
        Write-Info "Both are honoured, and audience= wins if a caller sends both."
    }

    Write-Step "A client may still ask for its OWN audience explicitly"
    $tok3 = Get-M2MToken $caller $caller.Audience $false
    Assert-Status "POST /oauth/token (audience=<own>)" 200 $tok3
    if ($tok3.Status -eq 200) { Assert-Aud "own audience, named explicitly" $caller.Audience $tok3.Json.access_token }
}

# ================================ PHASE 7 (THE ONE THAT MATTERS) the refusals

Write-Head "PHASE 7 . NEGATIVE: every refused audience must look IDENTICAL"

Write-Info "This is the highest-value phase in the script."
Write-Info ""
Write-Info "RFC 8707 gives ONE error code for a refused audience. If the response for"
Write-Info "'you hold no grant for this' differs in any way from the response for 'no"
Write-Info "such audience exists', then any client with credentials can enumerate"
Write-Info "every audience in the deployment by diffing the errors - a complete map"
Write-Info "of every tenant's internal API surface, including other tenants'."
Write-Info ""
Write-Info "Compared as RAW BYTES, not parsed JSON: a difference in key order or"
Write-Info "whitespace is just as readable to an attacker as a difference in words."

if ($caller -and $webApp) {
    $probes = @(
        @{ Label = "exists, but this client has no grant"; Value = $webApp.Audience },
        @{ Label = "does not exist anywhere";              Value = "api://" + $TenantSlug + "/aud131-nonexistent-" + $stamp },
        @{ Label = "another tenant's shape";               Value = "api://some-other-tenant/their-api" },
        @{ Label = "malformed (no scheme)";                Value = "not-an-audience" },
        @{ Label = "malformed (uppercase)";                Value = "api://" + $TenantSlug + "/Orders" },
        @{ Label = "malformed (underscore)";               Value = "api://" + $TenantSlug + "/orders_api" },
        @{ Label = "RESERVED namespace";                   Value = "api://emc-auth" },
        @{ Label = "RESERVED by prefix";                   Value = "api://emc-auth-sneaky/admin" },
        @{ Label = "path traversal attempt";               Value = "api://" + $TenantSlug + "/../emc-auth" },
        @{ Label = "empty app label";                      Value = "api://" + $TenantSlug + "/" }
    )

    $responses = @()
    foreach ($p in $probes) {
        $r = Get-M2MToken $caller $p.Value $false
        Assert-Status ("REFUSED: " + $p.Label) 400 $r
        if ($r.Json -and $r.Json.error) {
            if ($r.Json.error -eq "invalid_target") { Pass ("  error=invalid_target (RFC 8707 s2)") }
            else { Fail ("  error code for " + $p.Label) ("expected invalid_target, got '" + $r.Json.error + "'") }
        }
        $responses += $r
    }

    Assert-SameBody "all ten refusals" $responses

    Write-Step "The reserved namespace, stated plainly"
    Write-Info "api://emc-auth is the audience the SERVER assigns itself (phase 1). A"
    Write-Info "tenant that could register or request it would receive a legitimately"
    Write-Info "signed token bearing this server's own management audience and reach the"
    Write-Info "admin surface with it - issue #84 reopened in a new form. It is refused"
    Write-Info "in the service layer AND by a CHECK constraint, so it holds for psql too."
}

# ==================================== PHASE 8 immutability of the identifier

Write-Head "PHASE 8 . NEGATIVE: the audience identifier cannot be changed"

Write-Info "Immutable because every resource server validating the value would break"
Write-Info "the moment it changed, and those servers are not ours to coordinate. Same"
Write-Info "reasoning as rp_id and the tenant slug."

if ($apiApp) {
    Write-Step "PUT /applications/:id with an audience field"
    $tryUpd = Invoke-Api -Method PUT -Path ("/api/v1/applications/" + $apiApp.Id) `
        -BearerToken $adminToken -Body @{ audience = "api://" + $TenantSlug + "/hijacked"; name = $apiApp.Name }
    # The API has NO audience field at all, so the value is not rejected - it is
    # not bound in the first place. Either outcome is acceptable; what must NOT
    # happen is the column changing.
    Write-Info ("PUT returned HTTP " + $tryUpd.Status + " - the request shape has no audience field to bind")
    $after = Invoke-Api -Method GET -Path ("/api/v1/applications/" + $apiApp.Id) -BearerToken $adminToken
    if ($after.Status -eq 200) {
        if ($after.Json.audience -eq $apiApp.Audience) {
            Pass ("audience unchanged after an update attempt: " + $after.Json.audience)
        } else {
            Fail "audience immutability" ("the audience CHANGED to '" + $after.Json.audience + "'. A convenience setter has been added; see the AppUpdate test.")
        }
    }

    Write-Step "require_audience, by contrast, IS meant to be settable"
    Write-Info "It is the per-client enforcement switch and flipping it is the #132"
    Write-Info "rollout. Do not confuse the two: one is an identifier other systems"
    Write-Info "depend on, the other is a policy this server enforces."
}

# ============================== PHASE 9 cross-tenant grants

Write-Head "PHASE 9 . NEGATIVE: a client cannot be granted another tenant's audience"

if (-not $IncludeCrossTenant) {
    Warn "cross-tenant grant" "skipped - pass -IncludeCrossTenant to create a second tenant and prove it"
} else {
    $otherSlug = "aud131t" + $stamp.Replace("-", "")
    # owner_email is REQUIRED: creating a tenant also seeds its permission
    # catalogue, an owner role, and an owner user, and the owner is created
    # without a password so the invitation is their only route in.
    $mkTenant = Invoke-Api -Method POST -Path "/api/v1/tenants" -BearerToken $adminToken -Body @{
        name        = ("Aud131 Other " + $stamp)
        slug        = $otherSlug
        owner_email = ("aud131-owner-" + $stamp + "@test.example.com")
    }
    Assert-OneOf "POST /api/v1/tenants" @(200, 201) $mkTenant
    if ($mkTenant.Status -eq 200 -or $mkTenant.Status -eq 201) {
        # .tenant.id, NOT .id - CreateTenant answers {tenant:{...}, owner:{...}}
        # because it also seeds an owner user and emails an invitation.
        #
        # Reading the wrong field cost this phase a whole run. $otherTid came
        # back $null, the path collapsed to "/api/v1/tenants//applications",
        # Echo matched :tid as an EMPTY string, and tenantFromClaimsOrPath fell
        # back to the caller's own tenant. Everything answered 201 and the
        # "victim" was created in emc - so the grant that followed was not
        # cross-tenant at all and correctly succeeded. The phase reported two
        # failures while the server behaved perfectly.
        $otherTid = $mkTenant.Json.tenant.id
        [void]$script:Cleanup.Add("tenant:" + $otherSlug)
        $victimAud = $null

        if (-not $otherTid) {
            Fail "second tenant id" "could not read .tenant.id from the create response - refusing to continue, because an empty :tid silently resolves to the caller's OWN tenant and this phase would pass while testing nothing"
            $victim = [pscustomobject]@{ Status = -1; Raw = ""; Json = $null }
        } else {
            Write-Val "second tenant id" $otherTid
            $victim = Invoke-Api -Method POST -Path ("/api/v1/tenants/" + $otherTid + "/applications") `
                -BearerToken $adminToken -Body @{ name = ("aud131-victim-" + $stamp); app_type = "m2m" }
            Assert-OneOf "create an application in the other tenant" @(200, 201) $victim
        }

        if ($victim.Status -eq 200 -or $victim.Status -eq 201) {
            Write-Val "the other tenant's audience" $victim.Json.audience

            # THE GUARD, and the reason this phase can be trusted from now on.
            # Everything below is meaningless unless the victim really is in the
            # OTHER tenant - and the audience says so out loud, because it is
            # namespaced by tenant slug. An audience under emc/ proves the
            # application landed in the wrong place.
            if ($victim.Json.audience -like ("api://" + $otherSlug + "/*")) {
                Pass ("the victim application really is in the other tenant: " + $victim.Json.audience)
                $victimAud = $victim.Json.audience
            } else {
                Fail "cross-tenant setup" ("the victim's audience is '" + $victim.Json.audience + "', not under api://" + $otherSlug + "/. It was created in the WRONG tenant, so nothing below would test cross-tenant isolation.")
            }
        }

        if ($victimAud) {
            Write-Step "Granting tenant A's client an audience owned by tenant B"
            $bad = Invoke-Api -Method POST -Path ("/api/v1/applications/" + $caller.Id + "/grants") `
                -BearerToken $adminToken -Body @{ audience = $victimAud }
            Assert-OneOf "POST cross-tenant grant" @(400, 404) $bad
            Write-Info "Refused by a composite FOREIGN KEY, not only by application code:"
            Write-Info "oauth_client_grants(tenant_id, audience) must name a real oauth_clients"
            Write-Info "row, so this is impossible even from psql."

            Write-Step "And requesting it directly at the token endpoint"
            $bad2 = Get-M2MToken $caller $victimAud $false
            Assert-Status "POST /oauth/token for another tenant's audience" 400 $bad2
            if ($bad2.Json.error) { Assert-Equal "  error" "invalid_target" $bad2.Json.error }
        }
    }
}

# ============================== PHASE 10 the refresh chain

Write-Head "PHASE 10 . NEGATIVE: a refresh cannot move its own audience"

Write-Info "Without the pin a client could obtain a token for API A, then rotate its"
Write-Info "refresh token while naming API B, and walk from one grant to another"
Write-Info "without ever presenting a credential for B."

if ($caller) {
    # A user session on the caller application, so there IS a refresh chain.
    # client_credentials mints no refresh token (RFC 6749 4.4.3), so the machine
    # path cannot be used to test this.
    if ($script:appRefreshToken) {
        Write-Step "Rotating with an audience parameter naming a DIFFERENT api"
        $moved = Invoke-Api -Method POST -Path "/oauth/token" -FormEncoded `
            -Body ("grant_type=refresh_token&refresh_token=" + [uri]::EscapeDataString($script:appRefreshToken) + `
                   "&audience=" + [uri]::EscapeDataString($apiApp.Audience)) `
            -BasicUser $webApp.ClientId -BasicPass $webApp.Secret
        if ($moved.Status -eq 400) {
            Pass "a rotation naming a different audience is refused (HTTP 400)"
            if ($moved.Json.error) { Write-Info ("error=" + $moved.Json.error) }
        } elseif ($moved.Status -eq 200) {
            $newAud = Get-Aud $moved.Json.access_token
            if ($newAud -eq $webApp.Audience) {
                Pass ("the rotation kept its pinned audience: " + $newAud)
            } else {
                Fail "refresh audience pin" ("the rotation MOVED the audience to '" + $newAud + "'. A refresh must never change the API a chain is good for.")
            }
        } else {
            Warn "refresh audience pin" ("inconclusive - HTTP " + $moved.Status)
        }
    } else {
        Warn "refresh audience pin" "no app-scoped refresh token captured in phase 4 (see the known P1 there)"
    }
}

# ============================== PHASE 11 revoke ownership (deferred #22)

Write-Head "PHASE 11 . NEGATIVE: one client cannot revoke another client's tokens"

Write-Info "CLAUDE.md deferred #22. Client authentication was already required and the"
Write-Info "UPDATE was already scoped by tenant, so this was never an unauthenticated"
Write-Info "hole. What remained: two clients inside ONE tenant could revoke each"
Write-Info "other's refresh tokens, because refresh_tokens had no application_id to"
Write-Info "compare an authenticated client_id against. Migration 00087 adds it."

if ($webApp -and $caller) {
    $victimLogin = Invoke-Api -Method POST -Path "/api/v1/auth/apps/login" `
        -BasicUser $webApp.ClientId -BasicPass $webApp.Secret -Body @{
            email = ("aud131-user-" + $stamp + "@test.example.com"); password = "Password123!"
        }
    if ($victimLogin.Status -eq 200 -and $victimLogin.Json.refresh_token) {
        $rt = $victimLogin.Json.refresh_token

        Write-Step "The OTHER client tries to revoke it"
        $rv = Invoke-Api -Method POST -Path "/oauth/revoke" -FormEncoded `
            -Body ("token=" + [uri]::EscapeDataString($rt)) `
            -BasicUser $caller.ClientId -BasicPass $caller.Secret
        Assert-Status "POST /oauth/revoke by a foreign client" 200 $rv
        Write-Info "200 REGARDLESS - RFC 7009 s2.2 forbids the oracle. A distinguishable"
        Write-Info "response would tell a caller whether a captured string is a live token,"
        Write-Info "so the refusal is invisible on the wire. The DATABASE is the evidence."

        Write-Step "Was it actually revoked? (this is the real assertion)"
        $stillWorks = Invoke-Api -Method POST -Path "/api/v1/auth/refresh" -Body @{ refresh_token = $rt }
        if ($stillWorks.Status -eq 200) {
            Pass "the token still works - the foreign client's revoke had no effect"
        } else {
            Fail "cross-client revoke" ("the foreign client revoked another client's token (refresh now HTTP " + $stillWorks.Status + ") - deferred #22 is not closed")
        }
    } else {
        Warn "cross-client revoke" "could not obtain a victim refresh token"
    }
}

# ================== PHASE 12 (WORST CASE) enforcement, and audience recycling

Write-Head "PHASE 12 . WORST CASE: the states that bite weeks later, not on deploy day"

Write-Step "A. An audience is NEVER recycled, even after a soft delete"

Write-Info "oauth_clients' own name index is PARTIAL (WHERE deleted_at IS NULL), so"
Write-Info "soft-deleting an application frees its NAME. Its audience must NOT be"
Write-Info "freed: grants and tokens outlive the client row, so a reissued identifier"
Write-Info "would silently redirect them to a DIFFERENT application. This is the"
Write-Info "failure mode that would be discovered months later, by a resource server"
Write-Info "trusting a token it should have refused."

$doomedName = "aud131-doomed-" + $stamp
$doomed = New-App $adminToken $doomedName "m2m" $null
if ($doomed) {
    [void]$script:Cleanup.Add($doomedName)
    Write-Val "orphaned audience" $doomed.Audience

    $del = Invoke-Api -Method DELETE -Path ("/api/v1/applications/" + $doomed.Id) -BearerToken $adminToken
    Assert-OneOf "DELETE /applications/:id (soft delete)" @(200, 204) $del

    if ($del.Status -eq 200 -or $del.Status -eq 204) {
        Write-Step "Recreating an application with the SAME name"
        $again = Invoke-Api -Method POST -Path "/api/v1/applications" -BearerToken $adminToken -Body @{
            name = $doomedName; app_type = "m2m"
        }
        if ($again.Status -eq 200 -or $again.Status -eq 201) {
            if ($again.Json.audience -eq $doomed.Audience) {
                Fail "audience recycling" ("the recreated application got the SAME audience (" + $again.Json.audience + "). Every grant and token for the old application now points at the new one.")
            } else {
                Pass ("recreation did not reuse the audience (got: " + $again.Json.audience + ")")
            }
        } elseif ($again.Status -eq 409) {
            Pass "recreation with the same name is refused because the audience is reserved forever (HTTP 409)"
            Write-Info ("body: " + $again.Raw)
            if ($again.Raw -like "*name already exists*") {
                Fail "recycling error message" "it blames the NAME, which is genuinely free here (its index is partial on deleted_at). The audience is what is taken, and an operator told otherwise will hunt a live application that does not exist."
            } else {
                Pass "the message names the AUDIENCE, not the name"
            }
        } elseif ($again.Status -eq 500) {
            Fail "audience recycling" ("recreation returned HTTP 500: " + $again.Raw + " - the refusal is correct in the service layer but the handler is not mapping ErrAudienceTaken, so a valid refusal reaches the operator as a server fault")
        } else {
            Warn "audience recycling" ("recreation returned HTTP " + $again.Status + ": " + $again.Raw)
        }
    }
}

Write-Step "B. require_audience enforcement"

if (-not $IncludeEnforcement) {
    Warn "require_audience enforcement" "skipped - pass -IncludeEnforcement to flip it on a throwaway client"
} else {
    # A client with NO audience is the only interesting case: with one, nothing
    # to enforce. So the flag is flipped on a client whose audience was never
    # assigned, which is what a pre-#131 row looks like.
    #
    # The API cannot create that state (every new application gets an audience),
    # so this needs SQL - which is also why it is gated behind a switch.
    if ($SkipSql) {
        Warn "require_audience enforcement" "needs SQL access and -SkipSql was passed"
    } else {
        $bareName = "aud131-bare-" + $stamp
        $bare = New-App $adminToken $bareName "m2m" $null
        if ($bare) {
            [void]$script:Cleanup.Add($bareName)
            # Drop the self-grant first: the composite FK refuses to let a
            # REFERENCED audience be updated at all, which is itself a stronger
            # immutability guarantee than the API alone provides.
            $r1 = Invoke-Psql ("DELETE FROM oauth_client_grants WHERE client_id = " + $bare.Id + ";")
            $r2 = Invoke-Psql ("UPDATE oauth_clients SET audience = NULL, require_audience = true WHERE id = " + $bare.Id + ";")
            if ($r1 -eq $script:PsqlError -or $r2 -eq $script:PsqlError) {
                Warn "require_audience enforcement" "could not set up the pre-#131 row shape via SQL"
            } else {
                Write-Info "This client now looks like a pre-#131 row (no audience) with"
                Write-Info "enforcement switched ON - the exact state the #132 rollout creates"
                Write-Info "if a client is enabled before it has an audience."
                $enf = Get-M2MToken $bare $null $false
                Assert-Status "client_credentials with require_audience and no audience" 400 $enf
                if ($enf.Json.error) {
                    Assert-Equal "  error" "invalid_target" $enf.Json.error
                    Write-Info "Reported as invalid_target, NOT as a distinct 'enforcement is on'"
                    Write-Info "error: a distinguishable answer would tell a caller which clients"
                    Write-Info "have enforcement enabled, which is a map of the #132 rollout."
                }

                Write-Step "Turning it back off restores service"
                $r3 = Invoke-Psql ("UPDATE oauth_clients SET require_audience = false WHERE id = " + $bare.Id + ";")
                if ($r3 -ne $script:PsqlError) {
                    $back = Get-M2MToken $bare $null $false
                    Assert-Status "the same request after rollback" 200 $back
                    if ($back.Status -eq 200) {
                        Assert-Aud "no audience, enforcement off" "(ABSENT)" $back.Json.access_token
                        Pass "rollback is configuration only - no deploy, and the claim is simply omitted"
                    }
                }
            }
        }
    }
}

Write-Step "C. A deleted grant stops the NEXT mint, not the current token"

if ($caller -and $script:grantId) {
    $before = Get-M2MToken $caller $apiApp.Audience $false
    if ($before.Status -eq 200) { Write-Info "the grant currently works" }

    $dg = Invoke-Api -Method DELETE -BearerToken $adminToken `
        -Path ("/api/v1/applications/" + $caller.Id + "/grants/" + $script:grantId)
    Assert-Status "DELETE /applications/:id/grants/:gid" 200 $dg

    if ($dg.Status -eq 200) {
        $after = Get-M2MToken $caller $apiApp.Audience $false
        Assert-Status "the same request after the grant is revoked" 400 $after
        if ($after.Json.error) { Assert-Equal "  error" "invalid_target" $after.Json.error }
        Write-Info "Revoking a grant is not an instant cut-off and cannot be: an access"
        Write-Info "token is self-contained with no server-side record, and lives 15"
        Write-Info "minutes. What it stops is the next mint and every refresh."

        Write-Step "And the refusal is still byte-identical to a nonexistent audience"
        $ghost = Get-M2MToken $caller ("api://" + $TenantSlug + "/aud131-ghost-" + $stamp) $false
        Assert-SameBody "revoked-grant vs nonexistent" @($after, $ghost)
    }
}

# ============================================================= PHASE 13 metrics

Write-Head "PHASE 13 . Metrics: the denial counter must have actually moved"

Write-Info "A counter that is declared but never incremented reads as a flat zero,"
Write-Info "indistinguishable from 'no denials happened' - and #132 would then ship"
Write-Info "on evidence that does not exist. CLAUDE.md deferred #12"
Write-Info "(emc_auth_rate_limit_hits_total) has been in exactly that state for"
Write-Info "months. This phase is the assertion that keeps #131 out of it."

$metricsAfter = Get-Metrics
$denialsAfter = Get-MetricValue $metricsAfter "emc_auth_audience_grant_denials_total"
Write-Val "denials before" $denialsBefore
Write-Val "denials after"  $denialsAfter

if ($denialsAfter -gt $denialsBefore) {
    Pass ("emc_auth_audience_grant_denials_total rose by " + ($denialsAfter - $denialsBefore))
} else {
    Fail "emc_auth_audience_grant_denials_total" "did not move despite the refusals above. Every denial path must increment it, or a refusal is invisible in Prometheus."
}

if ($metricsAfter -match "emc_auth_audience_grant_denials_total\{[^}]*audience=") {
    Pass "the audience label is populated, so a dashboard can name what was refused"
    foreach ($line in ($metricsAfter -split "`n")) {
        if ($line -like "emc_auth_audience_grant_denials_total{*" -and $line -notlike "#*") {
            Write-Info $line.Trim()
        }
    }
}

$legacyAfter = Get-MetricValue $metricsAfter "emc_auth_legacy_audience_verifications_total"
Write-Val "legacy-verif. after" $legacyAfter
if ($legacyAfter -gt $legacyBefore) {
    Warn "legacy audience fallback fired" ("rose by " + ($legacyAfter - $legacyBefore) + " during this run - a pre-#130 token is still in circulation. This is the #132 gate, not a #131 failure.")
} else {
    Pass "no legacy-audience fallback during this run (the #132 gate stayed at zero)"
}

# ================================================ PHASE 14 database verification

Write-Head "PHASE 14 . Database verification"

if ($SkipSql) {
    Warn "database checks" "skipped (-SkipSql)"
} else {
    Write-Info "A claim about a column is not evidence about a column. Everything above"
    Write-Info "went through HTTP; this phase reads the rows."

    Write-Step "The schema migration 00087 actually created"
    $cols = Invoke-Psql @"
SELECT table_name || '.' || column_name
FROM information_schema.columns
WHERE (table_name = 'oauth_clients' AND column_name IN ('audience','require_audience'))
   OR (table_name = 'refresh_tokens' AND column_name IN ('audience','application_id'))
   OR (table_name = 'oauth_authorization_codes' AND column_name = 'audience')
ORDER BY 1;
"@
    if ($cols -eq $script:PsqlError) {
        Warn "schema check" "psql failed"
    } else {
        $expected = @(
            "oauth_authorization_codes.audience",
            "oauth_clients.audience",
            "oauth_clients.require_audience",
            "refresh_tokens.application_id",
            "refresh_tokens.audience"
        )
        $actual = @($cols -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        Assert-SameSet "columns added by 00087" $expected $actual
    }

    Write-Step "The audience unique index must be FULL, not partial"
    $idx = Invoke-Psql "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_oauth_clients_audience';"
    if ($idx -eq $script:PsqlError -or -not $idx) {
        Fail "idx_oauth_clients_audience" "not found - an audience could then be recycled"
    } elseif ($idx -match "WHERE") {
        Fail "idx_oauth_clients_audience" ("it is PARTIAL: " + $idx + " - a soft-deleted application's audience would be reusable, silently redirecting its grants and tokens to a different application")
    } else {
        Pass "idx_oauth_clients_audience is a full unique index (an audience is never recycled)"
    }

    Write-Step "The reserved-namespace CHECK constraint exists"
    $chk = Invoke-Psql "SELECT conname FROM pg_constraint WHERE conname = 'oauth_clients_audience_not_reserved';"
    if ($chk -eq $script:PsqlError) { Warn "CHECK constraint" "psql failed" }
    elseif ($chk) { Pass "oauth_clients_audience_not_reserved is present (holds for psql too, not just the API)" }
    else { Fail "oauth_clients_audience_not_reserved" "missing - only the service layer would refuse the reserved namespace" }

    Write-Step "The composite FK that makes a cross-tenant grant impossible"
    $fk = Invoke-Psql "SELECT conname FROM pg_constraint WHERE conname = 'oauth_client_grants_audience_fkey';"
    if ($fk -eq $script:PsqlError) { Warn "composite FK" "psql failed" }
    elseif ($fk) { Pass "oauth_client_grants_audience_fkey is present" }
    else { Fail "oauth_client_grants_audience_fkey" "missing - a cross-tenant grant would be refused only by application code" }

    Write-Step "Every live application has an audience, and a self-grant"
    $counts = Invoke-Psql @"
SELECT
  (SELECT count(*) FROM oauth_clients WHERE deleted_at IS NULL) ||
  '|' || (SELECT count(*) FROM oauth_clients WHERE deleted_at IS NULL AND audience IS NOT NULL) ||
  '|' || (SELECT count(*) FROM oauth_client_grants) ||
  '|' || (SELECT count(*) FROM oauth_clients c WHERE c.deleted_at IS NULL AND c.audience IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM oauth_client_grants g WHERE g.client_id = c.id AND g.audience = c.audience));
"@
    if ($counts -eq $script:PsqlError) {
        Warn "row counts" "psql failed"
    } else {
        $p = ($counts -split "\|")
        Write-Val "live applications"      $p[0]
        Write-Val "  with an audience"     $p[1]
        Write-Val "grant rows total"       $p[2]
        Write-Val "missing a self-grant"   $p[3]
        if ([int] $p[3] -eq 0) {
            Pass "every live application with an audience holds its own self-grant"
        } else {
            Fail "self-grants" ([string] $p[3] + " live application(s) have an audience but no self-grant. Once enforcement is on they cannot get a token for their own API.")
        }
        if ([int] $p[0] -eq [int] $p[1]) {
            Pass "no live application is missing an audience"
        } else {
            # Measured as a DELTA against the phase 0 baseline. An absolute count
            # is wrong here: leftovers from previous runs are expected (the
            # cleanup SQL is optional), and phase 12B deliberately creates one
            # audience-less row per run to build a pre-#131 shape.
            $missing  = [int] $p[0] - [int] $p[1]
            $expected = 0
            if ($IncludeEnforcement -and -not $SkipSql) { $expected = 1 }
            $delta = $missing - $script:BareBefore
            Write-Val "  pre-existing (baseline)" $script:BareBefore
            Write-Val "  created by this run"     $delta

            if ($delta -eq $expected) {
                if ($expected -eq 0) {
                    Pass "this run left no application without an audience"
                } else {
                    Pass "the one audience-less application is the pre-#131 row phase 12B built on purpose"
                }
            } else {
                Warn "applications without an audience" ("this run changed the count by " + $delta + ", expected " + $expected + ". A live application with no audience cannot get a token for its own API once enforcement is on.")
            }
        }
    }

    Write-Step "The refresh chain really is pinned on the row"
    $pins = Invoke-Psql @"
SELECT count(*) || '|' || count(audience) || '|' || count(application_id)
FROM refresh_tokens WHERE revoked_at IS NULL;
"@
    if ($pins -ne $script:PsqlError) {
        $q = ($pins -split "\|")
        Write-Val "live refresh tokens"        $q[0]
        Write-Val "  with an audience pinned"  $q[1]
        Write-Val "  with an application_id"   $q[2]
        if ([int] $q[1] -gt 0) { Pass "audience is being written to refresh_tokens" }
        else { Fail "refresh audience pin" "no live refresh token carries an audience - the pin is not being written, so a rotation has nothing to enforce" }
    }

    Write-Step "No audience anywhere is inside the reserved namespace"
    $bad = Invoke-Psql "SELECT count(*) FROM oauth_clients WHERE audience LIKE 'api://emc-auth%';"
    if ($bad -ne $script:PsqlError) {
        if ([int] $bad -eq 0) { Pass "no tenant holds an audience under api://emc-auth" }
        else { Fail "reserved namespace" ([string] $bad + " application(s) hold a reserved audience - each can mint a token bearing this server's own management audience") }
    }

    Write-Step "Slug collisions that WOULD have failed the migration"
    $dupes = Invoke-Psql @"
SELECT count(*) FROM (
  SELECT lower(t.slug), lower(regexp_replace(regexp_replace(c.name,'[^a-zA-Z0-9]+','-','g'),'(^-+|-+$)','','g'))
  FROM oauth_clients c JOIN tenants t ON t.id = c.tenant_id
  GROUP BY 1,2 HAVING count(*) > 1
) d;
"@
    if ($dupes -ne $script:PsqlError) {
        if ([int] $dupes -eq 0) { Pass "no slug collisions in this database (including soft-deleted rows)" }
        else { Warn "slug collisions" ([string] $dupes + " group(s) collide. Re-run this check against PRODUCTION before shipping the migration - the ticket's own pre-flight query filters deleted_at and would MISS these.") }
    }
}

# ==================================================================== SUMMARY

Write-Head "SUMMARY"

Write-Host ""
Write-Host ("   PASS : " + $script:PassCount) -ForegroundColor Green
Write-Host ("   WARN : " + $script:WarnCount)  -ForegroundColor Yellow
Write-Host ("   FAIL : " + $script:FailCount)  -ForegroundColor Red

if ($script:WarnCount -gt 0) {
    Write-Host ""
    Write-Host "   Warnings (not regressions - skipped checks and known gaps):" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) { Write-Host ("     - " + $w) -ForegroundColor DarkYellow }
}

if ($script:FailCount -gt 0) {
    Write-Host ""
    Write-Host "   Failures:" -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host ("     - " + $f) -ForegroundColor DarkRed }
}

Write-Host ""
Write-Host ("=" * 78) -ForegroundColor DarkCyan
if ($script:FailCount -eq 0) {
    Write-Host "  ISSUE #131 VERIFIED" -ForegroundColor Green
    Write-Host ""
    Write-Host "  What this run proved:" -ForegroundColor Green
    Write-Host "    * a client that asks for NOTHING still works (phases 3, 4)" -ForegroundColor Gray
    Write-Host "    * an audience cannot be obtained without a grant (phase 7)" -ForegroundColor Gray
    Write-Host "    * every refusal is byte-identical, so nothing is enumerable (phase 7)" -ForegroundColor Gray
    Write-Host "    * an audience is immutable and never recycled (phases 8, 12)" -ForegroundColor Gray
    Write-Host "    * a refresh cannot move its audience (phase 10)" -ForegroundColor Gray
    Write-Host "    * one client cannot revoke another's tokens (phase 11)" -ForegroundColor Gray
    Write-Host "    * the denial counter actually increments (phase 13)" -ForegroundColor Gray
} else {
    Write-Host "  ISSUE #131 NOT VERIFIED - see the failures above" -ForegroundColor Red
}
Write-Host ("=" * 78) -ForegroundColor DarkCyan

# -------------------------------------------------------------------- cleanup

Write-Host ""
Write-Host "CLEANUP SQL (throwaway objects created by this run):" -ForegroundColor Cyan
Write-Host ""
Write-Host "-- Audience identifiers are NEVER released, by design (migration 00087 uses" -ForegroundColor DarkGray
Write-Host "-- a FULL unique index). So these rows' audiences stay reserved even after the" -ForegroundColor DarkGray
Write-Host "-- delete below. That is the feature working, not a leak: every name carries" -ForegroundColor DarkGray
Write-Host "-- the run id '$stamp', so re-runs never collide." -ForegroundColor DarkGray
Write-Host ""
Write-Host "DELETE FROM oauth_client_grants WHERE client_id IN (SELECT id FROM oauth_clients WHERE name LIKE 'aud131-%');" -ForegroundColor Yellow
Write-Host "DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'aud131-%');" -ForegroundColor Yellow
Write-Host "DELETE FROM user_sessions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'aud131-%');" -ForegroundColor Yellow
Write-Host "DELETE FROM users WHERE email LIKE 'aud131-%';" -ForegroundColor Yellow
Write-Host "DELETE FROM oauth_clients WHERE name LIKE 'aud131-%';" -ForegroundColor Yellow
if ($IncludeCrossTenant) {
    Write-Host "DELETE FROM tenants WHERE slug LIKE 'aud131t%';" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Run it with:" -ForegroundColor Cyan
Write-Host ("  docker exec -i " + $PgContainer + " psql -U " + $PgUser + " -d " + $PgDb) -ForegroundColor Gray

if ($script:FailCount -gt 0) { exit 1 }
exit 0
