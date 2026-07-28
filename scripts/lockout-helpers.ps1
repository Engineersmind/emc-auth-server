# Helpers for manual lockout testing (issue #72).
# Dot-source ONCE per PowerShell window, then run the test blocks:
#
#     . .\scripts\lockout-helpers.ps1
#
# Deliberately ASCII-only and free of multi-line pasting hazards: defining these
# by pasting into the PS 5.1 console is unreliable (nested braces + the '>>'
# continuation prompt), which is why they live in a file.

# Deliberately a long, specific name. PowerShell variables are CASE-INSENSITIVE,
# so a short global like $B is silently destroyed the moment a test block assigns
# to $b - which produces "Invalid URI: The hostname could not be parsed" on every
# later call, far from the actual cause.
$global:LockoutBaseUrl = 'http://localhost:9090'

# Hit performs one API call and ALWAYS returns an inspectable object, never
# throws. Invoke-WebRequest treats 401 as terminating, but a 401 is the expected
# result for most checks here, so the error path is unwrapped into the same shape
# as the success path.
function global:Hit {
    param($Method, $Path, $Body, $Token, $Hdr = @{})

    $h = @{ 'Content-Type' = 'application/json' }
    foreach ($k in $Hdr.Keys) { $h[$k] = $Hdr[$k] }
    if ($Token) { $h['Authorization'] = "Bearer $Token" }

    # Fail loudly if the base URL was clobbered, rather than emitting an opaque
    # "Invalid URI" for every call afterwards.
    if ($global:LockoutBaseUrl -isnot [string]) {
        throw "`$global:LockoutBaseUrl was overwritten (type $($global:LockoutBaseUrl.GetType().Name)). Re-run: . .\scripts\lockout-helpers.ps1"
    }

    $p = @{ Uri = "$global:LockoutBaseUrl$Path"; Method = $Method; Headers = $h; UseBasicParsing = $true }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Compress -Depth 8) }

    try {
        $r = Invoke-WebRequest @p
        $j = $null
        if ($r.Content) { try { $j = $r.Content | ConvertFrom-Json } catch {} }
        return [pscustomobject]@{
            Code       = [int]$r.StatusCode
            Body       = $r.Content
            Json       = $j
            RetryAfter = $r.Headers['Retry-After']
        }
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) {
            # No HTTP response at all: server down, wrong port, connection reset.
            return [pscustomobject]@{
                Code = 0; Body = $_.Exception.Message; Json = $null; RetryAfter = $null
            }
        }
        $raw = ''
        try {
            $sr  = New-Object System.IO.StreamReader($resp.GetResponseStream())
            $raw = $sr.ReadToEnd(); $sr.Close()
        } catch {}
        $j = $null
        if ($raw) { try { $j = $raw | ConvertFrom-Json } catch {} }
        $ra = $null
        try { $ra = $resp.Headers['Retry-After'] } catch {}
        return [pscustomobject]@{
            Code = [int]$resp.StatusCode; Body = $raw; Json = $j; RetryAfter = $ra
        }
    }
}

function global:Login {
    param($Email, $Password)
    Hit POST '/api/v1/auth/login' @{ email = $Email; password = $Password }
}

function global:Register {
    param($Email, $Password, $Slug = 'emc')
    Hit POST '/api/v1/auth/register' `
        @{ email = $Email; password = $Password; first_name = 'Lock'; last_name = 'Test' } `
        $null @{ 'X-Tenant-Slug' = $Slug }
}

# GetUser looks the victim up through the admin API so locked_until / is_active
# can be inspected without touching the database directly.
function global:GetUser {
    param($Email, $Token)
    $q = [uri]::EscapeDataString($Email)
    $r = Hit GET "/api/v1/users?search=$q&limit=5" $null $Token
    if (-not $r.Json.users) { return $null }
    return $r.Json.users | Where-Object { $_.email -eq $Email } | Select-Object -First 1
}

# Check prints a pass/fail line. $Why explains what a failure MEANS so a red line
# is actionable without re-reading the implementation.
function global:Check {
    param($Name, $Condition, $Actual, $Why)
    if ($Condition) {
        Write-Host '  [PASS] ' -ForegroundColor Green -NoNewline
        Write-Host "$Name" -NoNewline
        if ($Actual) { Write-Host "  ($Actual)" -ForegroundColor DarkGray } else { Write-Host '' }
    } else {
        Write-Host '  [FAIL] ' -ForegroundColor Red -NoNewline
        Write-Host "$Name" -ForegroundColor Red
        if ($Actual) { Write-Host "         actual : $Actual" -ForegroundColor Yellow }
        if ($Why)    { Write-Host "         meaning: $Why"   -ForegroundColor Magenta }
    }
}

Write-Host ''
Write-Host 'Lockout test helpers loaded: Hit, Login, Register, GetUser, Check' -ForegroundColor Cyan
Write-Host "Target: $global:LockoutBaseUrl" -ForegroundColor DarkGray
Write-Host 'Run every test block in THIS window - $T, $V, $P, $ID are session state.' -ForegroundColor DarkGray
Write-Host ''
