<#
.SYNOPSIS
    Validates the Postman collection and environment before importing them.

.DESCRIPTION
    Postman fails opaquely on a bad collection: a script with a syntax error
    still shows the request as "sent" while every assertion in it silently stops
    running, and a hardcoded credential wedges the importer on the "Secrets
    Detected" dialog with no way back. Both happened to this collection. This
    script catches each class before the file reaches Postman.

    Checks, in order of how loudly they fail:
      1  both files are valid JSON, valid UTF-8, no BOM
      2  the collection matches the v2.1.0 schema Postman expects
      3  every script parses as real JavaScript (node, not a regex)
      4  no hardcoded bearer token or basic-auth password (import blocker)
      5  no {{var}} that is never set, and none used before it is set
      6  the environment has no duplicate or disabled keys
      7  the #7b discovery requests are present

    Requires python and node, both already used by this repo's tooling.

.EXAMPLE
    .\postman\verify-collection.ps1
#>

[CmdletBinding()]
param(
    [string]$Collection,
    [string]$Environment
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0

# Resolved here rather than as a param default: in Windows PowerShell 5.1
# $PSScriptRoot is not yet populated while parameters are being bound, so a
# default built from it silently becomes a bare filename.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Collection) { $Collection = Join-Path $here 'EMC-Auth.postman_collection.json' }
if (-not $Environment) { $Environment = Join-Path $here 'EMC-Auth.local.postman_environment.json' }

function Write-Section($Title) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkGray
}

function Write-Pass($Message) { Write-Host "  [PASS] $Message" -ForegroundColor Green }
function Write-Fail($Message) {
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
    $script:Failures++
}

Write-Host ''
Write-Host 'EMC Auth - Postman collection verification' -ForegroundColor White
Write-Host "  collection : $Collection" -ForegroundColor DarkGray
Write-Host "  environment: $Environment" -ForegroundColor DarkGray

foreach ($path in @($Collection, $Environment)) {
    if (-not (Test-Path $path)) {
        Write-Fail "file not found: $path"
        exit 1
    }
}

# --- 1. Encoding and JSON validity ----------------------------------------
Write-Section '1. Encoding and JSON validity'

foreach ($path in @($Collection, $Environment)) {
    $name = Split-Path $path -Leaf
    $bytes = [System.IO.File]::ReadAllBytes($path)

    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Fail "$name has a UTF-8 BOM (Postman's parser chokes on it)"
    }
    else {
        Write-Pass "$name has no BOM"
    }

    try {
        $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
        [void]$utf8Strict.GetString($bytes)
        Write-Pass "$name is valid UTF-8"
    }
    catch {
        Write-Fail "$name is NOT valid UTF-8: $($_.Exception.Message)"
    }

    try {
        [void](Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json)
        Write-Pass "$name is valid JSON  ($([math]::Round($bytes.Length / 1KB)) KB)"
    }
    catch {
        Write-Fail "$name is NOT valid JSON: $($_.Exception.Message)"
    }
}

# --- 2. Collection schema --------------------------------------------------
Write-Section '2. Collection schema'

$coll = Get-Content $Collection -Raw -Encoding UTF8 | ConvertFrom-Json
$expectedSchema = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'

if ($coll.info.schema -eq $expectedSchema) {
    Write-Pass "schema is v2.1.0"
}
else {
    Write-Fail "unexpected schema: $($coll.info.schema)"
}

Write-Host "         name        : $($coll.info.name)" -ForegroundColor DarkGray
Write-Host "         _postman_id : $($coll.info._postman_id)" -ForegroundColor DarkGray
Write-Host "         folders     : $($coll.item.Count)" -ForegroundColor DarkGray

# --- 3, 4, 5, 6, 7 : delegated to node / python ---------------------------
# These need a real JS parser and a full tree walk, which PowerShell has no
# business reimplementing. Both interpreters are already required by this repo.

Write-Section '3-7. Deep checks (scripts, secrets, variables)'

foreach ($tool in @('node', 'python')) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $found) {
        Write-Fail "$tool is not on PATH - cannot run the deep checks"
        exit 1
    }
}

$deepCheck = Join-Path $env:TEMP 'emc-postman-deepcheck.js'

@'
const fs = require('fs');
const vm = require('vm');

const collPath = process.argv[2];
const envPath  = process.argv[3];
const coll = JSON.parse(fs.readFileSync(collPath, 'utf8'));
const env  = JSON.parse(fs.readFileSync(envPath, 'utf8'));

let failures = 0;
const pass = m => console.log('  [PASS] ' + m);
const fail = m => { console.log('  [FAIL] ' + m); failures++; };
const info = m => console.log('         ' + m);

// Flatten every request in run order, and collect folder-level scripts too --
// folders carry a pre-request script that stamps their name for the diagnostic,
// so skipping them would leave 14 scripts unchecked.
const flat = [];
const folderEvents = [];
(function walk(items, folder) {
  for (const it of items) {
    if (it.item) {
      for (const e of it.event || []) folderEvents.push({ name: `folder:${it.name}`, e });
      walk(it.item, it.name);
      continue;
    }
    flat.push({ folder, req: it });
  }
})(coll.item, '<root>');

// ---- 3. every script parses as JavaScript --------------------------------
let scripts = 0;
const brokenScripts = [];
const checkScript = (name, listen, exec) => {
  scripts++;
  try { new vm.Script(exec.join('\n'), { filename: name }); }
  catch (e) { brokenScripts.push(`${name} [${listen}]: ${e.message}`); }
};
for (const e of coll.event || []) checkScript('<collection>', e.listen, e.script.exec);
for (const { name, e } of folderEvents) checkScript(name, e.listen, e.script.exec);
for (const { req } of flat) for (const e of req.event || []) checkScript(req.name, e.listen, e.script.exec);

if (brokenScripts.length === 0) {
  pass(`all ${scripts} scripts parse as JavaScript`);
} else {
  fail(`${brokenScripts.length} of ${scripts} scripts do NOT parse`);
  brokenScripts.forEach(b => info('  ' + b.replace(/[^\x20-\x7e]/g, '?')));
  info('  a parse error means EVERY assertion in that request silently stops running');
}

// ---- 4. no hardcoded secrets (the import blocker) ------------------------
const JWT = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;
const secrets = [];
for (const { folder, req } of flat) {
  const rq = req.request || {};
  for (const h of rq.header || []) {
    const v = String(h.value || '');
    if (JWT.test(v)) secrets.push(`${folder} / ${req.name} -> header ${h.key} contains a literal JWT`);
    else if (String(h.key).toLowerCase() === 'authorization' && v && !v.includes('{{'))
      secrets.push(`${folder} / ${req.name} -> hardcoded Authorization: ${v.slice(0, 40)}`);
  }
  const auth = rq.auth || {};
  for (const kind of ['basic', 'bearer']) {
    for (const entry of auth[kind] || []) {
      const v = String(entry.value || '');
      if (v && !v.includes('{{'))
        secrets.push(`${folder} / ${req.name} -> hardcoded auth.${kind}.${entry.key}: ${v.slice(0, 30)}`);
    }
  }
}
if (secrets.length === 0) {
  pass('no hardcoded tokens or auth passwords - Postman will not block the import');
} else {
  fail(`${secrets.length} hardcoded secret(s) - Postman will wedge on "Secrets Detected"`);
  secrets.forEach(s => info('  ' + s.replace(/[^\x20-\x7e]/g, '?')));
}

// ---- 5. variable resolution ---------------------------------------------
const SET = /pm\.(?:environment|collectionVariables|globals|variables)\.set\(\s*'([^']+)'/g;
const REF = /\{\{([^}]+)\}\}/g;

const envKeys = new Set(env.values.map(v => v.key));
const collVars = new Set((coll.variable || []).map(v => v.key));

const collectionSets = new Set();
for (const e of coll.event || []) {
  const src = e.script.exec.join('\n');
  let m; const re = new RegExp(SET.source, 'g');
  while ((m = re.exec(src))) collectionSets.add(m[1]);
}

const setAt = new Map();
flat.forEach(({ req }, idx) => {
  for (const e of req.event || []) {
    const src = e.script.exec.join('\n');
    let m; const re = new RegExp(SET.source, 'g');
    while ((m = re.exec(src))) if (!setAt.has(m[1])) setAt.set(m[1], idx);
  }
});

// Harvested automatically by the collection-level test script.
const AUTO = new Set(['access_token','refresh_token','session_token','mfa_token','login_code',
  'client_id','client_secret','api_key','reset_token','kid','jwks_url','totp_secret','otpauth_url',
  'id','tenant_id','user_id','application_id','role_id','permission_id','api_key_id','new_tenant_id']);

const unknown = [], early = [];
flat.forEach(({ folder, req }, idx) => {
  const blob = JSON.stringify(req);
  let m; const re = new RegExp(REF.source, 'g');
  const seen = new Set();
  while ((m = re.exec(blob))) {
    const v = m[1].trim();
    if (seen.has(v) || v.startsWith('$')) continue;
    seen.add(v);
    const known = envKeys.has(v) || collVars.has(v) || collectionSets.has(v) || setAt.has(v) || AUTO.has(v);
    if (!known) unknown.push(`${folder} / ${req.name} -> {{${v}}}`);
    else if (setAt.has(v) && setAt.get(v) > idx && !envKeys.has(v))
      early.push(`${folder} / ${req.name} -> {{${v}}} is set later, by "${flat[setAt.get(v)].req.name}"`);
  }
});

if (unknown.length === 0) pass('every {{variable}} resolves to something');
else { fail(`${unknown.length} unresolvable {{variable}}(s)`); unknown.forEach(u => info('  ' + u.replace(/[^\x20-\x7e]/g, '?'))); }

if (early.length === 0) pass('no variable is referenced before the request that sets it');
else { fail(`${early.length} used-before-set`); early.forEach(u => info('  ' + u.replace(/[^\x20-\x7e]/g, '?'))); }

// ---- 6. environment hygiene ----------------------------------------------
const keys = env.values.map(v => v.key);
const dupes = [...new Set(keys.filter(k => keys.filter(x => x === k).length > 1))];
const disabled = env.values.filter(v => v.enabled === false).map(v => v.key);
if (dupes.length === 0) pass(`environment has ${keys.length} variables, no duplicates`);
else fail('duplicate environment keys: ' + dupes.join(', '));
if (disabled.length === 0) pass('no disabled environment variables');
else fail('disabled environment variables (they resolve as empty): ' + disabled.join(', '));

// ---- 7. the #7b discovery requests ---------------------------------------
const discovery = flat.filter(f => f.req.name.includes('#7b')).map(f => f.req.name);
if (discovery.length >= 4) {
  pass(`#7b discovery requests present (${discovery.length})`);
  discovery.forEach(n => info('  ' + n.replace(/[^\x20-\x7e]/g, '?')));
} else {
  fail(`expected 4 #7b requests, found ${discovery.length} - is this the updated file?`);
}

info('');
info(`total requests: ${flat.length}   total scripts: ${scripts}`);
process.exit(failures === 0 ? 0 : 1);
'@ | Set-Content -Path $deepCheck -Encoding utf8

node $deepCheck $Collection $Environment
if ($LASTEXITCODE -ne 0) { $script:Failures++ }
Remove-Item $deepCheck -ErrorAction SilentlyContinue

# --- Summary ---------------------------------------------------------------
Write-Section 'Summary'

if ($script:Failures -eq 0) {
    Write-Host '  ALL CHECKS PASSED - safe to import into Postman.' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Import: Postman > Import > File > select BOTH files.' -ForegroundColor DarkGray
    Write-Host '  The collection reuses its _postman_id, so Postman UPDATES the existing' -ForegroundColor DarkGray
    Write-Host '  "EMC Auth Server" collection in place rather than adding a second copy.' -ForegroundColor DarkGray
    Write-Host '  Confirm it landed: folder 11 should now end with four (#7b) requests.' -ForegroundColor DarkGray
    exit 0
}

Write-Host "  $($script:Failures) CHECK(S) FAILED - fix before importing." -ForegroundColor Red
exit 1
