<#
.SYNOPSIS
    Builds yggmail-mobile for selected Android targets and generates Kotlin bindings.

.DESCRIPTION
    Builds the yggmail-mobile Rust crate for one or more Android architectures
    using cargo-ndk, then generates Kotlin bindings via uniffi-bindgen. Targets
    are selected via positional alias/triple arguments or the -All switch. With
    no arguments the script prints usage and exits 1 — it does NOT build all
    targets silently. No files are copied automatically; a manual-copy hint is
    printed at the end.

.PREREQUISITES
    - Rust with Android targets installed:
        rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android
    - cargo-ndk installed (⚠ version not verified):
        cargo install cargo-ndk
    - Android NDK with ANDROID_NDK_HOME environment variable set:
        $env:ANDROID_NDK_HOME = 'C:\path\to\android-ndk'

.EXAMPLE
    .\build-android.ps1 arm64
    Builds only aarch64-linux-android.

.EXAMPLE
    .\build-android.ps1 arm64 x86_64
    Builds two targets.

.EXAMPLE
    .\build-android.ps1 -All
    Builds all four targets.

.EXAMPLE
    .\build-android.ps1 -Help
    Shows usage and exits.
#>

param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Tokens,

    [switch]$All,

    [switch]$Help
)

$ErrorActionPreference = 'Stop'

# ponytail: two hashtables, explicit, deterministic. Keep keys on one column.
$aliasMap = @{
    'arm64'  = 'aarch64-linux-android'
    'x86_64' = 'x86_64-linux-android'
    'arm'    = 'armv7-linux-androideabi'
    'x86'    = 'i686-linux-android'
}

$abiMap = @{
    'aarch64-linux-android'   = 'arm64-v8a'
    'x86_64-linux-android'    = 'x86_64'
    'armv7-linux-androideabi' = 'armeabi-v7a'
    'i686-linux-android'      = 'x86'
}

$allTargets = @(
    'aarch64-linux-android'
    'x86_64-linux-android'
    'armv7-linux-androideabi'
    'i686-linux-android'
)

function Show-Usage {
    Write-Host "Usage: .\build-android.ps1 [-All] [-Help] [<alias|triple> ...]"
    Write-Host ""
    Write-Host "Targets (alias -> triple):"
    Write-Host "  arm64  -> aarch64-linux-android"
    Write-Host "  x86_64 -> x86_64-linux-android"
    Write-Host "  arm    -> armv7-linux-androideabi"
    Write-Host "  x86    -> i686-linux-android"
    Write-Host ""
    Write-Host "Full triples are also accepted directly."
    Write-Host ""
    Write-Host "Flags:"
    Write-Host "  -All    build all four targets"
    Write-Host "  -Help   show this help and exit"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build-android.ps1 arm64"
    Write-Host "  .\build-android.ps1 arm64 x86_64"
    Write-Host "  .\build-android.ps1 -All"
}

# Resolve one token (alias or triple) to a canonical triple. Returns the triple
# via [ref] $canonical; returns $true on success, $false on failure.
function Resolve-Token {
    param(
        [string]$Token,
        [ref]$Canonical
    )
    if ($aliasMap.ContainsKey($Token)) {
        $Canonical.Value = $aliasMap[$Token]
        return $true
    }
    if ($abiMap.ContainsKey($Token)) {
        $Canonical.Value = $Token
        return $true
    }
    Write-Host "ERROR: unknown target '$Token'"
    Write-Host "Valid aliases: arm64, x86_64, arm, x86"
    Write-Host "Valid triples: $($allTargets -join ' ')"
    return $false
}

if ($Help) {
    Show-Usage
    exit 0
}

# ponytail: -All expands to the canonical set; otherwise resolve positional tokens. Dedup via $seen.
$selected = @()
$seen = @{}
if (-not $All) {
    foreach ($tok in $Tokens) {
        if ($null -eq $tok) { continue }
        $triple = $null
        $ok = Resolve-Token -Token $tok -Canonical ([ref]$triple)
        if (-not $ok) {
            exit 1
        }
        if (-not $seen.ContainsKey($triple)) {
            $selected += $triple
            $seen[$triple] = $true
        }
    }
} else {
    # -All: ignore any positional tokens, expand canonical set in fixed order.
    foreach ($t in $allTargets) {
        $selected += $t
    }
}

if ($selected.Count -eq 0) {
    Show-Usage
    exit 1
}

Write-Host '=== Building yggmail-mobile for Android ==='
Write-Host "Targets: $($selected -join ' ')"
Write-Host ''

foreach ($target in $selected) {
    Write-Host "--- Building for $target ---"
    & cargo ndk `
        --target $target `
        --platform 21 `
        -- build --release -p yggmail-mobile
    if ($LASTEXITCODE -ne 0) {
        throw "cargo ndk failed for target: $target"
    }
}

# Bindings are arch-independent: use the .so from the FIRST selected target,
# never a hardcoded aarch64 path (would break for x86-only builds).
$firstTriple = $selected[0]
$soPath = "target\$firstTriple\release\libyggmail_mobile.so"

Write-Host "--- Generating Kotlin bindings (from $soPath) ---"
& cargo run --bin uniffi-bindgen -- generate `
    --language kotlin `
    --out-dir kotlin-bindings `
    $soPath
if ($LASTEXITCODE -ne 0) {
    throw 'uniffi-bindgen failed'
}

Write-Host ''
Write-Host '=== Done! ==='
Write-Host 'Kotlin bindings: kotlin-bindings\uniffi\yggmail_mobile\'
Write-Host ''
Write-Host 'Copy manually to Android project:'
foreach ($target in $selected) {
    $abi = $abiMap[$target]
    Write-Host "  target\$target\release\libyggmail_mobile.so  ->  app\src\main\jniLibs\$abi\libyggmail_mobile.so"
}
Write-Host '  kotlin-bindings\uniffi\yggmail_mobile\yggmail_mobile.kt  ->  app\src\main\java\uniffi\yggmail_mobile\'
