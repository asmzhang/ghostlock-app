# set-profile-override.ps1 - write a sparse profile override into the app's
# SharedPreferences so a trial batch can change profile tuning without
# rebuilding the APK.
#
# Why this works: the app keeps user/advanced edits as a sparse HOCON override
# map in the SharedPreferences file "ghostlock_prefs" under the key
# "debug_profile_overrides" (release -> override tree), see
# app/src/main/kotlin/com/ghostlock/app/data/AndroidProfileConfigController.kt
# (readDebugOverrides / writeAdvancedOverride, PrefDebugProfileOverrides) and
# AndroidGhostlockRepository.kt (getSharedPreferences("ghostlock_prefs")).
# The controller resolves builtin -> imported -> override, so a sparse entry
# here wins over the builtin profile for that release.
#
# The app caches the resolved profile per process, so the app is force-stopped
# after the write: the next launch re-reads the preferences.
#
# Usage:
#   # show the current override map (HOCON) for the release
#   ./set-profile-override.ps1 -Dev 3e6f1443 -Show
#   # set/replace the override map from a HOCON file
#   ./set-profile-override.ps1 -Dev 3e6f1443 -HoconFile build/tmp/ovr.conf
#   # drop the override map entirely (back to builtin)
#   ./set-profile-override.ps1 -Dev 3e6f1443 -Clear
#
# Verify on device: each run writes the effective document to
# Download/ghostlock-debug-log/<timestamp>/profile.conf - check the value there
# before trusting a measurement.

param(
    [Parameter(Mandatory = $true)][string]$Dev,
    [string]$HoconFile,
    [switch]$Show,
    [switch]$Clear
)

$ErrorActionPreference = 'Stop'
$pkg = 'com.ghostlock.app'
$prefsRel = 'shared_prefs/ghostlock_prefs.xml'
$key = 'debug_profile_overrides'

function Invoke-Adb {
    # NB: do not name the parameter $Args - that is a PowerShell automatic
    # variable, and the shadowed version splats as empty, so adb runs bare.
    # adb writes routine messages to stderr (e.g. "cat: ... No such file"),
    # which with ErrorActionPreference=Stop aborts the script; capture them as
    # data instead.
    param([string[]]$AdbArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & adb -s $Dev @AdbArgs 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
    return ($out -join "`n")
}

function Read-Prefs {
    $raw = Invoke-Adb @('shell', "run-as $pkg cat $prefsRel")
    if ($raw -match 'No such file') {
        # SharedPreferences files are created lazily: this app has never
        # written one, so start from a minimal valid document instead. Emit
        # nothing here - anything this function writes on the success stream
        # becomes part of the returned XML and corrupts the pushed file.
        return "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>" + "`n" + "<map>" + "`n" + "</map>" + "`n"
    }
    if ($raw -match 'Permission denied|not found') {
        throw "cannot read $prefsRel : $raw"
    }
    return $raw
}

function Get-OverrideValue {
    param([string]$Xml)
    $m = [regex]::Match($Xml, "<string name=`"$key`">(.*?)</string>", 'Singleline')
    if (-not $m.Success) { return $null }
    # SharedPreferences XML escapes & < > and quotes; HOCON in this key uses
    # double quotes, which Android writes as &quot;.
    return ($m.Groups[1].Value -replace '&quot;', '"' -replace '&apos;', "'" -replace '&lt;', '<' -replace '&gt;', '>' -replace '&amp;', '&')
}

function Set-OverrideValue {
    param([string]$Xml, [string]$Value)
    $escaped = $Value -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;'
    $entry = "<string name=`"$key`">$escaped</string>"
    if ([regex]::IsMatch($Xml, "<string name=`"$key`">.*?</string>", 'Singleline')) {
        return [regex]::Replace($Xml, "<string name=`"$key`">.*?</string>", $entry, 'Singleline')
    }
    # Insert before the closing </map>; XML declaration + <map> always present
    # in a SharedPreferences file.
    return [regex]::Replace($Xml, '</map>', "    $entry`n</map>")
}

if ($Show) {
    $xml = Read-Prefs
    $v = Get-OverrideValue $xml
    if ($null -eq $v) { Write-Output "(no override for $key)" } else { Write-Output $v }
    exit 0
}

if (-not $Clear -and [string]::IsNullOrWhiteSpace($HoconFile)) {
    throw "nothing to do: pass -HoconFile <path>, -Show or -Clear"
}

$xml = Read-Prefs
if ($Clear) {
    $xml = [regex]::Replace($xml, "<string name=`"$key`">.*?</string>", '', 'Singleline')
    Write-Output "=== clearing override ==="
} else {
    if (-not (Test-Path $HoconFile)) { throw "HoconFile not found: $HoconFile" }
    $hocon = (Get-Content $HoconFile -Raw).Trim()
    $xml = Set-OverrideValue $xml $hocon
    Write-Output "=== writing override ==="
    Write-Output $hocon
}

# Guard: a document that does not start with the XML declaration makes
# Android's SharedPreferences parser fail (content in prolog) and silently
# drops every preference - which looks exactly like "the override had no
# effect" in the next run's profile.conf.
if ($xml -notmatch '^\s*<\?xml') {
    throw "refusing to push: prefs document does not start with an XML declaration"
}

# Push the new XML back through run-as (the file lives in the app's private
# data dir, so only the app uid - or run-as - may write it).
$tmp = "build/tmp/ghostlock_prefs.xml"
New-Item -ItemType Directory -Force -Path (Split-Path $tmp) | Out-Null
[System.IO.File]::WriteAllText((Resolve-Path -LiteralPath (Split-Path $tmp)).Path + "/ghostlock_prefs.xml", $xml, (New-Object System.Text.UTF8Encoding($false)))

$push = Invoke-Adb @('push', $tmp, '/data/local/tmp/glk_prefs.xml')
Write-Output $push
$cp = Invoke-Adb @('shell', "run-as $pkg sh -c 'cat /data/local/tmp/glk_prefs.xml > $prefsRel'")
if ($cp -match 'denied|No such') { throw "write failed: $cp" }

# The controller caches the resolved profile per process; restart the app.
Invoke-Adb @('shell', 'am force-stop com.ghostlock.app') | Out-Null
Start-Sleep -Seconds 2
Write-Output "=== override applied; app force-stopped ==="
Write-Output "=== verify: Download/ghostlock-debug-log/<timestamp>/profile.conf of the next run ==="
