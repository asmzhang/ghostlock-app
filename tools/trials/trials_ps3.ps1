param(
    [int]$Rounds = 10,
    [string]$Dev = "3e6f1443",
    [int]$PollSeconds = 70,
    [int]$SettleSeconds = 20,
    [string]$Tag = "rounds-pathA"
)

# v3 of trials_ps2.ps1: additionally records whether the path A consumer gate
# confirmed the waiter was parked in pselect before the consumer fired, so a
# round can be read as "gate confirmed -> fired" versus "gate timed out ->
# fell back to the blind delay". -Tag names the output directory under
# build/510profile so successive fixes keep their own round archives.
$ErrorActionPreference = "Continue"
$adb = "adb"
$out = Join-Path (Get-Location) "build/510profile/$Tag"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = Join-Path $out "summary.txt"

function Test-Dev {
    $st = (& $adb -s $Dev get-state 2>$null) -join ""
    return ($st.Trim() -eq "device")
}

function Wait-Device {
    for ($i = 0; $i -lt 300; $i++) {
        if (Test-Dev) {
            $bc = (& $adb -s $Dev shell getprop sys.boot_completed 2>$null) -join ""
            if ($bc.Trim() -eq "1") { return $true }
        }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Device-Uptime {
    return ((& $adb -s $Dev shell cat /proc/uptime 2>$null) -join "").Trim()
}

function Read-NativeLog {
    return ((& $adb -s $Dev shell "run-as com.ghostlock.app cat files/.ghostlock_native.log" 2>$null) -join "`n")
}

for ($r = 1; $r -le $Rounds; $r++) {
    $stamp = Get-Date -Format "HH:mm:ss"
    if (-not (Wait-Device)) {
        "round $r : DEVICE-NEVER-CAME-BACK ($stamp)" | Add-Content $summary
        break
    }
    Start-Sleep -Seconds $SettleSeconds
    $upBefore = Device-Uptime

    & $adb -s $Dev shell "input keyevent KEYCODE_WAKEUP"      > $null 2>&1
    & $adb -s $Dev shell "input swipe 540 1800 540 600 300"   > $null 2>&1
    & $adb -s $Dev shell "run-as com.ghostlock.app sh -c 'rm -f files/.ghostlock_native.log files/.ghostlock_run_state.json'" > $null 2>&1
    & $adb -s $Dev shell "am start -n com.ghostlock.app/.ui.MainActivity" > $null 2>&1
    Start-Sleep -Seconds 7
    & $adb -s $Dev shell "input tap 540 2222" > $null 2>&1

    $verdict = ""
    $panicked = $false
    $log = ""
    for ($t = 1; $t -le ($PollSeconds / 2); $t++) {
        Start-Sleep -Seconds 2
        if (-not (Test-Dev)) { $panicked = $true; break }
        $log = Read-NativeLog
        if ($log -match "child is root!")                { $verdict = "HIT-ROOT"; break }
        if ($log -match "Write 1 failed")                { $verdict = "NOFIRE-W1FAIL"; break }
        if ($log -match "SELinux permissive")            { $verdict = "W1-OK" }
        if ($log -match "child seccomp fully bypassed")  { $verdict = "W3-OK" }
    }

    if ($panicked) {
        $verdict = "PANIC"
        if (Wait-Device) {
            Start-Sleep -Seconds 3
            $log = Read-NativeLog
        }
    }
    if (-not $verdict) { $verdict = "TIMEOUT" }

    $clean = ($log -replace "\x1b\[[0-9;]*m", "")
    Set-Content -Path (Join-Path $out "round-$r.full.log") -Value $clean

    $reserved = ""
    $gate = ""
    $gateFail = 0
    foreach ($line in ($clean -split "`n")) {
        if ($line -match "reserved .* low fds")               { $reserved = $line.Trim() }
        if ($line -match "consumer gate: waiter parked")      { $gate = "confirmed" }
        if ($line -match "consumer gate: waiter not in")      { $gateFail++ }
    }
    if (-not $gate -and $gateFail -gt 0) { $gate = "timeout x$gateFail" }
    if (-not $gate) { $gate = "not-armed" }

    $lines = $clean -split "`n" | Where-Object { $_ -ne "" }
    $tail = ($lines | Select-Object -Last 50) -join "`n"
    Set-Content -Path (Join-Path $out "round-$r.log") -Value $tail

    $sawW1 = if ($clean -match "SELinux permissive") { "W1=ok" } else { "W1=no" }
    $reachedW2 = if ($clean -match "W2: cred") { "W2=entered" } else { "W2=no" }
    $sawW3 = if ($clean -match "child seccomp fully bypassed") { "W3=ok" }
             elseif ($clean -match "W3-0: leaf dir") { "W3=entered" }
             else { "W3=no" }
    $upAfter = ""
    if (Test-Dev) { $upAfter = Device-Uptime }
    $rec = "round $r : $verdict | $sawW1 $reachedW2 $sawW3 | gate=$gate | park='$reserved' | up_before=$upBefore | up_after=$upAfter | $stamp"
    $rec | Add-Content $summary
    Write-Output $rec
}

"=== done ===" | Add-Content $summary
