param(
    [int]$Rounds = 30,
    [string]$Dev = "3e6f1443",
    [int]$PollSeconds = 70,
    [int]$SettleSeconds = 20,
    [string]$Tag = "rounds-p01p02-c",
    [switch]$StopAfterHit,
    # v4.7: after HIT-ROOT the root child unbinds the hypervisor watchdog, which
    # means the next miss would freeze the kernel instead of rebooting. For work
    # that needs many rounds (measuring landing rates) reboot after each hit so
    # the watchdog is armed again and SELinux is back to Enforcing.
    [switch]$RebootAfterHit
)

# v4 of trials_ps3.ps1. Root cause fixed: after a HIT-ROOT the app pops the
# "日志" bottom sheet over the start button (540,2222), so v3's fixed tap
# landed on the sheet and later rounds never started a run (empty TIMEOUT).
# v4 adds Reset-AppUi (BACK + re-am start) before every tap, re-taps once if
# the native log is still empty 5s after the tap, and on HIT-ROOT waits 12s
# so the native exit tail (fork-hold parked ...) is captured, plus a ps
# snapshot for survivor identification. Verdict records hold=ok/no.
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

# v4.5: with the hypervisor watchdog unbound (P3), a miss no longer reboots the
# phone - the kernel stalls and every `adb shell` blocks forever. Plain
# `& adb ...` then hangs the harness (this is exactly what stopped the n batch
# at r19 after the device wedged). Every poll goes through this timed wrapper,
# and the sentinel "__TIMEOUT__" means "device answered adbd but the kernel
# cannot run a process" = FREEZE.
function Invoke-AdbTimed {
    param([string[]]$AdbArgs, [int]$TimeoutSec = 20)
    $tmp = [System.IO.Path]::GetTempFileName()
    $err = "$tmp.err"
    $p = Start-Process -FilePath $adb -ArgumentList $AdbArgs -RedirectStandardOutput $tmp -RedirectStandardError $err -NoNewWindow -PassThru
    $ok = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $ok) {
        try { $p.Kill() } catch {}
        Remove-Item $tmp, $err -ErrorAction SilentlyContinue
        return "__TIMEOUT__"
    }
    $text = Get-Content $tmp -Raw -ErrorAction SilentlyContinue
    Remove-Item $tmp, $err -ErrorAction SilentlyContinue
    if ($null -eq $text) { return "" }
    return $text.Trim()
}

function Device-Uptime {
    return (Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "cat /proc/uptime") -TimeoutSec 15)
}

function Read-NativeLog {
    return (Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "run-as com.ghostlock.app cat files/.ghostlock_native.log") -TimeoutSec 20)
}

# v4.3: the j-batch proved the forensics payload (kmsg-head.bin, param-*,
# pstore-*) is written by the rooted child but destroyed by the next round's
# `rm -f` before anyone copies it. Grab every forensics artefact the moment a
# HIT is confirmed. exec-out + Start-Process keeps the binary intact (a plain
# pwsh `>` would re-encode it).
function Grab-Forensics {
    param([int]$Round)
    $note = Join-Path $out "round-$Round.forensics.txt"
    $grabbed = @()
    # v4.4: the rooted child now writes world-readable forensics under
    # /data/local/tmp/glk-forensics (the app-private files/ copy came out
    # root:root 0600, unreadable by shell *and* by run-as). That directory also
    # carries kmsg-tail.bin - the continuous /dev/kmsg recorder that survives a
    # freeze or reset. Prefer it; keep files/ as a fallback for older builds.
    $listing = (& $adb -s $Dev shell "ls /data/local/tmp/glkfx /data/local/tmp/glk-forensics" 2>$null) -join "`n"
    foreach ($n in ($listing -split "`r?`n")) {
        $n = $n.Trim()
        if ($n -eq "" -or $n -match "No such file|Permission denied|^/data/local/tmp") { continue }
        # v4.6: pull BOTH directories. The two builds write the same file names,
        # and a size heuristic silently dropped the legacy copy once the new
        # recorder had more than 200 bytes - which is exactly the frozen-boot
        # kernel log (the whole point of the unlock).
        $destG = Join-Path $out "round-$Round.glk.$n"
        Start-Process -FilePath $adb -ArgumentList @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glkfx/$n") -RedirectStandardOutput $destG -NoNewWindow -Wait
        $destL = Join-Path $out "round-$Round.legacy.$n"
        Start-Process -FilePath $adb -ArgumentList @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glk-forensics/$n") -RedirectStandardOutput $destL -NoNewWindow -Wait
        foreach ($d in @($destG, $destL)) {
            $item = Get-Item $d -ErrorAction SilentlyContinue
            if ($null -eq $item -or $item.Length -lt 1) { Remove-Item $d -ErrorAction SilentlyContinue }
        }
        $grabbed += "glk/$n"
    }
    $listing2 = (& $adb -s $Dev shell "run-as com.ghostlock.app ls files" 2>$null) -join "`n"
    foreach ($n in ($listing2 -split "`r?`n")) {
        $n = $n.Trim()
        if ($n -match '^(kmsg-head\.bin|param-.+|pstore-.+|\.ghostlock_root\.sh|\.ghostlock_run_state\.json)$') {
            $dest = Join-Path $out "round-$Round.forensics.$n"
            Start-Process -FilePath $adb -ArgumentList @("-s", $Dev, "exec-out", "run-as", "com.ghostlock.app", "cat", "files/$n") -RedirectStandardOutput $dest -NoNewWindow -Wait
            $grabbed += "files/$n"
        }
    }
    if ($grabbed.Count -eq 0) { "no forensics artefacts at HIT time" | Add-Content $note; return }
    "grabbed: $($grabbed -join ', ')" | Add-Content $note
}

# v4.3: per-round device black box (build/glbb.sh) — samples /proc/stat per CPU
# at ~10 Hz plus a thread table, syncing every second, so the last seconds
# before a watchdog reset survive on disk. Restarted every round (a reset kills
# it) and pulled as round-N.bb.log for the spin-vs-deadlock analysis.
function Start-BlackBox {
    & $adb -s $Dev push (Join-Path (Get-Location) "build/glbb.sh") /data/local/tmp/glbb.sh > $null 2>&1
    & $adb -s $Dev shell "chmod 755 /data/local/tmp/glbb.sh; rm -f /data/local/tmp/glbb.log; setsid sh /data/local/tmp/glbb.sh </dev/null >/dev/null 2>&1 &" > $null 2>&1
    Start-Sleep -Seconds 1
}

function Pull-BlackBox {
    param([int]$Round)
    $dest = Join-Path $out "round-$Round.bb.log"
    Start-Process -FilePath $adb -ArgumentList @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glbb.log") -RedirectStandardOutput $dest -NoNewWindow -Wait
}

# v4.2: the start button is located dynamically per round. The i-batch showed
# (540,2222) can drift off the button (button container measured at
# [33,2080][1047,2214] → center (540,2147)) after layout changes, so every
# round dumps the UI hierarchy and taps the bottom-most clickable view,
# falling back to (540,2147) if the dump fails.

# Close any overlay (log sheet) with BACK, then re-foreground the activity so
# the start button is actually exposed before the tap.
function Reset-AppUi {
    & $adb -s $Dev shell "input keyevent KEYCODE_BACK" > $null 2>&1
    Start-Sleep -Seconds 1
    & $adb -s $Dev shell "am start -n com.ghostlock.app/.ui.MainActivity" > $null 2>&1
    Start-Sleep -Seconds 7
}

# Locate the start button. MIUI quirk: uiautomator bounds can disagree with
# the rendered pixels (i-batch: dump said y=2147, screen scan said 2197-2330),
# and the layout drifts between boots. So: dump gives a coarse hint, then a
# blue-pixel row scan of the actual screenshot refines the y (button is the
# only saturated-blue band in the lower third). Returns an "x y" string.
function Get-StartButtonPoint {
    param([string]$Fallback = "540 2264")
    $hintY = -1
    try {
        & $adb -s $Dev shell "uiautomator dump /data/local/tmp/gl-ui.xml" > $null 2>&1
        $raw = (& $adb -s $Dev shell "cat /data/local/tmp/gl-ui.xml") -join "`n"
        foreach ($m in [regex]::Matches($raw, '<node[^>]*clickable="true"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"')) {
            $cy = ([int]$m.Groups[2].Value + [int]$m.Groups[4].Value) / 2
            if ($cy -gt $hintY) { $hintY = [int]$cy }
        }
    } catch { }
    # Refine with a screenshot scan: find rows where >40 of 90 sampled pixels
    # are saturated blue (the start button), take the vertical center.
    $png = "/data/local/tmp/gl-btn.png"
    & $adb -s $Dev shell "screencap -p $png" > $null 2>&1
    & $adb -s $Dev pull $png "build/_gl_btn.png" > $null 2>&1
    $y = -1
    try {
        Add-Type -AssemblyName System.Drawing
        $bmp = [System.Drawing.Bitmap]::FromFile((Resolve-Path "build/_gl_btn.png"))
        $first = 0; $last = 0
        for ($ry = 1800; $ry -lt 2400; $ry++) {
            $cnt = 0
            for ($x = 100; $x -lt 1000; $x += 10) {
                $p = $bmp.GetPixel($x, $ry)
                if ($p.B -gt 200 -and $p.R -lt 100) { $cnt++ }
            }
            if ($cnt -gt 40) { if ($first -eq 0) { $first = $ry }; $last = $ry }
        }
        $bmp.Dispose()
        if ($first -gt 0) { $y = [int](($first + $last) / 2) }
    } catch { }
    if ($y -gt 0) { return "540 $y" }
    if ($hintY -gt 0) { return "540 $hintY" }
    return $Fallback
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
    # v4.4: the evidence dir must be traversable for adb shell. The rooted child
    # creates it 0700 root:root if it gets there first (umask), which hides the
    # kernel-log recorder; create it as shell while we still can.
    & $adb -s $Dev shell "mkdir -p /data/local/tmp/glkfx && chmod 777 /data/local/tmp/glkfx" > $null 2>&1
    & $adb -s $Dev shell "run-as com.ghostlock.app sh -c 'rm -f files/.ghostlock_native.log files/.ghostlock_run_state.json'" > $null 2>&1
    Reset-AppUi
    $btn = Get-StartButtonPoint
    Start-BlackBox
    & $adb -s $Dev shell "input tap $btn" > $null 2>&1

    # Dead-tap guard: native writes the log within ~1s of starting; an empty
    # log 5s after the tap means the tap missed the button. Re-locate and
    # re-tap (not the same coordinates — the first tap may have hit nothing).
    Start-Sleep -Seconds 5
    $early = Read-NativeLog
    if (-not $early.Trim()) {
        $btn2 = Get-StartButtonPoint -Fallback "540 2222"
        & $adb -s $Dev shell "input tap $btn2" > $null 2>&1
    }

    $verdict = ""
    $panicked = $false
    $frozen = $false
    $log = ""
    for ($t = 1; $t -le ($PollSeconds / 2); $t++) {
        Start-Sleep -Seconds 2
        if (-not (Test-Dev)) { $panicked = $true; break }
        $log = Read-NativeLog
        if ($log -eq "__TIMEOUT__")                      { $frozen = $true; break }
        if ($log -match "child is root!")                { $verdict = "HIT-ROOT"; break }
        if ($log -match "Write 1 failed")                { $verdict = "NOFIRE-W1FAIL"; break }
        if ($log -match "SELinux permissive")            { $verdict = "W1-OK" }
        if ($log -match "child seccomp fully bypassed")  { $verdict = "W3-OK" }
    }

    if ($verdict -eq "HIT-ROOT") {
        # Native exit tail (incl. fork-hold parked) lands only after native
        # exits; poll for the line instead of a fixed 12s wait. (v4.1: the
        # c-batch lost it — native was still alive 12s after HIT, and the
        # next round's rm -f deleted the tail.)
        for ($h = 0; $h -lt 20; $h++) {
            Start-Sleep -Seconds 2
            $log = Read-NativeLog
            if ($log -match "fork-hold parked") { break }
        }
        & $adb -s $Dev shell "ps -A -o pid,ppid,user,stime,comm" | Out-File -FilePath (Join-Path $out "round-$r.ps.log") -Encoding utf8
        # v4.3: copy the rooted child's forensics out of files/ before the next
        # round wipes them (j-batch lost all three HIT payloads this way).
        Grab-Forensics -Round $r
    }
    if ($panicked) {
        $verdict = "PANIC"
        if (Wait-Device) {
            Start-Sleep -Seconds 3
            $log = Read-NativeLog
        }
    }
    if ($frozen) {
        # Watchdog is unbound, so the kernel stalls instead of rebooting. adbd
        # still answers get-state, and `adb reboot` (a property write handled by
        # init) has been observed to work on a wedged device, so try it and wait
        # for the phone to come back before the next round.
        $verdict = "FREEZE"
        Invoke-AdbTimed -AdbArgs @("-s", $Dev, "reboot") -TimeoutSec 20 | Out-Null
        for ($w = 0; $w -lt 60; $w++) {
            Start-Sleep -Seconds 5
            $u = Device-Uptime
            if ($u -ne "__TIMEOUT__" -and $u -match "^\s*[0-9]+\.\d+") { break }
        }
        if (Wait-Device) {
            Start-Sleep -Seconds 3
            $log = Read-NativeLog
        }
    }
    if (-not $verdict) { $verdict = "TIMEOUT" }
    Pull-BlackBox -Round $r

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
    $hold = if ($clean -match "fork-hold parked pid=(\d+)") { "ok(pid=$($Matches[1]))" } else { "no" }
    $upAfter = ""
    if (Test-Dev) { $upAfter = Device-Uptime }
    $rec = "round $r : $verdict | $sawW1 $reachedW2 $sawW3 hold=$hold | gate=$gate | park='$reserved' | up_before=$upBefore | up_after=$upAfter | $stamp"
    $rec | Add-Content $summary
    Write-Output $rec

    # With the watchdog unbound (P3) a trailing miss now freezes the kernel
    # instead of rebooting, and recovery may need a physical power cycle. Stop
    # right after the hit we came for unless the run is explicitly about
    # sampling post-hit misses.
    if ($StopAfterHit -and $verdict -eq "HIT-ROOT") {
        "=== stopped after hit (StopAfterHit) ===" | Add-Content $summary
        Write-Output "=== stopped after hit ==="
        break
    }

    if ($RebootAfterHit -and $verdict -eq "HIT-ROOT") {
        "=== rebooting to re-arm the watchdog (RebootAfterHit) ===" | Add-Content $summary
        Write-Output "=== reboot after hit ==="
        # The -s $Dev selector is mandatory: other devices are usually attached
        # and a bare `adb reboot` fails with "more than one device/emulator",
        # which used to make this path report a failed recovery without ever
        # rebooting.
        (Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'reboot') -TimeoutSec 20) | Out-Null
        $prevUp = 1e9
        if ($upBefore -match "^\s*([0-9]+(?:\.[0-9]+)?)") { $prevUp = [double]$Matches[1] }
        $back = $false
        for ($w = 0; $w -lt 72; $w++) {
            Start-Sleep -Seconds 5
            $u = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'cat /proc/uptime') -TimeoutSec 8
            if ($u -eq "__TIMEOUT__" -or $u -notmatch "^\s*([0-9]+(?:\.[0-9]+)?)") { continue }
            $nowUp = [double]$Matches[1]
            # A real reboot restarts uptime well below the pre-hit value.
            if ($nowUp -ge $prevUp) { continue }
            $bc = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'getprop sys.boot_completed') -TimeoutSec 8
            if ($bc -notmatch "1") { continue }
            $back = $true
            break
        }
        if (-not $back) {
            "=== device did not answer after reboot; stopping ===" | Add-Content $summary
            Write-Output "=== reboot recovery failed ==="
            break
        }
        $enf = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'getenforce') -TimeoutSec 10
        $upNow = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'cat /proc/uptime') -TimeoutSec 10
        if ([string]::IsNullOrWhiteSpace($upNow)) { $upNow = "<no answer>" }
        "=== rebooted; uptime now $upNow; enforce=$enf ===" | Add-Content $summary
        Start-Sleep -Seconds 8
    }
}

"=== done ===" | Add-Content $summary
