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
    [switch]$RebootAfterHit,
    # v4.8: reboot after every Nth HIT-ROOT instead of after every one. Same-boot
    # runs skip W1 (check_selinux_off() short-circuits the SELinux stage once the
    # first hit left the policy permissive), so each later round needs one pselect
    # instead of two -- and a miss after a hit freezes (watchdog already unbound)
    # rather than rebooting, which the FREEZE recovery path handles. N=0 disables.
    [int]$RebootEveryHits = 0,
    # v4.10: cold-boot arm. A batch is not state-neutral: rounds sharing a boot
    # inherit whatever the previous round left behind (permissive SELinux,
    # kernelsu loaded, panic_on_oops=0, hypervisor watchdog unbound), and the
    # landing rate is measured to drift ~3.5x between a fresh boot and a used
    # one. Any A/B on a rate must draw both arms from the same state class, so
    # this reboots before EVERY round; the summary's up_before then proves it
    # (a fresh boot is well under ~120s).
    [switch]$RebootEveryRound
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
# v4.8: HIT-ROOT counter for -RebootEveryHits.
$hitCount = 0

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

# v4.9: binary-safe timed pull. Grab-Forensics and Pull-BlackBox used
# `Start-Process -Wait` with no timeout, so a wedged kernel (adbd still answers
# `get-state`, but no process can run) hung the whole harness before it could
# even write summary.txt - exactly what stopped the ov3 test round. Redirect
# straight to a file so binary payloads stay intact, but bound the wait and
# kill the stuck client. Partial content is kept: even a truncated kernel log
# is evidence. Returns $false when the pull timed out.
function Invoke-AdbToFile {
    param([string[]]$AdbArgs, [string]$Dest, [int]$TimeoutSec = 25)
    $err = "$Dest.err"
    $p = Start-Process -FilePath $adb -ArgumentList $AdbArgs -RedirectStandardOutput $Dest -RedirectStandardError $err -NoNewWindow -PassThru
    $ok = $p.WaitForExit($TimeoutSec * 1000)
    if (-not $ok) { try { $p.Kill() } catch {}; return $false }
    Remove-Item $err -ErrorAction SilentlyContinue
    return $true
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
    $listing = Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "ls /data/local/tmp/glkfx /data/local/tmp/glk-forensics") -TimeoutSec 20
    if ($listing -eq "__TIMEOUT__") { $listing = "" }
    foreach ($n in ($listing -split "`r?`n")) {
        $n = $n.Trim()
        if ($n -eq "" -or $n -match "No such file|Permission denied|^/data/local/tmp") { continue }
        # v4.6: pull BOTH directories. The two builds write the same file names,
        # and a size heuristic silently dropped the legacy copy once the new
        # recorder had more than 200 bytes - which is exactly the frozen-boot
        # kernel log (the whole point of the unlock).
        $destG = Join-Path $out "round-$Round.glk.$n"
        Invoke-AdbToFile -AdbArgs @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glkfx/$n") -Dest $destG | Out-Null
        $destL = Join-Path $out "round-$Round.legacy.$n"
        Invoke-AdbToFile -AdbArgs @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glk-forensics/$n") -Dest $destL | Out-Null
        foreach ($d in @($destG, $destL)) {
            $item = Get-Item $d -ErrorAction SilentlyContinue
            if ($null -eq $item -or $item.Length -lt 1) { Remove-Item $d -ErrorAction SilentlyContinue }
        }
        $grabbed += "glk/$n"
    }
    $listing2 = Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "run-as com.ghostlock.app ls files") -TimeoutSec 20
    if ($listing2 -eq "__TIMEOUT__") { $listing2 = "" }
    foreach ($n in ($listing2 -split "`r?`n")) {
        $n = $n.Trim()
        if ($n -match '^(kmsg-head\.bin|param-.+|pstore-.+|\.ghostlock_root\.sh|\.ghostlock_run_state\.json)$') {
            $dest = Join-Path $out "round-$Round.forensics.$n"
            Invoke-AdbToFile -AdbArgs @("-s", $Dev, "exec-out", "run-as", "com.ghostlock.app", "cat", "files/$n") -Dest $dest | Out-Null
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
    Invoke-AdbTimed -AdbArgs @("-s", $Dev, "push", (Join-Path (Get-Location) "build/glbb.sh"), "/data/local/tmp/glbb.sh") -TimeoutSec 30 | Out-Null
    Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "chmod 755 /data/local/tmp/glbb.sh; rm -f /data/local/tmp/glbb.log; setsid sh /data/local/tmp/glbb.sh </dev/null >/dev/null 2>&1 &") -TimeoutSec 20 | Out-Null
    Start-Sleep -Seconds 1
}

function Pull-BlackBox {
    param([int]$Round)
    $dest = Join-Path $out "round-$Round.bb.log"
    Invoke-AdbToFile -AdbArgs @("-s", $Dev, "exec-out", "cat", "/data/local/tmp/glbb.log") -Dest $dest | Out-Null
}

# v4.2: the start button is located dynamically per round. The i-batch showed
# (540,2222) can drift off the button (button container measured at
# [33,2080][1047,2214] → center (540,2147)) after layout changes, so every
# round dumps the UI hierarchy and taps the bottom-most clickable view,
# falling back to (540,2147) if the dump fails.

# Close any overlay (log sheet) with BACK, then re-foreground the activity so
# the start button is actually exposed before the tap.
function Reset-AppUi {
    Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "input keyevent KEYCODE_BACK") -TimeoutSec 15 | Out-Null
    Start-Sleep -Seconds 1
    Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "am start -n com.ghostlock.app/.ui.MainActivity") -TimeoutSec 20 | Out-Null
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

# Host-side kernel log capture. `logcat -b kernel` is pumped by adbd over the
# host's own transport, so it can still deliver the last kernel lines when a
# miss wedges the device: on 2026-10-14 14:44 the frozen device answered
# `adb get-state` but timed out on both `adb shell` and `adb pull`, i.e. the
# on-device recorder (f2fs under /data/local/tmp) was unreadable. Start this
# before the round loop; it is stopped after the loop.
$kernelLog = Join-Path $out "kernel.log"
$kernelCapture = $null
try {
    $adbExe = (Get-Command $adb -ErrorAction SilentlyContinue).Source
    if ([string]::IsNullOrWhiteSpace($adbExe)) { $adbExe = $adb }
    $kernelCapture = Start-Process -FilePath $adbExe -ArgumentList @('-s', $Dev, 'logcat', '-b', 'kernel', '-v', 'time') -RedirectStandardOutput $kernelLog -NoNewWindow -PassThru
    Write-Output "=== kernel log capture -> $kernelLog (pid $($kernelCapture.Id)) ==="
} catch {
    Write-Output "=== kernel log capture failed to start: $_ ==="
}

for ($r = 1; $r -le $Rounds; $r++) {
    $stamp = Get-Date -Format "HH:mm:ss"
    if ($RebootEveryRound) {
        # Cold-boot the arm: no round may inherit the previous round's kernel
        # state. Reboot first, then wait for boot_completed and the settle
        # margin, so up_before below is the proof that this round started fresh.
        Invoke-AdbTimed -AdbArgs @("-s", $Dev, "reboot") -TimeoutSec 20 | Out-Null
        if (-not (Wait-Device)) {
            "round $r : DEVICE-NEVER-CAME-BACK-AFTER-COLD-BOOT ($stamp)" | Add-Content $summary
            break
        }
        Start-Sleep -Seconds $SettleSeconds
        $fresh = Device-Uptime
        if ($fresh -and $fresh -notmatch "__") {
            $secs = [double]($fresh -split "\s+")[0]
            if ($secs -gt 300) {
                "round $r : WARN cold boot did not take; uptime=${secs}s (measurement is not isolated)" | Add-Content $summary
                Write-Output "=== WARN round $r : cold boot did not take; uptime=${secs}s ==="
            }
        }
    }
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
    # v4.10: kill the previous process before the run, so the log below starts
    # empty. Kept from the rounds-multi-cold investigation, but that batch's
    # three "stale log" rounds (2/3/5) are now known to have been real HIT-ROOTs
    # whose per-stage flags read "no" for the v4.11 reason, not because a live
    # process re-created the log: see the $verdictLog snapshot below.
    & $adb -s $Dev shell "am force-stop com.ghostlock.app" > $null 2>&1
    Start-Sleep -Milliseconds 800
    & $adb -s $Dev shell "run-as com.ghostlock.app sh -c 'rm -f files/.ghostlock_native.log files/.ghostlock_run_state.json files/ghostlock-ksu-*.log files/.ghostlock_sh_probe'" > $null 2>&1
    $logState = ((& $adb -s $Dev shell "run-as com.ghostlock.app sh -c 'test -f files/.ghostlock_native.log && echo present || echo absent'" 2>$null) -join "").Trim()
    if ($logState -ne "absent") {
        "round $r : WARN stale native log not cleared (state=$logState); verdict may not be this round's" | Add-Content $summary
        Write-Output "=== WARN round $r : stale native log not cleared (state=$logState) ==="
    }
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

    # v4.11: the verdict log is a snapshot, not a live handle. rounds-leaf1 rounds
    # 5 and 9 were real HIT-ROOTs whose per-stage flags all read "no": the
    # HIT-ROOT branch below re-reads the log for up to 40s waiting for
    # "fork-hold parked", and if the app exits inside that window the file comes
    # back empty - so round-N.full.log kept 2 bytes, every flag read "no", and
    # the tallies silently turned two hits into "stale log" rounds. Keep the
    # verdict-time copy and fall back to it whenever the later read is shorter.
    $verdictLog = $log

    $missed = $false
    if (-not $verdict) {
        # No terminal verdict inside the poll window. Two very different cases:
        #  - the tap missed and native never started: the log is empty
        #  - the run was attempted and the pselect never returned: the log ends
        #    at "consumer gate: waiter parked in syscall 72" (baseline round 7,
        #    2026-10-14). That is a MISS, and it leaves a kernel task stuck on
        #    the PI lock: the device stays reachable (round 7's up_after was
        #    readable), but the NEXT run deadlocks the kernel - round 8 of that
        #    same batch froze the device. Reboot before the next round instead
        #    of letting the poison accumulate into a freeze.
        if ($log -match "consumer gate: waiter parked in syscall" -and $log -notmatch "pselect route done") {
            $verdict = "MISS"
            $missed = $true
        } else {
            $verdict = "TIMEOUT"
        }
    }

    if ($verdict -eq "HIT-ROOT") {
        # Native exit tail (incl. fork-hold parked) lands only after native
        # exits; poll for the line instead of a fixed 12s wait. (v4.1: the
        # c-batch lost it — native was still alive 12s after HIT, and the
        # next round's rm -f deleted the tail.)
        # v4.12: the 40s window truncated the W3+handoff long tail —
        # rounds-prebuilt r4's log ended at "handoff: script open fd=320"
        # while the 239MB kmsg tail proved KernelSU had loaded (ksud
        # tp_marker: unmark lines). The root script's own log is the honest
        # completion marker: wait for it (or the native tail) up to 90s, and
        # snapshot the ksu log whether or not the native tail arrives.
        $ksuLogGrabbed = $false
        for ($h = 0; $h -lt 45; $h++) {
            Start-Sleep -Seconds 2
            $log = Read-NativeLog
            if ($log -match "fork-hold parked") { break }
            if (-not $ksuLogGrabbed) {
                $ksuProbe = Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "run-as com.ghostlock.app sh -c 'ls -t files/ghostlock-ksu-*.log 2>/dev/null | head -1'") -TimeoutSec 15
                if ($ksuProbe -ne "__TIMEOUT__" -and $ksuProbe -match "ghostlock-ksu-\d+\.log") {
                    $ksuName = $Matches[0]
                    Invoke-AdbToFile -AdbArgs @("-s", $Dev, "exec-out", "run-as", "com.ghostlock.app", "cat", "files/$ksuName") -Dest (Join-Path $out "round-$r.ksu.log") | Out-Null
                    $ksuLogGrabbed = $true
                }
            }
        }
        # v4.9: timed - this dump runs in the post-HIT window, which is exactly
        # where a trailing miss wedges the kernel (a plain `& adb` hung here).
        $psOut = Invoke-AdbTimed -AdbArgs @("-s", $Dev, "shell", "ps -A -o pid,ppid,user,stime,comm") -TimeoutSec 20
        if ($psOut -ne "__TIMEOUT__") { $psOut | Out-File -FilePath (Join-Path $out "round-$r.ps.log") -Encoding utf8 }
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
    if ($missed) {
        # A miss leaves a task stuck on the kernel's PI lock. The device is
        # still reachable right after it (that is why this reboot works while
        # the FREEZE one often cannot), so clear the boot here: running another
        # round on top of the stuck task is what produced the freeze.
        Invoke-AdbTimed -AdbArgs @("-s", $Dev, "reboot") -TimeoutSec 20 | Out-Null
        for ($w = 0; $w -lt 60; $w++) {
            Start-Sleep -Seconds 5
            $u = Device-Uptime
            if ($u -ne "__TIMEOUT__" -and $u -match "^\s*[0-9]+\.\d+") { break }
        }
        if (Wait-Device) { Start-Sleep -Seconds 3 }
    }
    if (-not $verdict) { $verdict = "TIMEOUT" }
    Pull-BlackBox -Round $r

    # v4.11: never let a late, truncated re-read erase the verdict. A shorter
    # read means the app truncated its log after the verdict, not that the
    # stages never ran.
    if ($log.Length -lt $verdictLog.Length) { $log = $verdictLog }

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
    $hold = if ($clean -match "fork-hold parked pid=(\d+)") { "ok(pid=$($Matches[1]))" }
            elseif ((Test-Path (Join-Path $out "round-$r.ksu.log")) -and
                    ((Get-Content (Join-Path $out "round-$r.ksu.log") -Raw -ErrorAction SilentlyContinue) -match "KernelSU module loaded")) { "ok(ksu-log)" }
            else { "no" }
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

    if ($verdict -eq "HIT-ROOT") { $hitCount++ }
    $periodicReboot = ($RebootEveryHits -gt 0 -and $verdict -eq "HIT-ROOT" -and
                       ($hitCount % $RebootEveryHits) -eq 0)
    if (($RebootAfterHit -and $verdict -eq "HIT-ROOT") -or $periodicReboot) {
        $why = if ($RebootAfterHit) { "RebootAfterHit" }
               else { "RebootEveryHits=$RebootEveryHits at hit #$hitCount" }
        "=== rebooting to re-arm the watchdog ($why) ===" | Add-Content $summary
        Write-Output "=== reboot after hit ==="
        # The -s $Dev selector is mandatory: other devices are usually attached
        # and a bare `adb reboot` fails with "more than one device/emulator",
        # which used to make this path report a failed recovery without ever
        # rebooting.
        #
        # v4.9: `adb reboot` runs init's orderly shutdown, which terminates every
        # process -- including the fork-hold child P0-1 parks to keep the reclaim
        # sockets alive. Releasing those sockets runs
        # unix_release_sock -> put_page on a page carved out of the kernel image
        # that never had its refcount raised ("BUG: Bad page state"), and the
        # root script has already turned panic_on_oops off, so that oops lands
        # mid-shutdown and wedges the kernel instead of resetting it: the device
        # sits in `adb offline` until it is power-cycled by hand (2026-10-15, the
        # rounds-w3fix batch, round 2 hit then never came back).
        #
        # `reboot -f` jumps straight to the kernel restart, so no process exits
        # and nothing is released. After a HIT-ROOT KernelSU su is up, which is
        # exactly when this path runs; the poll below falls back to `adb reboot`
        # if su is missing or the forced reset does not take.
        $down = $false
        $suReboot = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'su', '-c', '"reboot -f"') -TimeoutSec 25
        if ($suReboot -eq "__TIMEOUT__") { $down = $true }
        if (-not $down) {
            for ($d = 0; $d -lt 8; $d++) {
                Start-Sleep -Seconds 2
                $u = Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'shell', 'cat /proc/uptime') -TimeoutSec 5
                if ($u -eq "__TIMEOUT__" -or $u -notmatch "^\s*([0-9]+(?:\.[0-9]+)?)") { $down = $true; break }
            }
        }
        if (-not $down) {
            "=== forced reboot did not take; falling back to adb reboot ===" | Add-Content $summary
            (Invoke-AdbTimed -AdbArgs @('-s', $Dev, 'reboot') -TimeoutSec 20) | Out-Null
        }
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

if ($kernelCapture -and -not $kernelCapture.HasExited) {
    try { $kernelCapture.Kill() } catch { }
}
Write-Output "=== kernel log capture stopped ($kernelLog) ==="
