# APatch jailbreak finisher for marble (my2-proven sequence, 2026-09-11).
# Prereq: a hit just landed -> kernelpatch.ko is Live (check /proc/modules via
# kpatch sucompat `su`, which the shell uid 2000 passes by default).
#
# Steps:
#   1. verify kernelpatch Live + temp su works (context u:r:kernel:s0 is fine)
#   2. soft-reboot (framework only; the kernel keeps the module)
#   3. wait for framework, fix sys.boot_completed (soft-reboot clears it and
#      nothing sets it back -> the manager would wait forever)
#   4. restart the APatch manager, then verify `su -c id` shows uid=0 +
#      context=u:r:magisk:s0 (the real APatch root, not the kernel domain)
param(
    [string]$Dev = "3e6f1443",
    [int]$SoftRebootWaitSec = 50
)
$ErrorActionPreference = "Continue"
$env:PATH = "D:\platform\Android\Sdk\platform-tools;" + $env:PATH

function Invoke-Adb([string[]]$AdbArgs, [int]$TimeoutSec = 25) {
    $p = Start-Process -FilePath adb -ArgumentList (@("-s", $Dev) + $AdbArgs) `
        -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\apd_out.txt" -RedirectStandardError "$env:TEMP\apd_err.txt"
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        return "__TIMEOUT__"
    }
    return ((Get-Content "$env:TEMP\apd_out.txt" -Raw -ErrorAction SilentlyContinue) + (Get-Content "$env:TEMP\apd_err.txt" -Raw -ErrorAction SilentlyContinue))
}

"=== step 1: verify kernelpatch Live + temp su ==="
$mods = Invoke-Adb @("shell", "su -c 'grep kernelpatch /proc/modules'")
"modules: $mods"
$su1 = Invoke-Adb @("shell", "su -c id")
"su: $su1"
if ($mods -eq "__TIMEOUT__" -or $mods -notmatch "kernelpatch") {
    "VERDICT: kernelpatch not Live; aborting (no soft-reboot)"
    exit 1
}

"=== step 2: soft-reboot (framework only) ==="
$null = Invoke-Adb @("shell", "su -c 'chmod 755 /data/adb/ap/bin/apd 2>/dev/null; /data/adb/ap/bin/apd soft-reboot'") 25
"soft-reboot issued $(Get-Date -Format HH:mm:ss)"

"=== step 3: wait for framework ==="
Start-Sleep -Seconds $SoftRebootWaitSec
$up1 = Invoke-Adb @("shell", "cat /proc/uptime")
"uptime after soft-reboot: $up1  (must be far below pre-reboot total)"

"=== step 4: fix boot_completed + restart manager ==="
$mods2 = Invoke-Adb @("shell", "su -c 'grep kernelpatch /proc/modules'")
"kernelpatch still Live: $mods2"
$null = Invoke-Adb @("shell", "su -c '/data/adb/ap/bin/apd resetprop sys.boot_completed 1'")
$bc = Invoke-Adb @("shell", "getprop sys.boot_completed")
"boot_completed now: $bc"
$null = Invoke-Adb @("shell", "am force-stop me.bmax.apatch")
$null = Invoke-Adb @("shell", "am start -n me.bmax.apatch/me.bmax.apatch.ui.MainActivity")
Start-Sleep -Seconds 8

"=== step 5: final verdict ==="
$su2 = Invoke-Adb @("shell", "su -c id")
"su after jailbreak: $su2"
if ($su2 -match "uid=0" -and $su2 -match "magisk") {
    "VERDICT: SUCCESS - APatch root available (u:r:magisk:s0)"
} elseif ($su2 -match "uid=0") {
    "VERDICT: PARTIAL - su works but context is not magisk; check package_config"
} else {
    "VERDICT: FAILED - su not usable after soft-reboot"
}
