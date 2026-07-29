# GhostLock Installer (Windows)
# Run this on your PC with one supported Android device connected via ADB.

Write-Host "=== GhostLock Installer ===" -ForegroundColor Green
$installerRoot = $PSScriptRoot

# Check ADB
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    Write-Host "Error: adb not found in PATH" -ForegroundColor Red
    exit 1
}

# Do not start pushing while the device is disconnected, offline, or waiting
# for the USB-debugging authorization prompt. The old script ignored all adb
# exit codes and could report success without copying any files.
$adbOutput = @(adb devices)
$adbExitCode = $LASTEXITCODE
if ($adbExitCode -ne 0) {
    Write-Host "Error: 'adb devices' failed (adb exit code $adbExitCode)." -ForegroundColor Red
    exit 1
}

$authorizedSerials = @(
    $adbOutput | ForEach-Object {
        if ($_ -match '^\s*(\S+)\s+device\s*$') {
            $Matches[1]
        }
    }
)
$unauthorizedRows = @($adbOutput | Where-Object { $_ -match '\bunauthorized\b' })
$offlineRows = @($adbOutput | Where-Object { $_ -match '\boffline\b' })

if ($authorizedSerials.Count -ne 1) {
    if ($unauthorizedRows.Count -gt 0) {
        Write-Host "Error: device is still unauthorized. Unlock the phone and accept the USB debugging prompt, then run 'adb devices' again." -ForegroundColor Red
    }
    elseif ($offlineRows.Count -gt 0) {
        Write-Host "Error: device is offline. Reconnect USB debugging and run 'adb devices' again." -ForegroundColor Red
    }
    elseif ($authorizedSerials.Count -eq 0) {
        Write-Host "Error: no authorized adb device found. Connect the phone and verify that 'adb devices' shows status 'device'." -ForegroundColor Red
    }
    else {
        Write-Host "Error: multiple authorized adb devices found. Connect only the target phone or set an explicit device serial." -ForegroundColor Red
    }
    exit 1
}

$script:AdbSerial = $authorizedSerials[0]

$binaryPath = Join-Path $installerRoot "ghostlock"
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
    $binaryPath = Join-Path (Split-Path $installerRoot -Parent) "ghostlock"
}

function Invoke-AdbChecked {
    param(
        [Parameter(Mandatory = $true)][string[]]$AdbArguments,
        [Parameter(Mandatory = $true)][string]$Step
    )

    & adb -s $script:AdbSerial @AdbArguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: $Step failed (adb exit code $LASTEXITCODE)." -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
    Write-Host "Error: ghostlock binary not found in the installer or project root. Run 'make ghostlock' first." -ForegroundColor Red
    exit 1
}

Write-Host "Using authorized device: $script:AdbSerial"
Write-Host "Pushing files to device..." -ForegroundColor Cyan

# Push the executable.
Invoke-AdbChecked @("push", $binaryPath, "/data/local/tmp/ghostlock") "push ghostlock"

# Set permissions.
Invoke-AdbChecked @("shell", "chmod 755 /data/local/tmp/ghostlock") "set executable permissions"

Write-Host "`nInstallation complete!" -ForegroundColor Green
Write-Host "Now run on device:" -ForegroundColor Yellow
Write-Host "adb shell /data/local/tmp/ghostlock" -ForegroundColor White
Write-Host "`nThe exploit will start KernelSU and finish the su/SELinux setup." -ForegroundColor Cyan
