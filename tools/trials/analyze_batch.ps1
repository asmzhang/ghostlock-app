# Batch analyzer: per-round verdict + stage landing + death-point classification.
# Usage: powershell -File build\analyze_batch.ps1 -Tag rounds-prebuilt-b [-Baseline rounds-sprayprobe]
param(
    [Parameter(Mandatory=$true)][string]$Tag,
    [string]$Baseline = ""
)
$ErrorActionPreference = "Continue"
$dir = "build/510profile/$Tag"
if (-not (Test-Path $dir)) { Write-Error "no dir $dir"; exit 1 }

$rounds = @()
foreach ($f in (Get-ChildItem "$dir/round-*.full.log" | Sort-Object { [int](($_.BaseName -replace '\.full$','') -replace 'round-','') })) {
    $r = [int](($f.BaseName -replace '\.full$','') -replace 'round-','')
    $raw = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    $rounds += [pscustomobject]@{ r = $r; raw = $raw; name = $f.BaseName }
}

$sum = Get-Content "$dir/summary.txt" -ErrorAction SilentlyContinue | Select-String '^round '
$stats = [ordered]@{
    rounds = 0; hit = 0; panic = 0; freeze = 0
    w1_ok = 0; w2_entered = 0; w2_total = 0; w3_ok = 0
    complete = 0; prep_death = 0; pselect_death = 0
    prebuilt_ok = 0; prebuilt_used = 0
    death_w1 = 0; death_w2 = 0; death_w3 = 0; death_other = 0
}
$detail = @()
foreach ($ln in $sum) {
    if ($ln -notmatch '^round (\d+) : (\S+)') { continue }
    $r = [int]$Matches[1]; $verdict = $Matches[2]
    $stats.rounds++
    $c = ($rounds | Where-Object { $_.r -eq $r }).raw
    if (-not $c) { $detail += "r$($r): NO-LOG verdict=$verdict"; continue }
    $hit = $verdict -eq 'HIT-ROOT'
    $panic = $verdict -eq 'PANIC'
    $freeze = $verdict -eq 'FREEZE'
    if ($hit) { $stats.hit++ } elseif ($panic) { $stats.panic++ } elseif ($freeze) { $stats.freeze++ }
    $w1 = $c.Contains('SELinux permissive')
    $w2 = $c.Contains('W2: cred')
    $w3 = $c.Contains('child seccomp fully bypassed')
    $hold = $c.Contains('fork-hold parked')
    if ($w1) { $stats.w1_ok++ }
    if ($w2) { $stats.w2_entered++; $stats.w2_total++ }
    if ($w3) { $stats.w3_ok++ }
    if ($hold) { $stats.complete++ }
    if ($c.Contains('W3-0 page prebuilt ok')) { $stats.prebuilt_ok++ }
    if ($c.Contains('heap spray skipped (prebuilt')) { $stats.prebuilt_used++ }

    # death point: last non-empty line
    $lines = ($c -split "`r?`n") | Where-Object { $_.Trim() -ne '' }
    $last = $lines[-1]
    $died_in_prepare = $last -match 'early collision screen|finding futex collisions|heap spray start|step[0-9]|collision scan|mm_struct leaked' -and
                       $last -notmatch 'spray done|payload ready'
    if ($panic -and $died_in_prepare) {
        $stats.prep_death++
        if ($c -match '=== W2: cred ===') { $stats.death_w2++ } elseif ($c -match '=== W1: SELinux ===') { $stats.death_w1++ } else { $stats.death_other++ }
    } elseif ($panic) {
        $stats.pselect_death++
        $stage = if ($c -match '=== W2: cred ===') { 'W2' } elseif ($c -match '=== W1: SELinux ===') { 'W1' } elseif ($c -match '=== W3') { 'W3' } else { '?' }
        switch ($stage) { 'W1' { $stats.death_w1++ } 'W2' { $stats.death_w2++ } 'W3' { $stats.death_w3++ } default { $stats.death_other++ } }
    }
    $tail = if ($last.Length -gt 64) { $last.Substring(0,64) } else { $last }
    $detail += ("r{0} {1} W1={2} W2={3} W3={4} hold={5} death={6} :: {7}" -f $r,$verdict,(1,[int]$w1)[1-1+([int]$w1)],0,0,0,0,$tail)
}

# simpler detail rebuild
$detail = @()
foreach ($ln in $sum) {
    if ($ln -notmatch '^round (\d+) : (\S+)') { continue }
    $r = [int]$Matches[1]; $verdict = $Matches[2]
    $c = ($rounds | Where-Object { $_.r -eq $r }).raw
    if (-not $c) { $detail += "r$($r) $verdict NO-LOG"; continue }
    $lines = ($c -split "`r?`n") | Where-Object { $_.Trim() -ne '' }
    $last = $lines[-1]
    $w1 = [int]($c.Contains('SELinux permissive')); $w2 = [int]($c.Contains('W2: cred')); $w3 = [int]($c.Contains('child seccomp fully bypassed')); $hold = [int]($c.Contains('fork-hold parked'))
    $died_in_prepare = $last -match 'early collision screen|finding futex collisions|heap spray start|step[0-9]|collision scan|mm_struct leaked' -and $last -notmatch 'spray done|payload ready'
    $stage = if ($c.Contains('=== W3')) { 'W3' } elseif ($c.Contains('=== W2: cred ===')) { 'W2' } elseif ($c.Contains('=== W1: SELinux ===')) { 'W1' } else { '?' }
    $death = if ($verdict -eq 'HIT-ROOT') { '-' } elseif ($died_in_prepare) { "PREP($stage)" } else { "pselect($stage)" }
    $tail = ($last -replace '^\[\*\] ','') -replace '\s+',' '
    if ($tail.Length -gt 56) { $tail = $tail.Substring(0,56) }
    $detail += ("r{0,-3} {1,-8} W1={2} W2={3} W3={4} hold={5} {6,-12} | {7}" -f $r,$verdict,$w1,$w2,$w3,$hold,$death,$tail)
}

$out = @()
$out += "=== $Tag batch analysis ==="
$out += ("rounds={0} uid0={1} ({2}%) complete={3} panic={4} freeze={5}" -f $stats.rounds,$stats.hit,[math]::Round(100*$stats.hit/[math]::Max(1,$stats.rounds)),$stats.complete,$stats.panic,$stats.freeze)
$out += ("W1 landed={0}/{1}  W2 landed={2}/{3}  W3 verified={4}" -f $stats.w1_ok,$stats.rounds,$stats.w2_entered,$stats.w2_total,$stats.w3_ok)
$out += ("PREP-DEATH={0}  pselect-deaths={1}  (W1:{2} W2:{3} W3:{4} other:{5})" -f $stats.prep_death,$stats.pselect_death,$stats.death_w1,$stats.death_w2,$stats.death_w3,$stats.death_other)
$out += ("prebuilt prepared={0}  consumed={1}" -f $stats.prebuilt_ok,$stats.prebuilt_used)
$out += ""
$out += $detail
if ($Baseline) {
    $b = Get-Content "$dir/../$Baseline/summary.txt" -ErrorAction SilentlyContinue | Select-String '^round '
    if ($b) {
        $bn = $b.Count; $bh = ($b | Where-Object { $_ -match 'HIT-ROOT' }).Count
        $out += ""
        $out += "=== baseline $Baseline : rounds=$bn uid0=$bh ($([math]::Round(100*$bh/[math]::Max(1,$bn)))%) ==="
    }
}
$outPath = "$dir/analysis.txt"
$out | Set-Content $outPath
$out | ForEach-Object { Write-Host $_ }
Write-Host "`nwritten: $outPath"
