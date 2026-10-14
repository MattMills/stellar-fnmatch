# run_checks.ps1 -LuaJit <luajit.exe> -Module <module.lua> [-Slices 128] [-Jobs 4] [-Out <dir>]
# Windows counterpart of run_checks.sh: check.lua's layout and declaration checks over a
# generated module, in parallel slices (one LuaJIT state each), summed up. Keep paths short:
# LuaJIT's loaders fail on long Windows paths.
param(
    [Parameter(Mandatory = $true)][string]$LuaJit,
    [Parameter(Mandatory = $true)][string]$Module,
    [int]$Slices = 128,
    [int]$Jobs = 4,
    [string]$Out = (Join-Path $env:TEMP "ffi_checks")
)
$check = Join-Path $PSScriptRoot "check.lua"
New-Item -ItemType Directory -Force $Out | Out-Null
foreach ($what in "layouts", "decls") {
    $running = @()
    for ($i = 1; $i -le $Slices; $i++) {
        while (($running | Where-Object { -not $_.HasExited }).Count -ge $Jobs) { Start-Sleep -Milliseconds 200 }
        $running += Start-Process -FilePath $LuaJit -ArgumentList @($check, $what, $Module, $i, $Slices) -NoNewWindow -PassThru `
            -RedirectStandardOutput (Join-Path $Out "$what.$i.txt") -RedirectStandardError (Join-Path $Out "$what.$i.err")
    }
    $running | ForEach-Object { $_.WaitForExit() }
    $ok = 0; $fail = 0; $members = 0; $shown = 0; $reasons = @{}
    for ($i = 1; $i -le $Slices; $i++) {
        $lines = Get-Content (Join-Path $Out "$what.$i.txt")
        $last = $lines | Where-Object { $_ -like "$what ok *" } | Select-Object -Last 1
        if (-not $last) { Write-Output "$what slice $i failed: $(Get-Content (Join-Path $Out "$what.$i.err") -Raw)"; continue }
        $w = $last -split " "
        $ok += [int]$w[2]; $fail += [int]$w[4]
        if ($w.Count -ge 7) { $members += [int]$w[6] }
        foreach ($l in $lines) {
            if ($l -like "FAIL *" -and $shown -lt 20) { Write-Output $l; $shown++ }
            if ($l -like "REASON *") { $r = $l -split " "; $reasons[$r[1]] = [int]$reasons[$r[1]] + [int]$r[2] }
        }
    }
    $m = if ($members) { " (members checked $members)" } else { "" }
    Write-Output "${what}: ok $ok fail $fail$m"
    foreach ($k in $reasons.Keys) { Write-Output "  $k $($reasons[$k])" }
}
