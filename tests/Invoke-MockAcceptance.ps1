#Requires -Version 5.1
[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'veeam-yara-acceptance'))

function Invoke-ScannerFixture {
    param(
        [Parameter(Mandatory)][string]$Scenario,
        [Parameter(Mandatory)][string]$Mode,
        [Parameter(Mandatory)][string]$WorkRoot
    )
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $scanner = Join-Path $repoRoot 'Veeam-YARA-SecureRestore.ps1'
    $yara = Get-Command yara, yara64, yara64.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $yara) { throw 'Real YARA is required for entry-point acceptance.' }
    $caseRoot = Join-Path $WorkRoot "$Mode-$Scenario"
    $rules = Join-Path $caseRoot 'rules'
    $target = Join-Path $caseRoot ("mounted ' volume " + [char]0x96EA)
    $logs = Join-Path $caseRoot 'logs'
    New-Item -ItemType Directory -Path $rules, $target -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot 'yara-malware-detection.yara') -Destination $rules -Force
    Set-Content -LiteralPath (Join-Path $target 'clean.txt') -Value 'ordinary backup content' -Encoding UTF8
    $parameters = @{
        RuntimeMode = 'Standalone'; ExecutionMode = $Mode; YaraPath = $yara.Source
        YaraRulesPath = $rules; LogPath = $logs; ScanPath = @($target); ScanTimeout = 15
    }
    $expected = 0
    switch ($Scenario) {
        'Detected' {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/malicious/ransom_note_onion.txt') -Destination $target
            $expected = 1
        }
        'MalformedRule' {
            Set-Content -LiteralPath (Join-Path $rules 'broken.yara') -Value 'rule broken { condition: }' -Encoding ASCII
            $expected = 2
        }
        'MissingTool' { $parameters.YaraPath = Join-Path $caseRoot 'missing-yara.exe'; $expected = 2 }
        'MissingTarget' { $parameters.ScanPath = @(Join-Path $caseRoot 'missing-target'); $expected = 2 }
        'DiscoveryFailure' { $parameters.Remove('ScanPath'); $expected = 2 }
        'NoVolumes' { $parameters.Remove('ScanPath'); $expected = 2 }
        'Timeout' {
            Set-Content -LiteralPath (Join-Path $rules 'slow.yara') -Encoding ASCII -Value 'rule slow { condition: for any i in (1..1000000000) : (uint32(i % filesize) == 0xffffffff) }'
            $parameters.ScanTimeout = 1
            $expected = 2
        }
        'PartialFailure' {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'fixtures/malicious/ransom_note_onion.txt') -Destination $target
            $missing = Join-Path $caseRoot 'second-target'
            New-Item -ItemType Directory -Path $missing -Force | Out-Null
            # A descendant link is rejected while the first root retains its match.
            New-Item -ItemType SymbolicLink -Path (Join-Path $missing 'outside') -Target $target -ErrorAction Stop | Out-Null
            $parameters.ScanPath = @($target, $missing)
            $expected = 2
        }
        'Clean' {}
        default { throw "Unknown fixture scenario '$Scenario'." }
    }
    $payload = @{ Script = $scanner; Parameters = $parameters; Scenario = $Scenario } | ConvertTo-Json -Depth 6 -Compress
    $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $bootstrap = @'
$ErrorActionPreference = 'Stop'
$env:VEEAM_YARA_NOEXEC = $null
$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__DATA__')) | ConvertFrom-Json
$arguments = @{}
foreach ($property in $p.Parameters.PSObject.Properties) { $arguments[$property.Name] = $property.Value }
if ($p.Scenario -eq 'DiscoveryFailure') { function global:Get-Volume { throw 'Mock VBR mount discovery unavailable' } }
if ($p.Scenario -eq 'NoVolumes') { function global:Get-Volume { return @() } }
$global:LASTEXITCODE = 2
& $p.Script @arguments
exit $LASTEXITCODE
'@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap.Replace('__DATA__', $data)))
    $result = Invoke-ProcessWithTimeout -FilePath (Get-Process -Id $PID).Path -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -TimeoutSeconds 90
    $reports = @(Get-ChildItem -LiteralPath $logs -Filter 'results_*.json' -ErrorAction SilentlyContinue)
    $report = if ($reports.Count -eq 1) { Get-Content -LiteralPath $reports[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    [pscustomobject]@{
        Scenario = $Scenario; Mode = $Mode; ExpectedExit = $expected; ActualExit = $result.ExitCode
        TimedOut = $result.TimedOut; Report = $report; ReportCount = $reports.Count
        Output = ($result.Output -join "`n"); StandardError = ($result.StandardError -join "`n")
    }
}

if ($MyInvocation.InvocationName -eq '.') { return }
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Veeam-YARA-SecureRestore.ps1')
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$results = @(foreach ($mode in 'Sequential', 'Job', 'ThreadJob') {
    foreach ($scenario in 'Clean', 'Detected', 'MalformedRule') {
        Invoke-ScannerFixture -Scenario $scenario -Mode $mode -WorkRoot $OutputDirectory
    }
})
foreach ($scenario in 'MissingTool', 'MissingTarget', 'DiscoveryFailure', 'NoVolumes', 'Timeout') {
    $results += Invoke-ScannerFixture -Scenario $scenario -Mode Sequential -WorkRoot $OutputDirectory
}
$results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'acceptance.json') -Encoding UTF8
$failures = @($results | Where-Object {
    $_.TimedOut -or $_.ExpectedExit -ne $_.ActualExit -or $_.ReportCount -ne 1 -or
    ($_.ExpectedExit -eq 2 -and $_.Report.Status -ne 'Error') -or
    ($_.ExpectedExit -ne 2 -and $_.Report.Status -ne 'Completed')
})
$results | Select-Object Scenario, Mode, ExpectedExit, ActualExit, ReportCount | Format-Table -AutoSize
if ($failures.Count) { throw "$($failures.Count) mock acceptance scenarios failed. See acceptance.json." }
Write-Host "All $($results.Count) entry-point scenarios passed. Real YARA; simulated targets and mount discovery; no real VBR server."
