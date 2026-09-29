#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the scanner tests with Pester 5.7.1 on Windows PowerShell 5.1 or PowerShell 7.
.DESCRIPTION
    Returns nonzero for failures or an empty suite. CI also requires a working
    YARA executable and rejects skipped or unexecuted tests.
.PARAMETER InstallPester
    Installs the pinned Pester version from PSGallery when it is missing.
.PARAMETER RequireYara
    Fails before discovery if YARA is absent or cannot report its version.
.PARAMETER FailOnSkipped
    Fails if any test is skipped or not run.
.EXAMPLE
    pwsh -File tests/Invoke-Tests.ps1 -InstallPester -RequireYara -FailOnSkipped -ResultsPath testresults.xml
#>
[CmdletBinding()]
param(
    [string]$ResultsPath,
    [ValidateSet('None','Normal','Detailed','Diagnostic')]
    [string]$Output = 'Detailed',
    [switch]$InstallPester,
    [switch]$RequireYara,
    [switch]$FailOnSkipped
)

$ErrorActionPreference = 'Stop'
$pesterVersion = '5.7.1'

if ($InstallPester -and -not (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -eq [version]$pesterVersion })) {
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
    }
    Install-Module -Name Pester -RequiredVersion $pesterVersion -Repository PSGallery -Force -Scope CurrentUser -SkipPublisherCheck
}

Import-Module -Name Pester -RequiredVersion $pesterVersion -Force -ErrorAction Stop
Write-Host "Pester $((Get-Module Pester).Version) | PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition)"

if ($RequireYara) {
    $yara = Get-Command -Name yara, yara64, yara64.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $yara) { throw 'YARA is required. Put yara or yara64.exe on PATH before running the suite.' }
    $yaraVersion = & $yara.Source --version
    if ($LASTEXITCODE -ne 0 -or "$yaraVersion" -notmatch '^\d+\.\d+\.\d+') {
        throw "YARA version probe failed for '$($yara.Source)' (exit $LASTEXITCODE)."
    }
    Write-Host "YARA $yaraVersion | $($yara.Source)"
}

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.Exit = $false
$config.Run.PassThru = $true
$config.Output.Verbosity = $Output
$config.Should.ErrorAction = 'Continue'

if ($ResultsPath) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath = $ResultsPath
}

$result = Invoke-Pester -Configuration $config
Write-Host "Tests: $($result.TotalCount); passed: $($result.PassedCount); failed: $($result.FailedCount); skipped: $($result.SkippedCount); not run: $($result.NotRunCount)"
if ($result.TotalCount -eq 0 -or $result.Result -ne 'Passed') { exit 1 }
if ($FailOnSkipped -and ($result.SkippedCount -gt 0 -or $result.NotRunCount -gt 0)) { exit 1 }
exit 0
