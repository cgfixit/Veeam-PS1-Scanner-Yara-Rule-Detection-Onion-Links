#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Veeam-YARA-SecureRestore Pester test-suite.

.DESCRIPTION
    Convenience runner for the tests under tests/. Configures Pester 5, optionally
    emits an NUnit results file for CI, and returns a non-zero exit code if any
    test fails. Works on Windows PowerShell 5.1 (the scanner's primary target) and
    PowerShell 7.

    YARA-engine tests (Yara.Detection.Tests.ps1) self-skip when the `yara` CLI is
    not on PATH, so the suite still runs (reduced) without YARA installed.

.PARAMETER ResultsPath
    If set, writes NUnit-format test results to this path (used by CI).

.PARAMETER Output
    Pester output verbosity: None | Normal | Detailed | Diagnostic. Default Detailed.

.PARAMETER InstallPester
    Install/Update Pester 5 from the PSGallery before running (handy in CI).

.EXAMPLE
    pwsh -File tests/Invoke-Tests.ps1

.EXAMPLE
    pwsh -File tests/Invoke-Tests.ps1 -ResultsPath testresults.xml -InstallPester
#>
[CmdletBinding()]
param(
    [string]$ResultsPath,
    [ValidateSet('None','Normal','Detailed','Diagnostic')]
    [string]$Output = 'Detailed',
    [switch]$InstallPester
)

$ErrorActionPreference = 'Stop'

if ($InstallPester) {
    Write-Host "Ensuring Pester 5 is installed..."
    if (-not (Get-Module -ListAvailable Pester | Where-Object Version -ge ([version]'5.0.0'))) {
        Install-Module Pester -MinimumVersion 5.0.0 -Force -Scope CurrentUser -SkipPublisherCheck
    }
}

Import-Module Pester -MinimumVersion 5.0.0 -ErrorAction Stop
Write-Host "Pester $((Get-Module Pester).Version) | PowerShell $($PSVersionTable.PSVersion)"

$config = New-PesterConfiguration
$config.Run.Path         = $PSScriptRoot
$config.Run.Exit         = $true          # process exit code reflects failed test count
$config.Output.Verbosity = $Output
$config.Should.ErrorAction = 'Continue'   # report every failed assertion, not just the first

if ($ResultsPath) {
    $config.TestResult.Enabled      = $true
    $config.TestResult.OutputFormat = 'NUnitXml'
    $config.TestResult.OutputPath   = $ResultsPath
}

Invoke-Pester -Configuration $config
