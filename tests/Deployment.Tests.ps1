BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Veeam-YARA-SecureRestore.ps1')
    . (Join-Path $PSScriptRoot 'Invoke-MockAcceptance.ps1')
}
Describe 'Deployment boundaries' {
    It 'refuses <Scenario> before scanning' -TestCases @(
        @{ Scenario = 'ExplicitTargetRequired'; Message = 'Explicit -ScanPath is required' }
        @{ Scenario = 'ReportInsideTarget'; Message = 'Report directory must be outside' }
    ) {
        param($Scenario, $Message)
        $r = Invoke-ScannerFixture -Scenario $Scenario -Mode Sequential -WorkRoot $TestDrive
        $r.ActualExit | Should -Be 2
        $r.Report.Status | Should -Be 'Error'
        ($r.Report.Errors -join ' ') | Should -Match $Message
        $r.Report.TotalMatches | Should -Be 0
        $r.Report.Coverage | Should -HaveCount 0
    }
}
