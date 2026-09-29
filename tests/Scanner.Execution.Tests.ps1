#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.7.1' }
BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Veeam-YARA-SecureRestore.ps1')
    . (Join-Path $PSScriptRoot 'Invoke-MockAcceptance.ps1')
}

Describe 'Actual scanner process with real YARA' {
    It '<Mode> produces exit <Expected> and an honest report for <Scenario>' -ForEach @(
        @{ Mode = 'Sequential'; Scenario = 'Clean'; Expected = 0 }
        @{ Mode = 'Sequential'; Scenario = 'Detected'; Expected = 1 }
        @{ Mode = 'Sequential'; Scenario = 'MalformedRule'; Expected = 2 }
        @{ Mode = 'Job'; Scenario = 'Clean'; Expected = 0 }
        @{ Mode = 'Job'; Scenario = 'Detected'; Expected = 1 }
        @{ Mode = 'Job'; Scenario = 'MalformedRule'; Expected = 2 }
        @{ Mode = 'ThreadJob'; Scenario = 'Clean'; Expected = 0 }
        @{ Mode = 'ThreadJob'; Scenario = 'Detected'; Expected = 1 }
        @{ Mode = 'ThreadJob'; Scenario = 'MalformedRule'; Expected = 2 }
        @{ Mode = 'Sequential'; Scenario = 'MissingTool'; Expected = 2 }
        @{ Mode = 'Sequential'; Scenario = 'MissingTarget'; Expected = 2 }
        @{ Mode = 'Sequential'; Scenario = 'DiscoveryFailure'; Expected = 2 }
        @{ Mode = 'Sequential'; Scenario = 'NoVolumes'; Expected = 2 }
        @{ Mode = 'Sequential'; Scenario = 'Timeout'; Expected = 2 }
    ) {
        $result = Invoke-ScannerFixture -Scenario $Scenario -Mode $Mode -WorkRoot $TestDrive
        $result.TimedOut | Should -BeFalse
        $result.ActualExit | Should -Be $Expected -Because $result.Output
        $result.ReportCount | Should -Be 1
        $result.Report.ExecutionMode | Should -Be $Mode
        if ($Expected -eq 2) {
            $result.Report.Status | Should -Be 'Error'
            $result.Report.Errors | Should -Not -BeNullOrEmpty
            $result.Output | Should -Not -Match 'All volumes clean|Scan completed\. No selected'
        } else {
            $result.Report.Status | Should -Be 'Completed'
            $result.Report.Errors | Should -HaveCount 0
            if ($Expected -eq 0) { $result.Report.TotalMatches | Should -Be 0 }
            else {
                $result.Report.TotalMatches | Should -BeGreaterThan 0
                ($result.Report.Findings.OnionLinks -join ' ') | Should -Match '\.onion'
            }
        }
    }
}

Describe 'Scan failure boundaries' {
    BeforeEach { $logFile = Join-Path $TestDrive 'failure.log' }
    It 'rejects a per-file YARA error even when YARA exits zero' {
        Mock Invoke-ProcessWithTimeout { [pscustomobject]@{ TimedOut = $false; ExitCode = 0; Output = @(); StandardError = @('error scanning file: access denied') } }
        { Invoke-YARAScan -ScanPaths @($TestDrive) -VolumeRoot $TestDrive -VMName 'mock' -YaraRuleFiles @([pscustomobject]@{Name='test.yara'; FullName='test.yara'}) } | Should -Throw '*YARA failed*'
    }
    It 'refuses to report success when the report cannot be persisted' {
        $YaraPath = 'missing-yara'
        $jsonReport = Join-Path $TestDrive 'absent/report.json'
        { Export-ScanResults -AllFindings @() } | Should -Throw '*Failed to write JSON report*'
    }
}
