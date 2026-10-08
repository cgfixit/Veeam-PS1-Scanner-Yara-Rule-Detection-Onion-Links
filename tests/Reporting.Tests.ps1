BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Veeam-YARA-SecureRestore.ps1')
    . (Join-Path $PSScriptRoot 'Invoke-MockAcceptance.ps1')
}
Describe 'Structured evidence contract' {
    It 'preserves quoted metadata, numeric offsets and original match bytes' {
        $wide = ('ABCDEFGHIJKLMNOP.ONION'.ToCharArray() | ForEach-Object { "${_}\x00" }) -join ''
        $f = @(Parse-YARAOutput -Output @('sample [description="review ] this",severity="MEDIUM",score=3,flag=true] E:\note.txt', "0x20:`$host: $wide") -VolumeRoot 'E:\' -VMName 'fixture')
        $f.Count | Should -Be 1
        $f[0].File | Should -Be 'E:\note.txt'
        $f[0].Metadata.description | Should -Be 'review ] this'
        $f[0].Metadata.score | Should -Be 3
        $f[0].Evidence[0].Offset | Should -Be 32
        $f[0].Evidence[0].RawValue | Should -Be $wide
        $f[0].Indicators | Should -Contain 'abcdefghijklmnop.onion'
    }
    It 'does not normalize an invalid hostname into a valid IOC' {
        $f = @(Parse-YARAOutput -Output @('sample E:\note.txt', '0x0:$host: aabcdefghijklmnop.onion') -VolumeRoot 'E:\' -VMName 'fixture')
        $f[0].Indicators | Should -HaveCount 0
        $f[0].Evidence | Should -HaveCount 1
    }
    It 'persists detection evidence and reports unsupported notification without changing exit 1' {
        $r = Invoke-ScannerFixture -Scenario NotificationUnsupported -Mode Sequential -WorkRoot $TestDrive
        $r.ActualExit | Should -Be 1 -Because $r.Output
        $r.Report.SchemaVersion | Should -Be 2
        $r.Report.TotalMatches | Should -BeGreaterThan 0
        $r.Report.Findings[0].RuleEvidence[0].Metadata | Should -Not -BeNullOrEmpty
        $r.Report.NotificationStatus[0].Status | Should -Be 'Unsupported'
        $r.Output | Should -Not -Match 'INFECTED FILES|MALWARE DETECTED|alarm raised'
    }
    It 'bounds an invalid syslog destination and retains an explicit failure result' {
        $EnableSyslog = $true
        $SyslogServer = 'invalid host name with spaces'
        $SyslogPort = 514
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $r = Send-SyslogAlert -Message 'fixture'
        $timer.Stop()
        $r.Status | Should -Be 'Failed'
        $timer.Elapsed.TotalSeconds | Should -BeLessThan 12
    }
}
