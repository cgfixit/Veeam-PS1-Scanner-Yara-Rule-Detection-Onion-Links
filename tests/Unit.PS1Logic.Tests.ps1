#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Unit.PS1Logic.Tests.ps1
    ------------------------
    Pester 5 unit tests for the pure(ish) PowerShell logic in
    Veeam-YARA-SecureRestore.ps1.

    The scanner is dot-sourced with $env:VEEAM_YARA_NOEXEC=1 so its functions
    load WITHOUT running a real scan (see the dot-source guard in the script).
    These tests exercise the parsing/translation/reporting logic in isolation;
    YARA-engine behaviour is covered by Yara.Detection.Tests.ps1 and the mocked
    Veeam surface by Integration.VeeamMock.Tests.ps1.

    Run:  pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/Unit.PS1Logic.Tests.ps1"
#>

BeforeAll {
    $env:VEEAM_YARA_NOEXEC = '1'
    $script:ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Veeam-YARA-SecureRestore.ps1'
    . $script:ScriptPath

    $onWindows = if ($PSVersionTable.PSVersion.Major -ge 6) { [bool]$IsWindows } else { $true }
    $script:OnWindows = $onWindows
}

Describe 'Dot-source / test guard' {
    It 'loads all public functions without running a scan' {
        foreach ($fn in 'Write-Log','Parse-YARAOutput','Convert-ToWindowsPath',
                        'Get-ScanTargets','Export-ScanResults','Invoke-ProcessWithTimeout',
                        'Get-MountedVMVolumes','Invoke-YARAScan','Invoke-VolumeScans',
                        'Send-SyslogAlert','Send-VeeamOneAlarm') {
            Get-Command $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined"
        }
    }

    It 'selects a valid parallelism tier at load time' {
        $script:ParallelMode | Should -BeIn @('ThreadJob','Job','Sequential')
    }
}

Describe 'Parse-YARAOutput' {

    It 'parses a single rule/file block into one finding' {
        $out = @(
            'comprehensive_onion_detection E:\Users\Bob\Documents\note.txt',
            '0x10:$v3_onion: http://abcdef234567.onion/recover',
            '0x30:$ransom1: ransom'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -HaveCount 1
        $f[0].Rule    | Should -Be 'comprehensive_onion_detection'
        $f[0].File    | Should -Be 'E:\Users\Bob\Documents\note.txt'
        $f[0].VMName  | Should -Be 'VM1'
    }

    It 'extracts and de-duplicates .onion links into OnionLinks' {
        $out = @(
            'comprehensive_onion_detection E:\a\note.txt',
            '0x10:$v3_onion: http://abcdef234567.onion/recover',
            '0x20:$v3_onion: http://abcdef234567.onion/recover',
            '0x30:$payment: payment'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f[0].OnionLinks | Should -Be 'http://abcdef234567.onion/recover'
        $f[0].MatchedStrings | Should -Match 'payment'
        $f[0].MatchedStrings | Should -Match '\.onion'
    }

    It 'keeps non-onion strings out of OnionLinks but in MatchedStrings' {
        $out = @(
            'comprehensive_onion_detection E:\a\note.txt',
            '0x10:$v3_onion: deadbeef234567.onion',
            '0x30:$ransom1: ransom'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f[0].OnionLinks     | Should -Not -Match 'ransom'
        $f[0].OnionLinks     | Should -Match '\.onion'
        $f[0].MatchedStrings | Should -Match 'ransom'
    }

    It 'strips a [metadata] block and preserves a Windows path with spaces' {
        $out = @(
            'tor_c2_configuration [description="Detects C2",author="CG"] E:\Program Files\app\c2.json',
            '0x10:$onion: abcdef234567.onion'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f[0].File | Should -Be 'E:\Program Files\app\c2.json'
        $f[0].Rule | Should -Be 'tor_c2_configuration'
    }

    It 'produces one finding per rule block for the same file (merged later by Export)' {
        $out = @(
            'comprehensive_onion_detection E:\a\note.txt',
            '0x10:$v3_onion: abcdef234567.onion',
            'onion_links_simple E:\a\note.txt',
            '0x20:$onion2: abcdef234567.onion'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -HaveCount 2
        ($f.Rule | Sort-Object) | Should -Be @('comprehensive_onion_detection','onion_links_simple')
    }

    It 'handles multiple distinct files' {
        $out = @(
            'onion_links_simple E:\a\1.txt',
            '0x1:$onion2: aaaa234567.onion',
            'onion_links_simple E:\b\2.txt',
            '0x2:$onion2: bbbb234567.onion'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -HaveCount 2
        $f.File | Should -Contain 'E:\a\1.txt'
        $f.File | Should -Contain 'E:\b\2.txt'
    }

    It 'ignores error: and warning: lines' {
        $out = @(
            'error: rule could not be compiled',
            'warning: something benign',
            'onion_links_simple E:\a\1.txt',
            '0x1:$onion2: aaaa234567.onion'
        )
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -HaveCount 1
        $f[0].File | Should -Be 'E:\a\1.txt'
    }

    It 'is resilient to null and empty entries in the output array (hardening)' {
        $out = @(
            'onion_links_simple E:\a\1.txt',
            $null,
            '',
            '   ',
            '0x1:$onion2: aaaa234567.onion'
        )
        { Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1' } | Should -Not -Throw
        $f = Parse-YARAOutput -Output $out -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -HaveCount 1
    }

    It 'returns nothing for output containing no rule matches' {
        $f = Parse-YARAOutput -Output @('error: x','warning: y') -VolumeRoot 'E:\' -VMName 'VM1'
        $f | Should -BeNullOrEmpty
    }

    It 'parses real captured "yara -s -m" output without throwing' {
        $real = Get-Content (Join-Path $PSScriptRoot 'fixtures/yara_output/real_tor_c2.txt')
        $f = Parse-YARAOutput -Output $real -VolumeRoot 'E:\' -VMName 'AppServer'
        $f.Count | Should -BeGreaterThan 0
        ($f.OnionLinks -join ' ') | Should -Match '\.onion'
        $f.Rule | Should -Contain 'tor_c2_configuration'
    }
}

Describe 'Convert-ToWindowsPath' {

    It 'normalises a mounted path to its drive-letter + relative path' {
        Convert-ToWindowsPath -MountedPath 'E:\Users\Bob\note.txt' -VolumeRoot 'E:\' |
            Should -Be 'E:\Users\Bob\note.txt'
    }

    It 'reports the path under the actual mounted drive letter (not hard-coded C:)' {
        Convert-ToWindowsPath -MountedPath 'F:\Windows\Temp\x.dat' -VolumeRoot 'F:\' |
            Should -Be 'F:\Windows\Temp\x.dat'
    }

    It 'returns the original path unchanged for an empty volume root (hardening)' {
        Convert-ToWindowsPath -MountedPath 'E:\a\b.txt' -VolumeRoot '' |
            Should -Be 'E:\a\b.txt'
    }

    It 'returns the original path unchanged for a too-short volume root (hardening)' {
        Convert-ToWindowsPath -MountedPath 'E:\a\b.txt' -VolumeRoot 'E' |
            Should -Be 'E:\a\b.txt'
    }

    It 'does not throw on a null volume root' {
        { Convert-ToWindowsPath -MountedPath 'E:\a\b.txt' -VolumeRoot $null } | Should -Not -Throw
    }
}

Describe 'Get-ScanTargets' {

    BeforeAll {
        $script:VolRoot = Join-Path $TestDrive 'vol'
        New-Item -ItemType Directory -Force -Path (Join-Path $script:VolRoot 'Users\alice\Documents') | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $script:VolRoot 'Windows\Temp')          | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $script:VolRoot 'ProgramData')           | Out-Null
    }

    It 'returns only the volume root in full-scan mode' {
        $QuickScan = [switch]$false
        $t = Get-ScanTargets -VolumeRoot $script:VolRoot
        $t | Should -Be @($script:VolRoot)
    }

    It 'returns only existing high-risk locations in quick-scan mode' {
        $QuickScan = [switch]$true
        $t = Get-ScanTargets -VolumeRoot $script:VolRoot
        $t.Count | Should -BeGreaterThan 0
        ($t | Where-Object { $_ -like '*Windows*Temp*' })  | Should -Not -BeNullOrEmpty
        ($t | Where-Object { $_ -like '*ProgramData*' })   | Should -Not -BeNullOrEmpty
        # inetpub\wwwroot was never created, so it must not appear
        ($t | Where-Object { $_ -like '*inetpub*' })       | Should -BeNullOrEmpty
    }
}

Describe 'Export-ScanResults' {

    BeforeEach {
        $script:jobId      = 'PESTER_JOB'
        $script:jsonReport = Join-Path $TestDrive ("results_{0}.json" -f ([guid]::NewGuid().ToString('N')))
    }

    It 'groups findings by WindowsPath and merges rules + onion links' {
        $findings = @(
            [pscustomobject]@{ VMName='VM1'; Rule='comprehensive_onion_detection'; File='E:\a\note.txt'; WindowsPath='E:\a\note.txt'; MatchedStrings='abcd.onion | ransom'; OnionLinks='abcd.onion'; Timestamp=(Get-Date) },
            [pscustomobject]@{ VMName='VM1'; Rule='onion_links_simple';            File='E:\a\note.txt'; WindowsPath='E:\a\note.txt'; MatchedStrings='abcd.onion';          OnionLinks='abcd.onion'; Timestamp=(Get-Date) }
        )
        # Capture into a script-scoped var so the script's own $jsonReport/$jobId resolve.
        $jobId = $script:jobId; $jsonReport = $script:jsonReport
        $grouped = Export-ScanResults -AllFindings $findings
        $grouped | Should -HaveCount 1
        $grouped[0].WindowsPath  | Should -Be 'E:\a\note.txt'
        $grouped[0].MatchedRules | Should -Match 'comprehensive_onion_detection'
        $grouped[0].MatchedRules | Should -Match 'onion_links_simple'
        $grouped[0].RuleCount    | Should -Be 2
    }

    It 'writes a valid JSON report to disk with the expected envelope' {
        $findings = @(
            [pscustomobject]@{ VMName='VM1'; Rule='onion_links_simple'; File='E:\a\1.txt'; WindowsPath='E:\a\1.txt'; MatchedStrings='abcd.onion'; OnionLinks='abcd.onion'; Timestamp=(Get-Date) }
        )
        $jobId = $script:jobId; $jsonReport = $script:jsonReport
        $null = Export-ScanResults -AllFindings $findings
        Test-Path $script:jsonReport | Should -BeTrue
        $json = Get-Content $script:jsonReport -Raw | ConvertFrom-Json
        $json.JobId        | Should -Be 'PESTER_JOB'
        $json.TotalMatches | Should -Be 1
        $json.UniqueFiles  | Should -Be 1
        $json.Findings     | Should -Not -BeNullOrEmpty
    }

    It 'tolerates null entries in the findings array (hardening)' {
        $jobId = $script:jobId; $jsonReport = $script:jsonReport
        { Export-ScanResults -AllFindings @($null) } | Should -Not -Throw
    }

    It 'tolerates an empty findings array' {
        $jobId = $script:jobId; $jsonReport = $script:jsonReport
        { Export-ScanResults -AllFindings @() } | Should -Not -Throw
    }
}

Describe 'Invoke-ProcessWithTimeout' {

    BeforeAll {
        if ($script:OnWindows) {
            $script:Sh = "$env:SystemRoot\System32\cmd.exe"
            $script:EchoArgs    = @('/c','echo','PROC_MARKER')
            $script:SleepArgs   = @('/c','ping','-n','10','127.0.0.1')
            $script:Exit3Args   = @('/c','exit','3')
        } else {
            $script:Sh = '/bin/sh'
            $script:EchoArgs    = @('-c','echo PROC_MARKER')
            $script:SleepArgs   = @('-c','sleep 10')
            $script:Exit3Args   = @('-c','exit 3')
        }
    }

    It 'captures stdout and a zero exit code on success' {
        $r = Invoke-ProcessWithTimeout -FilePath $script:Sh -Arguments $script:EchoArgs -TimeoutSeconds 30
        $r.TimedOut  | Should -BeFalse
        $r.ExitCode  | Should -Be 0
        ($r.Output -join "`n") | Should -Match 'PROC_MARKER'
    }

    It 'reports a non-zero exit code' {
        $r = Invoke-ProcessWithTimeout -FilePath $script:Sh -Arguments $script:Exit3Args -TimeoutSeconds 30
        $r.TimedOut | Should -BeFalse
        $r.ExitCode | Should -Be 3
    }

    It 'kills a process that exceeds the timeout and flags TimedOut' {
        $r = Invoke-ProcessWithTimeout -FilePath $script:Sh -Arguments $script:SleepArgs -TimeoutSeconds 1
        $r.TimedOut | Should -BeTrue
    }

    It 'surfaces a launch failure as an error exit code instead of throwing (hardening)' {
        $bogus = Join-Path $TestDrive 'definitely-not-an-executable.xyz'
        { $script:r2 = Invoke-ProcessWithTimeout -FilePath $bogus -Arguments @('--version') -TimeoutSeconds 5 } |
            Should -Not -Throw
        $script:r2.ExitCode | Should -BeGreaterThan 1
        ($script:r2.Output -join "`n") | Should -Match 'failed to run'
    }
}

Describe 'Write-Log' {

    It 'writes a level-tagged line to the configured log file' {
        $logFile = Join-Path $TestDrive 'scan.log'
        $jobId   = 'X'
        Write-Log -Message 'hello from pester' -Level 'WARNING'
        $content = Get-Content $logFile -Raw
        $content | Should -Match '\[WARNING\] hello from pester'
    }

    It 'never throws even when the log file path is invalid' {
        $logFile = Join-Path $TestDrive 'no-such-dir\deeper\scan.log'
        $jobId   = 'X'
        { Write-Log -Message 'should not throw' -Level 'ERROR' } | Should -Not -Throw
    }

    It 'rejects an invalid level via ValidateSet' {
        { Write-Log -Message 'x' -Level 'BOGUS' } | Should -Throw
    }
}

Describe 'Send-SyslogAlert / Send-VeeamOneAlarm opt-in guards' {

    It 'Send-SyslogAlert is a no-op when -EnableSyslog is not set' {
        $EnableSyslog = [switch]$false
        { Send-SyslogAlert -Message 'x' -Severity 2 } | Should -Not -Throw
    }

    It 'Send-VeeamOneAlarm is a no-op when -EnableVeeamOne is not set' {
        $EnableVeeamOne = [switch]$false
        { Send-VeeamOneAlarm -AlarmMessage 'x' -FindingsCount 1 } | Should -Not -Throw
    }
}
