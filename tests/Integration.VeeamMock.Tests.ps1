#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Integration.VeeamMock.Tests.ps1
    -------------------------------
    Drives the scanner against a mocked Veeam Backup & Replication environment
    (tests/mocks/VeeamMock.psm1) under both deployment profiles:

        VBR 12.3.2  + Windows PowerShell 5.1  (Add-VBRJobLogEvent absent)
        VBR 13      + PowerShell 7            (Add-VBRJobLogEvent present)

    Covers mounted-volume discovery (filtering + hardening) and the Veeam
    job-log integration path across versions, including failure handling.

    Run:  pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/Integration.VeeamMock.Tests.ps1"
#>

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'mocks/VeeamMock.psm1') -Force

    $env:VEEAM_YARA_NOEXEC = '1'
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'Veeam-YARA-SecureRestore.ps1')
}

AfterAll {
    Reset-VeeamMockEnvironment
    Remove-Module VeeamMock -ErrorAction SilentlyContinue
}

Describe 'Mock Veeam version profiles' {

    It 'VBR 12.3.2 pairs with PowerShell 5.1 and omits Add-VBRJobLogEvent' {
        Install-VeeamMockEnvironment -Version '12.3.2' | Out-Null
        $p = Get-VeeamVersionProfile -Version '12.3.2'
        $p.PairedPSMajor        | Should -Be 5
        $p.HasAddVBRJobLogEvent  | Should -BeFalse
        Get-Command Add-VBRJobLogEvent -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'VBR 13 pairs with PowerShell 7 and provides Add-VBRJobLogEvent' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        $p = Get-VeeamVersionProfile -Version '13'
        $p.PairedPSMajor        | Should -Be 7
        $p.HasAddVBRJobLogEvent  | Should -BeTrue
        Get-Command Add-VBRJobLogEvent -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Get-VBRServer reports the version-appropriate build string' {
        Install-VeeamMockEnvironment -Version '12.3.2' | Out-Null
        (Get-VBRServer).Version | Should -BeLike '12.3.2.*'
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        (Get-VBRServer).Version | Should -BeLike '13.0.*'
    }
}

Describe 'Get-MountedVMVolumes discovery (mocked Get-Volume)' {

    It 'discovers only NTFS/ReFS non-system volumes and labels them by VM' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        Mock -CommandName Test-Path -MockWith { $true }   # treat every volume as a Windows volume

        $vols = Get-MountedVMVolumes
        $vols           | Should -HaveCount 2
        $vols.DriveLetter | Should -Contain 'E:\'
        $vols.DriveLetter | Should -Contain 'F:\'
        $vols.DriveLetter | Should -Not -Contain 'C:\'   # system drive excluded
        $vols.DriveLetter | Should -Not -Contain 'G:\'   # FAT32 excluded
        ($vols | Where-Object DriveLetter -eq 'E:\').VMName | Should -Be 'PROD-DC01'
    }

    It 'returns an empty set when only the system drive / non-Windows FS exist' {
        Install-VeeamMockEnvironment -Version '13' -Volumes @(
            (New-MockVolume -DriveLetter 'C' -FileSystemType 'NTFS' -Label 'System'),
            (New-MockVolume -DriveLetter 'G' -FileSystemType 'FAT32' -Label 'USB')
        ) | Out-Null
        Mock -CommandName Test-Path -MockWith { $true }

        $vols = @(Get-MountedVMVolumes)
        $vols | Should -HaveCount 0
    }

    It 'returns an empty array (no throw) when Get-Volume fails — hardening' {
        Install-VeeamMockEnvironment -Version '13' -ThrowOnGetVolume | Out-Null
        { $script:r = @(Get-MountedVMVolumes) } | Should -Not -Throw
        $script:r | Should -HaveCount 0
    }

    It 'skips volumes whose Windows/Users probe is inaccessible — hardening' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        Mock -CommandName Test-Path -MockWith { throw 'access is denied (mock)' }

        { $script:r2 = @(Get-MountedVMVolumes) } | Should -Not -Throw
        $script:r2 | Should -HaveCount 0   # every probe failed, so every volume is skipped
    }
}

Describe 'Veeam job-log integration across versions (Write-Log)' {

    It 'VBR 13: forwards the log line to Add-VBRJobLogEvent with message + level' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        $logFile = Join-Path $TestDrive 'v13.log'
        $jobId   = 'V13JOB'

        Write-Log -Message 'onion link detected' -Level 'WARNING'

        $events = Get-VeeamMockVBREvents | Where-Object { $_.Message -eq 'onion link detected' }
        $events           | Should -HaveCount 1
        $events[0].Type   | Should -Be 'WARNING'
        (Get-Content $logFile -Raw) | Should -Match 'onion link detected'
    }

    It 'VBR 12.3.2: degrades to file/host logging when Add-VBRJobLogEvent is absent' {
        Install-VeeamMockEnvironment -Version '12.3.2' | Out-Null
        Get-Command Add-VBRJobLogEvent -ErrorAction SilentlyContinue | Should -BeNullOrEmpty

        $logFile = Join-Path $TestDrive 'v12.log'
        $jobId   = 'V12JOB'

        { Write-Log -Message 'scan started on v12' -Level 'INFO' } | Should -Not -Throw
        Get-VeeamMockVBREvents | Should -HaveCount 0
        (Get-Content $logFile -Raw) | Should -Match 'scan started on v12'
    }

    It 'VBR 13: a failing Add-VBRJobLogEvent is caught — scan logging never throws (hardening)' {
        Install-VeeamMockEnvironment -Version '13' -ThrowOnVBRLog | Out-Null
        $logFile = Join-Path $TestDrive 'v13-fail.log'
        $jobId   = 'V13FAIL'

        { Write-Log -Message 'first line'  -Level 'ERROR' } | Should -Not -Throw
        { Write-Log -Message 'second line' -Level 'ERROR' } | Should -Not -Throw

        # The cmdlet threw before recording, so nothing was logged to Veeam,
        # but file logging still captured both lines.
        Get-VeeamMockVBREvents | Should -HaveCount 0
        $content = Get-Content $logFile -Raw
        $content | Should -Match 'first line'
        $content | Should -Match 'second line'
    }
}
