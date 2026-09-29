#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Integration.VeeamMock.Tests.ps1
    -------------------------------
    Exercises scanner volume discovery and optional logging against synthetic
    Veeam fixtures. These tests run on the actual test host; fixture version
    labels are not evidence of Windows PowerShell or VBR runtime compatibility.
    No VBR version fixture supplies Add-VBRJobLogEvent by default. The optional
    synthetic hook is enabled explicitly to test capability detection.

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

    It 'excludes the configured system drive even when Windows is not installed on C' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        Mock -CommandName Test-Path -MockWith { $true }
        $originalSystemDrive = $env:SystemDrive
        try {
            $env:SystemDrive = 'E:'
            $volumes = @(Get-MountedVMVolumes)
            $volumes.DriveLetter | Should -Not -Contain 'E:\'
            $volumes.DriveLetter | Should -Contain 'C:\'
            $volumes.DriveLetter | Should -Contain 'F:\'
        } finally {
            $env:SystemDrive = $originalSystemDrive
        }
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

    It 'rejects failed volume enumeration instead of treating it as an empty scan' {
        Install-VeeamMockEnvironment -Version '13' -ThrowOnGetVolume | Out-Null
        { Get-MountedVMVolumes } | Should -Throw '*Failed to enumerate volumes*'
    }

    It 'rejects an inaccessible volume instead of silently excluding it' {
        Install-VeeamMockEnvironment -Version '13' | Out-Null
        Mock -CommandName Test-Path -MockWith { throw 'access is denied (mock)' }

        { Get-MountedVMVolumes } | Should -Throw '*Could not probe paths*access is denied*'
    }
}

Describe 'Optional logging capability (Write-Log)' {

    It 'forwards message and level when an optional hook is supplied on <Version>' -ForEach @(@{ Version = '12.3.2' }, @{ Version = '13' }) {
        Install-VeeamMockEnvironment -Version $Version -EnableLogHook | Out-Null
        $logFile = Join-Path $TestDrive 'v13.log'
        $jobId   = 'V13JOB'

        Write-Log -Message 'onion link detected' -Level 'WARNING'

        $events = Get-VeeamMockVBREvents | Where-Object { $_.Message -eq 'onion link detected' }
        $events           | Should -HaveCount 1
        $events[0].Type   | Should -Be 'WARNING'
        (Get-Content $logFile -Raw) | Should -Match 'onion link detected'
    }

    It 'uses file logging without an invented native hook on <Version>' -ForEach @(@{ Version = '12.3.2' }, @{ Version = '13' }) {
        Install-VeeamMockEnvironment -Version $Version | Out-Null
        Get-Command Add-VBRJobLogEvent -ErrorAction SilentlyContinue | Should -BeNullOrEmpty

        $logFile = Join-Path $TestDrive 'v12.log'
        $jobId   = 'V12JOB'

        { Write-Log -Message 'scan started on v12' -Level 'INFO' } | Should -Not -Throw
        Get-VeeamMockVBREvents | Should -HaveCount 0
        (Get-Content $logFile -Raw) | Should -Match 'scan started on v12'
    }

    It 'preserves file logging when the optional hook fails on <Version>' -ForEach @(@{ Version = '12.3.2' }, @{ Version = '13' }) {
        Install-VeeamMockEnvironment -Version $Version -EnableLogHook -ThrowOnVBRLog | Out-Null
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
