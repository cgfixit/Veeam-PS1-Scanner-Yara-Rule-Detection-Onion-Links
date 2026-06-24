<#
    VeeamMock.psm1
    --------------
    A lightweight mock of the Veeam Backup & Replication (VBR) PowerShell surface
    that Veeam-YARA-SecureRestore.ps1 touches, so the scanner can be integration
    tested on any host (including a Linux CI runner) with no Veeam install.

    Two version profiles are modelled, matching how the scanner is deployed:

        VBR 12.3.2  — paired with Windows PowerShell 5.1 (the scanner's primary
                      target). In this build Add-VBRJobLogEvent is NOT part of the
                      documented cmdlet surface, so the scanner must fall back to
                      file/host logging. (See the script's own note about the
                      cmdlet being unverified on v12.)

        VBR 13      — paired with PowerShell 7. Add-VBRJobLogEvent IS available
                      (with -Message/-Type), so the scanner forwards events to the
                      Veeam job log.

    The mock injects its cmdlets as GLOBAL functions so the dot-sourced scanner
    resolves them through normal command discovery (and Get-Command sees
    Add-VBRJobLogEvent only on the v13 profile). State lives in
    $global:VeeamMockState so behaviour and recorded calls are assertable.

    Public API:
        Install-VeeamMockEnvironment -Version '12.3.2'|'13' [-Volumes ...]
                                     [-ThrowOnGetVolume] [-ThrowOnVBRLog]
        New-MockVolume -DriveLetter E -FileSystemType NTFS -Label 'VM' -SizeGB 80
        Get-VeeamMockState
        Get-VeeamMockVBREvents
        Get-VeeamVersionProfile -Version '12.3.2'|'13'
        Reset-VeeamMockEnvironment
#>

Set-StrictMode -Version Latest

# Version → (paired PowerShell major, whether Add-VBRJobLogEvent exists, build string)
$script:VersionProfiles = @{
    '12.3.2' = [pscustomobject]@{
        Version              = '12.3.2'
        Build                = '12.3.2.1748'
        PairedPSMajor        = 5
        HasAddVBRJobLogEvent = $false
    }
    '13' = [pscustomobject]@{
        Version              = '13'
        Build                = '13.0.0.4967'
        PairedPSMajor        = 7
        HasAddVBRJobLogEvent = $true
    }
}

function Get-VeeamVersionProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('12.3.2','13')][string]$Version)
    return $script:VersionProfiles[$Version]
}

function New-MockVolume {
    <#
        Builds an object shaped like a Get-Volume result (the properties the
        scanner reads: DriveLetter, FileSystemType, FileSystemLabel, Size).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [ValidateSet('NTFS','ReFS','FAT32','exFAT','')]
        [string]$FileSystemType = 'NTFS',
        [string]$Label = '',
        [double]$SizeGB = 80
    )
    return [pscustomobject]@{
        DriveLetter     = $DriveLetter
        FileSystemType  = $FileSystemType
        FileSystemLabel = $Label
        Size            = [int64]($SizeGB * 1GB)
    }
}

function Get-DefaultMockVolumes {
    # A realistic mounted-VM layout: two scannable Windows volumes, the system
    # drive (must be excluded) and a non-Windows filesystem (must be excluded).
    return @(
        (New-MockVolume -DriveLetter 'E' -FileSystemType 'NTFS' -Label 'PROD-DC01' -SizeGB 120),
        (New-MockVolume -DriveLetter 'F' -FileSystemType 'ReFS' -Label 'PROD-SQL'  -SizeGB 500),
        (New-MockVolume -DriveLetter 'C' -FileSystemType 'NTFS' -Label 'System'    -SizeGB 80),
        (New-MockVolume -DriveLetter 'G' -FileSystemType 'FAT32' -Label 'USB'      -SizeGB 16)
    )
}

function Install-VeeamMockEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('12.3.2','13')][string]$Version,
        [object[]]$Volumes,
        [switch]$ThrowOnGetVolume,
        [switch]$ThrowOnVBRLog
    )

    $verProfile = $script:VersionProfiles[$Version]

    $global:VeeamMockState = [pscustomobject]@{
        Version              = $Version
        Profile              = $verProfile
        Volumes              = if ($PSBoundParameters.ContainsKey('Volumes')) { @($Volumes) } else { Get-DefaultMockVolumes }
        VBREvents            = [System.Collections.Generic.List[object]]::new()
        ThrowOnGetVolume     = [bool]$ThrowOnGetVolume
        ThrowOnVBRLog        = [bool]$ThrowOnVBRLog
        HasAddVBRJobLogEvent = $verProfile.HasAddVBRJobLogEvent
    }

    # ── Get-Volume: present on both VBR versions / both PS hosts ──────────────
    Set-Item -Path function:global:Get-Volume -Value {
        [CmdletBinding()] param()
        if ($global:VeeamMockState.ThrowOnGetVolume) {
            throw 'Get-Volume: the CIM/Storage provider is unavailable (mock).'
        }
        return $global:VeeamMockState.Volumes
    }

    # ── A small, version-tagged VBR cmdlet surface (illustrative) ─────────────
    Set-Item -Path function:global:Get-VBRServer -Value {
        [CmdletBinding()] param()
        return [pscustomobject]@{
            Name    = 'vbr.lab.local'
            Version = $global:VeeamMockState.Profile.Build
            Type    = 'Local'
        }
    }
    Set-Item -Path function:global:Get-VBRJob -Value {
        [CmdletBinding()] param([string]$Name)
        return [pscustomobject]@{ Name = if ($Name) { $Name } else { 'SecureRestore-PROD' }; JobType = 'SecureRestore' }
    }
    Set-Item -Path function:global:Get-VBRBackupSession -Value {
        [CmdletBinding()] param()
        return [pscustomobject]@{ Id = [guid]::NewGuid(); State = 'Working'; Result = 'None' }
    }

    # ── Add-VBRJobLogEvent: ONLY on the VBR 13 profile ────────────────────────
    if ($verProfile.HasAddVBRJobLogEvent) {
        Set-Item -Path function:global:Add-VBRJobLogEvent -Value {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory)][string]$Message,
                [Parameter()]$Type
            )
            if ($global:VeeamMockState.ThrowOnVBRLog) {
                throw 'Add-VBRJobLogEvent: backend log write failed (mock).'
            }
            $global:VeeamMockState.VBREvents.Add([pscustomobject]@{
                Message = $Message
                Type    = "$Type"
            })
        }
    } else {
        # Remove via the Function:\ path (a function:global: path does not reliably
        # delete a global function from inside a module — see Reset below).
        if (Test-Path 'Function:\Add-VBRJobLogEvent') {
            Remove-Item 'Function:\Add-VBRJobLogEvent' -Force
        }
    }

    return $global:VeeamMockState
}

function Get-VeeamMockState {
    [CmdletBinding()] param()
    if (-not (Get-Variable -Name VeeamMockState -Scope Global -ErrorAction SilentlyContinue)) { return $null }
    return $global:VeeamMockState
}

function Get-VeeamMockVBREvents {
    [CmdletBinding()] param()
    $state = Get-VeeamMockState
    if (-not $state) { return @() }
    return @($state.VBREvents)
}

function Reset-VeeamMockEnvironment {
    [CmdletBinding()] param()
    foreach ($fn in 'Get-Volume','Get-VBRServer','Get-VBRJob','Get-VBRBackupSession','Add-VBRJobLogEvent') {
        if (Test-Path "Function:\$fn") { Remove-Item "Function:\$fn" -Force }
    }
    if (Get-Variable -Name VeeamMockState -Scope Global -ErrorAction SilentlyContinue) {
        Remove-Variable -Name VeeamMockState -Scope Global -Force
    }
}

Export-ModuleMember -Function Install-VeeamMockEnvironment, New-MockVolume, Get-VeeamMockState,
                              Get-VeeamMockVBREvents, Get-VeeamVersionProfile, Reset-VeeamMockEnvironment
