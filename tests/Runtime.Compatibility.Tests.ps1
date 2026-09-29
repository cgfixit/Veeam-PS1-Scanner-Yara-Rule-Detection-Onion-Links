#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ScannerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Veeam-YARA-SecureRestore.ps1'
    . $script:ScannerPath
    $script:NativePowerShell = (Get-Process -Id $PID).Path
    $script:WindowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}

Describe 'Installed VBR runtime policy' {
    It 'selects <Edition> PowerShell <Minimum> for <Build>' -ForEach @(
        @{ Build = '12.3.2.4165'; Edition = 'Desktop'; Minimum = '5.1'; Major = 5 }
        @{ Build = '12.3.2.4854'; Edition = 'Desktop'; Minimum = '5.1'; Major = 5 }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Minimum = '7.4.13'; Major = 7 }
        @{ Build = '13.0.1.2067'; Edition = 'Core'; Minimum = '7.4.13'; Major = 7 }
        @{ Build = '13.0.2.29'; Edition = 'Core'; Minimum = '7.4.13'; Major = 7 }
        @{ Build = '13.0.3.63'; Edition = 'Core'; Minimum = '7.4.13'; Major = 7 }
        @{ Build = '13.1.0.411'; Edition = 'Core'; Minimum = '7.6.3'; Major = 7 }
        @{ Build = '13.1.1.18'; Edition = 'Core'; Minimum = '7.6.3'; Major = 7 }
    ) {
        $requirement = Get-VbrRuntimeRequirement -VbrVersion $Build
        $requirement.PSEdition | Should -Be $Edition
        $requirement.MinimumVersion | Should -Be ([version]$Minimum)
        $requirement.PSMajor | Should -Be $Major
    }

    It 'rejects unsupported or non-Windows VBR build <Build>' -ForEach @(
        @{ Build = '11.0.0.0' }
        @{ Build = '12.3.1.1139' }
        @{ Build = '12.4.0.0' }
        @{ Build = '13.0.0.4967' }
        @{ Build = '13.0.1.179' }
        @{ Build = '13.2.0.0' }
        @{ Build = '14.0.0.0' }
    ) {
        { Get-VbrRuntimeRequirement -VbrVersion $Build } | Should -Throw '*Unsupported Windows VBR build*'
    }

    It 'accepts or rejects <Build> with <Edition> <Version> x64=<X64> preview=<Preview>' -ForEach @(
        @{ Build = '12.3.2.4854'; Edition = 'Desktop'; Version = '5.1.19041'; X64 = $true; Preview = $false; Accepted = $true }
        @{ Build = '12.3.2.4854'; Edition = 'Core'; Version = '7.4.13'; X64 = $true; Preview = $false; Accepted = $false }
        @{ Build = '12.3.2.4854'; Edition = 'Desktop'; Version = '5.1'; X64 = $false; Preview = $false; Accepted = $false }
        @{ Build = '13.0.1.180'; Edition = 'Desktop'; Version = '5.1'; X64 = $true; Preview = $false; Accepted = $false }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Version = '7.4.7'; X64 = $true; Preview = $false; Accepted = $false }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Version = '7.4.13'; X64 = $true; Preview = $false; Accepted = $true }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Version = '7.6.3'; X64 = $true; Preview = $false; Accepted = $true }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Version = '7.4.13'; X64 = $false; Preview = $false; Accepted = $false }
        @{ Build = '13.0.1.180'; Edition = 'Core'; Version = '7.6.3'; X64 = $true; Preview = $true; Accepted = $false }
        @{ Build = '13.1.1.18'; Edition = 'Core'; Version = '7.6.2'; X64 = $true; Preview = $false; Accepted = $false }
        @{ Build = '13.1.1.18'; Edition = 'Core'; Version = '7.6.3'; X64 = $true; Preview = $false; Accepted = $true }
        @{ Build = '13.1.1.18'; Edition = 'Core'; Version = '8.0.0'; X64 = $true; Preview = $false; Accepted = $false }
    ) {
        $runtime = [pscustomobject]@{ PSEdition = $Edition; Version = [version]$Version; Is64Bit = $X64; IsPreview = $Preview }
        Test-PowerShellRuntime -Runtime $runtime -Requirement (Get-VbrRuntimeRequirement -VbrVersion $Build) | Should -Be $Accepted
    }
}

Describe 'Runtime selection and failures' {
    BeforeEach {
        Mock Get-CurrentPowerShellRuntime { [pscustomobject]@{ Executable = 'current'; Version = [version]'5.1'; PSEdition = 'Desktop'; Is64Bit = $true; IsPreview = $false } }
        Mock Get-InstalledVbrVersion { [pscustomobject]@{ Version = [version]'13.0.1.180'; Source = 'server-binary' } }
        Mock Get-PowerShellCandidate { @('candidate') }
        Mock Get-PowerShellRuntime { [pscustomobject]@{ Executable = 'candidate'; Version = [version]'7.4.13'; PSEdition = 'Core'; Is64Bit = $true; IsPreview = $false } }
        Mock Invoke-RuntimeRelaunch { 0 }
    }

    It 'continues directly on the correct V12 host' {
        Mock Get-InstalledVbrVersion { [pscustomobject]@{ Version = [version]'12.3.2.4854'; Source = 'server-binary' } }
        $result = Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{} -Hop 0
        $result.Action | Should -Be 'Continue'
        $result.VbrVersion | Should -Be '12.3.2.4854'
        Should -Invoke Invoke-RuntimeRelaunch -Times 0 -Exactly
    }

    It 'skips discovery and selection only in explicit standalone mode' {
        $result = Initialize-VbrRuntime -Mode Standalone -ScriptPath $script:ScannerPath -Parameters @{} -Hop 0
        $result.Mode | Should -Be 'Standalone'
        Should -Invoke Get-InstalledVbrVersion -Times 0 -Exactly
        Should -Invoke Get-PowerShellCandidate -Times 0 -Exactly
    }

    It 'preserves child exit <Code> on an automatic host change' -ForEach @(@{ Code = 0 }, @{ Code = 1 }, @{ Code = 2 }) {
        Mock Invoke-RuntimeRelaunch { $Code }
        $result = Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{ QuickScan = $true } -Hop 0
        $result.Action | Should -Be 'Exit'
        $result.ExitCode | Should -Be $Code
        Should -Invoke Invoke-RuntimeRelaunch -Times 1 -Exactly
    }

    It 'routes a V12 invocation from Core back to Desktop' {
        Mock Get-CurrentPowerShellRuntime { [pscustomobject]@{ Executable = 'pwsh'; Version = [version]'7.4.13'; PSEdition = 'Core'; Is64Bit = $true; IsPreview = $false } }
        Mock Get-InstalledVbrVersion { [pscustomobject]@{ Version = [version]'12.3.2.4854'; Source = 'server-binary' } }
        Mock Get-PowerShellRuntime { [pscustomobject]@{ Executable = 'powershell'; Version = [version]'5.1'; PSEdition = 'Desktop'; Is64Bit = $true; IsPreview = $false } }
        (Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{} -Hop 0).Action | Should -Be 'Exit'
        Should -Invoke Get-PowerShellCandidate -Times 1 -ParameterFilter { $Requirement.PSEdition -eq 'Desktop' }
    }

    It 'fails before selecting a host when server discovery fails' {
        Mock Get-InstalledVbrVersion { throw 'missing local VBR binary' }
        { Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{} -Hop 0 } | Should -Throw '*missing local VBR binary*'
        Should -Invoke Invoke-RuntimeRelaunch -Times 0 -Exactly
    }

    It 'reports missing or unusable compatible PowerShell' {
        Mock Get-PowerShellRuntime { $null }
        { Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{} -Hop 0 } | Should -Throw '*No compatible PowerShell host found*'
    }

    It 'prevents a second relaunch while incompatible' {
        { Initialize-VbrRuntime -Mode Auto -ScriptPath $script:ScannerPath -Parameters @{} -Hop 1 } | Should -Throw '*after one relaunch*'
        Should -Invoke Invoke-RuntimeRelaunch -Times 0 -Exactly
    }
}

Describe 'Runtime subprocess trust boundary' {
    BeforeEach { Mock Test-Path { $true } }

    It 'rejects a probe that times out' {
        Mock Invoke-ProcessWithTimeout { [pscustomobject]@{ TimedOut = $true; ExitCode = -1; Output = @() } }
        Get-PowerShellRuntime -FilePath 'candidate' | Should -BeNullOrEmpty
        Should -Invoke Invoke-ProcessWithTimeout -Times 1 -ParameterFilter { $TimeoutSeconds -eq 15 }
    }

    It 'rejects invalid probe JSON or unsuccessful process exit' -ForEach @(
        @{ Code = 0; Text = 'bad-json' }
        @{ Code = 2; Text = '{"Version":"7.4.13","PSEdition":"Core","Is64Bit":true}' }
        @{ Code = 0; Text = '{"Version":"7.4.13","PSEdition":"Core","Is64Bit":"false"}' }
    ) {
        Mock Invoke-ProcessWithTimeout { [pscustomobject]@{ TimedOut = $false; ExitCode = $Code; Output = @($Text) } }
        Get-PowerShellRuntime -FilePath 'candidate' | Should -BeNullOrEmpty
    }

    It 'recognizes previews from the actual executable probe' {
        Mock Invoke-ProcessWithTimeout { [pscustomobject]@{ TimedOut = $false; ExitCode = 0; Output = @('{"Version":"7.6.0-preview.1","PSEdition":"Core","Is64Bit":true}') } }
        (Get-PowerShellRuntime -FilePath 'candidate').IsPreview | Should -BeTrue
    }
}

Describe 'Native encoded relaunch' {
    It 'preserves Unicode, quotes, literal expressions, arrays, false switches, and the working directory as data' {
        $target = Join-Path $TestDrive "child's unicode-script.ps1"
        $resultFile = Join-Path $TestDrive 'roundtrip.json'
        @'
param([string]$Value, [string[]]$Items, [switch]$Enabled, [switch]$Disabled, [int]$RuntimeHop, [string]$ResultFile)
[pscustomobject]@{ Value = $Value; Items = $Items; Enabled = [bool]$Enabled; Disabled = [bool]$Disabled; Hop = $RuntimeHop; Directory = $PWD.Path } | ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding UTF8
exit 0
'@ | Set-Content -LiteralPath $target -Encoding UTF8
        $value = 'Unicode ' + [char]0x00e9 + ' '' " $(throw "injected") ` ; & exit 99'
        $parameters = @{ Value = $value; Items = @('one two', 'three'); Enabled = [System.Management.Automation.SwitchParameter]$true; Disabled = [System.Management.Automation.SwitchParameter]$false; ResultFile = $resultFile }
        $encoded = Get-RuntimeRelaunchCommand -ScriptPath $target -Parameters $parameters -WorkingDirectory $TestDrive
        Invoke-RuntimeRelaunch -FilePath $script:NativePowerShell -EncodedCommand $encoded | Should -Be 0
        $result = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
        $result.Value | Should -BeExactly $value
        @($result.Items) | Should -Be @('one two', 'three')
        $result.Enabled | Should -BeTrue
        $result.Disabled | Should -BeFalse
        $result.Hop | Should -Be 1
        $result.Directory | Should -Be $TestDrive
        $parameters.ContainsKey('RuntimeHop') | Should -BeFalse
    }

    It 'preserves exit <Code> and maps unexpected child exits to error <Expected>' -ForEach @(
        @{ Code = 0; Expected = 0 }
        @{ Code = 1; Expected = 1 }
        @{ Code = 2; Expected = 2 }
        @{ Code = 17; Expected = 2 }
    ) {
        $target = Join-Path $TestDrive 'exit-child.ps1'
        "param([int]`$RuntimeHop); exit $Code" | Set-Content -LiteralPath $target
        $encoded = Get-RuntimeRelaunchCommand -ScriptPath $target -Parameters @{} -WorkingDirectory $TestDrive
        Invoke-RuntimeRelaunch -FilePath $script:NativePowerShell -EncodedCommand $encoded | Should -Be $Expected
    }

    It 'runs standalone preflight without YARA or log directory side effects' {
        $previous = $env:VEEAM_YARA_NOEXEC
        try {
            Remove-Item Env:VEEAM_YARA_NOEXEC -ErrorAction SilentlyContinue
            $log = Join-Path $TestDrive 'must-not-exist'
            $json = & $script:NativePowerShell -NoProfile -NonInteractive -File $script:ScannerPath -RuntimeMode Standalone -PreflightOnly -LogPath $log -YaraPath 'missing-yara'
            $LASTEXITCODE | Should -Be 0
            ($json -join "`n" | ConvertFrom-Json).Mode | Should -Be 'Standalone'
            Test-Path -LiteralPath $log | Should -BeFalse
        } finally { $env:VEEAM_YARA_NOEXEC = $previous }
    }
}
