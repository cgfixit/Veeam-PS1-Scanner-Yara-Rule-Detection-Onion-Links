#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    Describe 'Native Windows VBR host transitions' {
        BeforeAll {
            $script:ScannerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Veeam-YARA-SecureRestore.ps1'
            . $script:ScannerPath
            $script:VbrRegistryPath = 'SOFTWARE\Veeam\Veeam Backup and Replication'
            $script:RuntimeRegistryPath = 'SOFTWARE\Microsoft\PowerShellCore\InstalledVersions\' + [guid]::NewGuid().ToString()
            $script:RegistryOwner = [guid]::NewGuid().ToString()
            $script:RegistryBase = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
            $existing = $script:RegistryBase.OpenSubKey($script:VbrRegistryPath)
            if ($existing) {
                $existing.Dispose()
                throw 'Native tests require an isolated Windows runner without an installed VBR registry key. Existing VBR settings will not be modified.'
            }
            $script:NativeDesktop = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $script:NativeCore = $env:VEEAM_TEST_PWSH_PATH
            if (-not $script:NativeCore -or -not (Test-Path -LiteralPath $script:NativeCore -PathType Leaf)) {
                throw 'Set VEEAM_TEST_PWSH_PATH to an installed x64 PowerShell 7.6.3+ pwsh.exe for native Windows runtime tests.'
            }
            # Desktop's compiler emits the native version resource inspected by Windows.
            # Core Add-Type emits managed attributes only, which Unix FileVersionInfo can
            # read but Windows FileVersionInfo cannot use as the server version.
            $builder = Join-Path $TestDrive 'Build-VersionFixtures.ps1'
            Set-Content -LiteralPath $builder -Encoding UTF8 -Value @'
param([string]$FixtureRoot)
$ErrorActionPreference = 'Stop'
foreach ($version in '12.3.2.4854', '13.0.1.180', '13.1.1.18') {
    $directory = Join-Path $FixtureRoot $version
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $className = 'VbrVersionFixture_' + [guid]::NewGuid().ToString('N')
    $code = "using System.Reflection; [assembly: AssemblyFileVersion(`"$version`")] public class $className { }"
    $libraryPath = Join-Path $directory 'VbrVersionFixture.dll'
    Add-Type -TypeDefinition $code -OutputAssembly $libraryPath -OutputType Library -ErrorAction Stop
    Copy-Item -LiteralPath $libraryPath -Destination (Join-Path $directory 'Veeam.Backup.Service.exe') -ErrorAction Stop
}
'@
            $buildResult = Invoke-ProcessWithTimeout -FilePath $script:NativeDesktop -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $builder, '-FixtureRoot', $TestDrive) -TimeoutSeconds 60
            if ($buildResult.TimedOut -or $buildResult.ExitCode -ne 0) {
                throw "Native fixture build failed: $($buildResult.StandardError -join '; ')"
            }
            $script:FixtureDirectories = @{}
            foreach ($version in '12.3.2.4854', '13.0.1.180', '13.1.1.18') {
                $directory = Join-Path $TestDrive $version
                $serverPath = Join-Path $directory 'Veeam.Backup.Service.exe'
                $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($serverPath)
                $observed = [version]::new($info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart)
                if ($observed -ne [version]$version) { throw "Native fixture version mismatch: expected $version, observed $observed at $serverPath." }
                $script:FixtureDirectories[$version] = $directory
            }
            $key = $script:RegistryBase.CreateSubKey($script:VbrRegistryPath)
            try { $key.SetValue('RuntimeTestOwner', $script:RegistryOwner) } finally { $key.Dispose() }
            $key = $script:RegistryBase.CreateSubKey($script:RuntimeRegistryPath)
            try { $key.SetValue('InstallLocation', (Split-Path -Parent $script:NativeCore)) } finally { $key.Dispose() }
        }

        AfterAll {
            if ($script:RegistryBase) {
                $key = $script:RegistryBase.OpenSubKey($script:VbrRegistryPath)
                $owned = $false
                try { if ($key) { $owned = $key.GetValue('RuntimeTestOwner') -eq $script:RegistryOwner } } finally { if ($key) { $key.Dispose() } }
                if ($owned) { $script:RegistryBase.DeleteSubKeyTree($script:VbrRegistryPath, $false) }
                if ($script:RuntimeRegistryPath) { $script:RegistryBase.DeleteSubKeyTree($script:RuntimeRegistryPath, $false) }
                $script:RegistryBase.Dispose()
            }
        }

        It 'runs VBR <Build> from <Initial> and ends in native <ExpectedEdition> PowerShell <ExpectedMajor>' -ForEach @(
            @{ Build = '12.3.2.4854'; Initial = 'Desktop'; ExpectedEdition = 'Desktop'; ExpectedMajor = 5 }
            @{ Build = '12.3.2.4854'; Initial = 'Core'; ExpectedEdition = 'Desktop'; ExpectedMajor = 5 }
            @{ Build = '13.0.1.180'; Initial = 'Desktop'; ExpectedEdition = 'Core'; ExpectedMajor = 7 }
            @{ Build = '13.0.1.180'; Initial = 'Core'; ExpectedEdition = 'Core'; ExpectedMajor = 7 }
            @{ Build = '13.1.1.18'; Initial = 'Desktop'; ExpectedEdition = 'Core'; ExpectedMajor = 7 }
            @{ Build = '13.1.1.18'; Initial = 'Core'; ExpectedEdition = 'Core'; ExpectedMajor = 7 }
        ) {
            $key = $script:RegistryBase.OpenSubKey($script:VbrRegistryPath, $true)
            try { $key.SetValue('CorePath', $script:FixtureDirectories[$Build]) } finally { $key.Dispose() }
            $exe = if ($Initial -eq 'Desktop') { $script:NativeDesktop } else { $script:NativeCore }
            $logPath = Join-Path $TestDrive "must-not-create-$Build-$Initial"
            $previous = $env:VEEAM_YARA_NOEXEC
            try {
                Remove-Item Env:VEEAM_YARA_NOEXEC -ErrorAction SilentlyContinue
                $result = Invoke-ProcessWithTimeout -FilePath $exe -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $script:ScannerPath, '-PreflightOnly', '-LogPath', $logPath) -TimeoutSeconds 90
            } finally { $env:VEEAM_YARA_NOEXEC = $previous }
            $result.TimedOut | Should -BeFalse
            $result.ExitCode | Should -Be 0 -Because ((@($result.Output) + @($result.StandardError)) -join "`n")
            $runtime = ($result.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
            $runtime.VbrVersion | Should -Be $Build
            $runtime.PSEdition | Should -Be $ExpectedEdition
            ([version]$runtime.PowerShellVersion).Major | Should -Be $ExpectedMajor
            $runtime.Is64Bit | Should -BeTrue
            $runtime.VbrVersionSource | Should -Be (Join-Path $script:FixtureDirectories[$Build] 'Veeam.Backup.Service.exe')
            Test-Path -LiteralPath $logPath | Should -BeFalse
        }
    }
}
