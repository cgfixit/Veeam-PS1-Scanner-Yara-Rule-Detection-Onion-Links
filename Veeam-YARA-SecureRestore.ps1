#Requires -Version 5.1
# Veeam-YARA-SecureRestore.ps1
# Native Windows YARA scanner for Veeam Secure Restore
# Extracts matched onion link strings with full file path details
#
# Auto mode selects the host for the installed Windows VBR build before scanning.
# Standalone mode keeps the current host for explicitly managed mount servers.
# The entire script must parse on Windows PowerShell 5.1 before host selection.
#
# NOTE: save this file as UTF-8 *with BOM* — Windows PowerShell 5.1 reads
# BOM-less files as the system ANSI codepage, which corrupts the box-drawing /
# emoji characters used in log output.

param(
    [ValidateSet('Auto', 'Standalone')]
    [string]$RuntimeMode = 'Auto',

    [switch]$PreflightOnly,

    [Parameter(DontShow=$true)]
    [ValidateRange(0, 1)]
    [int]$RuntimeHop = 0,

    [Parameter(Mandatory=$false)]
    [string]$YaraPath = "C:\Program Files\YARA\yara64.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$YaraRulesPath = "C:\ProgramData\YARA\Rules",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\Veeam\Logs\YARA-SecureRestore",
    
    [Parameter(Mandatory=$false)]
    [string]$SessionId,
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 86400)]
    [int]$ScanTimeout = 3600,  # 1 hour
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickScan,

    [string[]]$ScanPath,

    [ValidateSet('Auto', 'Sequential', 'Job', 'ThreadJob')]
    [string]$ExecutionMode = 'Auto',

    # ── Syslog / SIEM integration (opt-in) ──────────────────────────────────
    [Parameter(Mandatory=$false)]
    [switch]$EnableSyslog,

    [Parameter(Mandatory=$false)]
    [string]$SyslogServer = "127.0.0.1",

    [Parameter(Mandatory=$false)]
    [int]$SyslogPort = 514,

    # ── Veeam ONE integration (opt-in) ───────────────────────────────────────
    [Parameter(Mandatory=$false)]
    [switch]$EnableVeeamOne,

    [Parameter(Mandatory=$false)]
    [string]$VeeamOneServer = "localhost",

    [Parameter(Mandatory=$false)]
    [int]$VeeamOnePort = 1239
)

$script:DotSourced = ($MyInvocation.InvocationName -eq '.') -or [bool]$env:VEEAM_YARA_NOEXEC

function Get-VbrRuntimeRequirement {
    param([Parameter(Mandatory)][version]$VbrVersion)

    if ($VbrVersion.Major -eq 12 -and $VbrVersion.Minor -eq 3 -and $VbrVersion.Build -eq 2) {
        return [pscustomobject]@{ VbrVersion = $VbrVersion; PSEdition = 'Desktop'; PSMajor = 5; MinimumVersion = [version]'5.1' }
    }
    if ($VbrVersion.Major -eq 13 -and $VbrVersion.Minor -eq 0 -and $VbrVersion -ge [version]'13.0.1.180') {
        return [pscustomobject]@{ VbrVersion = $VbrVersion; PSEdition = 'Core'; PSMajor = 7; MinimumVersion = [version]'7.4.13' }
    }
    if ($VbrVersion.Major -eq 13 -and $VbrVersion.Minor -eq 1) {
        return [pscustomobject]@{ VbrVersion = $VbrVersion; PSEdition = 'Core'; PSMajor = 7; MinimumVersion = [version]'7.6.3' }
    }
    throw "Unsupported Windows VBR build '$VbrVersion'. Supported families are 12.3.2, Windows 13.0.1.180 or later 13.0, and 13.1. Review vendor requirements before adding another family."
}

function Get-InstalledVbrVersion {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Automatic VBR discovery requires a Windows VBR server. Use -RuntimeMode Standalone only for an explicitly managed mount server or test environment.'
    }
    $baseKey = $null
    $key = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $baseKey.OpenSubKey('SOFTWARE\Veeam\Veeam Backup and Replication')
        if (-not $key) { throw 'The 64-bit Veeam Backup and Replication registry key is missing.' }
        $corePath = [string]$key.GetValue('CorePath')
        if ([string]::IsNullOrWhiteSpace($corePath) -or -not [IO.Path]::IsPathRooted($corePath)) {
            throw 'The Veeam CorePath registry value is missing or is not an absolute installation path.'
        }
        $binaryPath = Join-Path $corePath 'Veeam.Backup.Service.exe'
        if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            throw "The local VBR server binary is missing at '$binaryPath'. A console-only installation is insufficient for automatic server discovery."
        }
        $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
        if ($info.FileMajorPart -le 0) { throw "The VBR server binary has no usable file version: '$binaryPath'." }
        $version = [version]::new($info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart)
        return [pscustomobject]@{ Version = $version; Source = $binaryPath }
    } finally {
        if ($key) { $key.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }
}

function Get-CurrentPowerShellRuntime {
    return [pscustomobject]@{
        Executable = (Get-Process -Id $PID -ErrorAction Stop).Path
        Version = [version]$PSVersionTable.PSVersion.ToString().Split('-')[0]
        PSEdition = [string]$PSVersionTable.PSEdition
        Is64Bit = [Environment]::Is64BitProcess
        IsPreview = $PSVersionTable.PSVersion.ToString().Contains('-')
    }
}

function Test-PowerShellRuntime {
    param([Parameter(Mandatory)]$Runtime, [Parameter(Mandatory)]$Requirement)
    return ($Runtime.Is64Bit -and -not $Runtime.IsPreview -and
        $Runtime.PSEdition -eq $Requirement.PSEdition -and
        $Runtime.Version.Major -eq $Requirement.PSMajor -and
        $Runtime.Version -ge $Requirement.MinimumVersion)
}

function Get-PowerShellCandidate {
    param([Parameter(Mandatory)]$Requirement)
    if ($Requirement.PSEdition -eq 'Desktop') {
        $systemDirectory = if ([Environment]::Is64BitProcess) { 'System32' } else { 'Sysnative' }
        return (Join-Path $env:SystemRoot "$systemDirectory\WindowsPowerShell\v1.0\powershell.exe")
    }
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { [Environment]::GetFolderPath('ProgramFiles') }
    $paths = @()
    if ($programFiles) { $paths += Join-Path $programFiles 'PowerShell\7\pwsh.exe' }
    $baseKey = $null
    $key = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $key = $baseKey.OpenSubKey('SOFTWARE\Microsoft\PowerShellCore\InstalledVersions')
        if ($key) {
            foreach ($name in $key.GetSubKeyNames()) {
                $installed = $key.OpenSubKey($name)
                try {
                    $location = [string]$installed.GetValue('InstallLocation')
                    if ($location -and [IO.Path]::IsPathRooted($location)) { $paths += Join-Path $location 'pwsh.exe' }
                } finally { if ($installed) { $installed.Dispose() } }
            }
        }
    } finally {
        if ($key) { $key.Dispose() }
        if ($baseKey) { $baseKey.Dispose() }
    }
    return @($paths | Select-Object -Unique)
}

function Get-PowerShellRuntime {
    param([Parameter(Mandatory)][string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { return $null }
    $probe = '[pscustomobject]@{ Version = $PSVersionTable.PSVersion.ToString(); PSEdition = $PSVersionTable.PSEdition; Is64Bit = [Environment]::Is64BitProcess } | ConvertTo-Json -Compress'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
    $result = Invoke-ProcessWithTimeout -FilePath $FilePath -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) -TimeoutSeconds 15
    if ($result.TimedOut -or $result.ExitCode -ne 0) { return $null }
    try {
        $data = ($result.Output -join "`n") | ConvertFrom-Json -ErrorAction Stop
        if ($data.Is64Bit -isnot [bool] -or $data.PSEdition -notin @('Desktop', 'Core') -or [string]::IsNullOrWhiteSpace([string]$data.Version)) { return $null }
        return [pscustomobject]@{
            Executable = $FilePath
            Version = [version]([string]$data.Version).Split('-')[0]
            PSEdition = [string]$data.PSEdition
            Is64Bit = $data.Is64Bit
            IsPreview = ([string]$data.Version).Contains('-')
        }
    } catch { return $null }
}

function Get-RuntimeRelaunchCommand {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Parameters,
        [Parameter(Mandatory)][string]$WorkingDirectory
    )
    $arguments = @{}
    foreach ($name in $Parameters.Keys) {
        $value = $Parameters[$name]
        $arguments[$name] = if ($value -is [System.Management.Automation.SwitchParameter]) { [bool]$value } else { $value }
    }
    $arguments['RuntimeHop'] = 1
    $payload = @{ ScriptPath = $ScriptPath; WorkingDirectory = $WorkingDirectory; Parameters = $arguments } | ConvertTo-Json -Depth 8 -Compress
    $data = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
    $command = @'
try {
    $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__')) | ConvertFrom-Json -ErrorAction Stop
    Set-Location -LiteralPath $payload.WorkingDirectory -ErrorAction Stop
    $parameters = @{}
    foreach ($property in $payload.Parameters.PSObject.Properties) { $parameters[$property.Name] = $property.Value }
    $global:LASTEXITCODE = 2
    & $payload.ScriptPath @parameters
    if ($LASTEXITCODE -in @(0, 1, 2)) { exit $LASTEXITCODE }
    exit 2
} catch {
    [Console]::Error.WriteLine("Runtime relaunch failed: $_")
    exit 2
}
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command.Replace('__PAYLOAD__', $data)))
}

function Invoke-RuntimeRelaunch {
    param([Parameter(Mandatory)][string]$FilePath, [Parameter(Mandatory)][string]$EncodedCommand)
    $global:LASTEXITCODE = 2
    & $FilePath -NoLogo -NoProfile -NonInteractive -EncodedCommand $EncodedCommand | Out-Host
    if ($LASTEXITCODE -in @(0, 1, 2)) { return [int]$LASTEXITCODE }
    return 2
}

function Initialize-VbrRuntime {
    param(
        [ValidateSet('Auto', 'Standalone')][string]$Mode,
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Parameters,
        [ValidateRange(0, 1)][int]$Hop
    )
    $current = Get-CurrentPowerShellRuntime
    if ($Mode -eq 'Standalone') {
        return [pscustomobject]@{ Action = 'Continue'; Mode = $Mode; VbrVersion = $null; VbrVersionSource = $null; Executable = $current.Executable; PowerShellVersion = $current.Version.ToString(); PSEdition = $current.PSEdition; Is64Bit = $current.Is64Bit }
    }
    $installed = Get-InstalledVbrVersion
    $requirement = Get-VbrRuntimeRequirement -VbrVersion $installed.Version
    if (Test-PowerShellRuntime -Runtime $current -Requirement $requirement) {
        return [pscustomobject]@{ Action = 'Continue'; Mode = $Mode; VbrVersion = $installed.Version.ToString(); VbrVersionSource = $installed.Source; Executable = $current.Executable; PowerShellVersion = $current.Version.ToString(); PSEdition = $current.PSEdition; Is64Bit = $current.Is64Bit }
    }
    if ($Hop -ne 0) {
        throw "PowerShell remains incompatible after one relaunch. VBR $($installed.Version) requires x64 $($requirement.PSEdition) PowerShell $($requirement.PSMajor), minimum $($requirement.MinimumVersion); current process is $($current.Executable) ($($current.Version))."
    }
    foreach ($candidate in @(Get-PowerShellCandidate -Requirement $requirement)) {
        $runtime = Get-PowerShellRuntime -FilePath $candidate
        if ($runtime -and (Test-PowerShellRuntime -Runtime $runtime -Requirement $requirement)) {
            if ($PWD.Provider.Name -ne 'FileSystem') { throw 'Run the scanner from a filesystem working directory before changing PowerShell hosts.' }
            $encoded = Get-RuntimeRelaunchCommand -ScriptPath $ScriptPath -Parameters $Parameters -WorkingDirectory $PWD.Path
            if (-not $Parameters['PreflightOnly']) {
                [Console]::WriteLine("VBR $($installed.Version) requires x64 $($requirement.PSEdition) PowerShell $($requirement.MinimumVersion)+. Relaunching with '$candidate' ($($runtime.Version)).")
            }
            $exitCode = Invoke-RuntimeRelaunch -FilePath $candidate -EncodedCommand $encoded
            return [pscustomobject]@{ Action = 'Exit'; ExitCode = $exitCode }
        }
    }
    throw "No compatible PowerShell host found for VBR $($installed.Version). Install the Veeam-supported x64 $($requirement.PSEdition) PowerShell $($requirement.PSMajor) runtime, minimum $($requirement.MinimumVersion), then rerun. Current host is '$($current.Executable)' ($($current.Version))."
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $logEntry

    # Lazily open the named mutex in whatever runspace/process Write-Log runs in.
    # Opening by name (not passing the object) is the only approach that works
    # uniformly for direct calls, in-process ThreadJob runspaces, and
    # out-of-process Start-Job children.
    if (-not $script:LogMutex) {
        $script:LogMutex = [System.Threading.Mutex]::new($false, "VeeamYARAScanLog")
    }
    $acquired = $false
    try {
        $acquired = $script:LogMutex.WaitOne(5000)
        [System.IO.File]::AppendAllText($logFile, "$logEntry`n")
    } catch {
        # As a last resort, fall back to a non-locked append so logging never
        # throws and aborts a scan.
        try { [System.IO.File]::AppendAllText($logFile, "$logEntry`n") } catch {}
    } finally {
        if ($acquired) { $script:LogMutex.ReleaseMutex() }
    }

    <#
        Placeholder since that cmdlet doesnt exist yet (only relevant for unified veeam logging; otherwise the paths for this script log are defined
        https://github.com/yetanothermightytool/powershell/blob/master/vbr/vbr-securerestore-lnx/vbr-securerestore.ps1 - not bad for workaround aside from just logging on server like it is now
    #>
    # Add-VBRJobLogEvent does not appear in Veeam v12/v13 public PS docs; the
    # -Type parameter name is unverified. Surface a one-time warning on failure
    # so operators know Veeam job-log integration is broken rather than silent.
    try {
        if (Get-Command Add-VBRJobLogEvent -ErrorAction SilentlyContinue) {
            try {
                Add-VBRJobLogEvent -Message $Message -Type $Level
            } catch {
                if (-not $script:VBRLogEventWarned) {
                    $script:VBRLogEventWarned = $true
                    $w = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARNING] Add-VBRJobLogEvent failed (verify cmdlet name and -Type param for your Veeam version): $_"
                    Write-Host $w
                    try { [System.IO.File]::AppendAllText($logFile, "$w`n") } catch {}
                }
            }
        }
    } catch {}
}

function Send-SyslogAlert {
    param(
        [string]$Message,
        [ValidateRange(0,7)]
        [int]$Severity = 4  # 4 = Warning; 2 = Critical; 6 = Informational
    )
    if (-not $EnableSyslog) { return }

    # UDP submission is not delivery acknowledgement. Bound DNS and send waits.
    $udp = $null
    try {
        $lookup = [Net.Dns]::GetHostAddressesAsync($SyslogServer)
        if (-not $lookup.Wait(5000)) { throw 'Syslog DNS lookup exceeded 5 seconds.' }
        $address = @($lookup.Result)[0]
        $udp = [Net.Sockets.UdpClient]::new($address.AddressFamily)
        $pri = 128 + $Severity
        $timestamp = (Get-Date).ToUniversalTime().ToString('o')
        $safeMessage = $Message -replace '[\r\n\x00]', ' '
        $bytes = [Text.Encoding]::UTF8.GetBytes("<$pri>1 $timestamp - VeeamYARAScanner - - - $safeMessage")
        $send = $udp.SendAsync($bytes, $bytes.Length, [Net.IPEndPoint]::new($address, $SyslogPort))
        if (-not $send.Wait(5000)) { throw 'Syslog send exceeded 5 seconds.' }
        return [pscustomobject]@{ Channel = 'Syslog'; Status = 'Submitted'; Detail = 'UDP submitted; delivery unconfirmed.' }
    } catch {
        return [pscustomobject]@{ Channel = 'Syslog'; Status = 'Failed'; Detail = "$_" }
    } finally { if ($udp) { $udp.Dispose() } }
}

function Send-VeeamOneAlarm {
    param([string]$AlarmMessage, [int]$FindingsCount)
    if (-not $EnableVeeamOne) { return }
    # The former POST /alarms example was an unsupported prototype. Keep the
    # opt-in parameter compatible, but never claim an alarm was created.
    return [pscustomobject]@{
        Channel = 'VeeamONE'; Status = 'Unsupported'
        Detail = 'No supported alarm-creation API is configured. Use the persisted report with an approved integration.'
    }
}

function Get-MountedVMVolumes {
    <#
    .SYNOPSIS
    Discovers mounted VM volumes from Veeam SureBackup or Instant Recovery
    #>
    
    Write-Log "Discovering mounted VM volumes..."
    $systemDrive = if ($env:SystemDrive) { $env:SystemDrive.TrimEnd(':') } else { 'C' }

    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object {
            $_.DriveLetter -and
            $_.FileSystemType -in @('NTFS', 'ReFS') -and
            $_.DriveLetter -ne $systemDrive
        }
    } catch {
        throw "Failed to enumerate volumes via Get-Volume: $_"
    }

    $mountedVolumes = @()

    foreach ($vol in $volumes) {
        $driveLetter = "$($vol.DriveLetter):\"

        # Check if this looks like a Windows volume. Test-Path can throw on a
        # volume that disappears mid-scan or denies access; skip it rather than
        # aborting discovery of the remaining volumes. [IO.Path]::Combine (not
        # Join-Path) avoids Join-Path's PSDrive resolution of the "E:\" qualifier.
        $systemRoot = [System.IO.Path]::Combine($driveLetter, "Windows")
        $usersDir = [System.IO.Path]::Combine($driveLetter, "Users")

        $looksWindows = $false
        try {
            $looksWindows = (Test-Path -LiteralPath $systemRoot -ErrorAction Stop) -or (Test-Path -LiteralPath $usersDir -ErrorAction Stop)
        } catch {
            throw "Could not probe paths on $driveLetter : $_"
        }

        if ($looksWindows) {
            Write-Log "Found Windows volume: $driveLetter (Size: $([math]::Round($vol.Size/1GB, 2)) GB)"
            
            # Try to identify VM name from volume label
            $vmName = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Unknown" }
            
            $mountedVolumes += [PSCustomObject]@{
                DriveLetter = $driveLetter
                Label = $vol.FileSystemLabel
                Size = $vol.Size
                SystemRoot = $systemRoot
                VMName = $vmName
            }
        }
    }
    
    if ($mountedVolumes.Count -eq 0) {
        Write-Log "WARNING: No mounted Windows volumes found!" -Level "WARNING"
    }
    
    return $mountedVolumes
}

function Get-ScanTargets {
    param([string]$VolumeRoot)
    
    if ($QuickScan) {
        # Quick scan: common malware/ransomware locations
        $targets = @(
            "Users\*\Documents",
            "Users\*\Desktop",
            "Users\*\Downloads",
            "Users\*\AppData\Local\Temp",
            "Users\*\AppData\Roaming",
            "Windows\Temp",
            "ProgramData",
            "inetpub\wwwroot",
            "Windows\System32\config"
        )
    } else {
        # Full scan: entire volume
        return @($VolumeRoot)
    }
    
    $scanPaths = @()
    foreach ($target in $targets) {
        $fullPath = Join-Path ([WildcardPattern]::Escape($VolumeRoot)) $target
        foreach ($resolved in @(Resolve-Path -Path $fullPath -ErrorAction SilentlyContinue -ErrorVariable pathErrors)) {
            if (Test-Path -LiteralPath $resolved.ProviderPath -PathType Container -ErrorAction Stop) {
                $scanPaths += $resolved.ProviderPath
            }
        }
        foreach ($pathError in $pathErrors) {
            if ($pathError.CategoryInfo.Category -ne 'ObjectNotFound') { throw $pathError }
        }
    }
    
    return $scanPaths
}

function Invoke-ProcessWithTimeout {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [ValidateRange(1, 86400)][int]$TimeoutSeconds
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    # .NET Framework lacks ArgumentList. Escape quotes and trailing backslashes
    # using the Windows native argument convention supported by ProcessStartInfo.
    $psi.Arguments = ($Arguments | ForEach-Object {
        '"' + (($_ -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
    }) -join ' '
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    $timedOut = $false
    $exitCode = -1
    $stdout = ''
    $stderr = ''
    try {
        if (-not $proc.Start()) { throw 'The process did not start.' }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            $proc.Kill()
            if (-not $proc.WaitForExit(5000)) { throw 'The process did not stop after its timeout.' }
        } else {
            $exitCode = $proc.ExitCode
        }
        if (-not $outTask.Wait(5000) -or -not $errTask.Wait(5000)) {
            throw 'The process output streams did not close.'
        }
        $stdout = $outTask.Result
        $stderr = $errTask.Result
    } catch {
        $stderr = "Invoke-ProcessWithTimeout failed to run '$FilePath': $_"
        $exitCode = 2
    } finally {
        $proc.Dispose()
    }
    $lines = @($stdout -split "`r?`n" | Where-Object { $_ -ne '' })
    $errorLines = @($stderr -split "`r?`n" | Where-Object { $_ -ne '' })
    return [pscustomobject]@{
        TimedOut = $timedOut
        ExitCode = $exitCode
        Output = $lines
        StandardError = $errorLines
    }
}

function Get-ScanInventory {
    param([string]$Root)
    $files = [Collections.Generic.List[string]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count) {
        $path = $pending.Pop()
        try {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            # The caller explicitly authorizes the starting root. Descendant links
            # are never followed, including Windows junctions and reparse points.
            if ($path -ne $Root -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Descendant link/reparse point is outside the traversal policy: $path"
            }
            if ($item.PSIsContainer) {
                foreach ($child in @(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop)) {
                    $pending.Push($child.FullName)
                }
            } else {
                if ($path -match '[\r\n]') { throw "Filename cannot be represented in a YARA scan list: $path" }
                $files.Add($item.FullName)
            }
        } catch { $errors.Add("Cannot inventory '$path': $_") }
    }
    [pscustomobject]@{ Files = $files.ToArray(); Errors = $errors.ToArray() }
}

function Invoke-YARAScan {
    param(
        [string[]]$ScanPaths,
        [string]$VolumeRoot,
        [string]$VMName,
        [object[]]$YaraRuleFiles,
        [switch]$Detailed
    )
    $findings = [Collections.Generic.List[object]]::new()
    $errors = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $comparer = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { [StringComparer]::OrdinalIgnoreCase } else { [StringComparer]::Ordinal }
    $seen = [Collections.Generic.HashSet[string]]::new($comparer)
    $completed = 0
    $attempted = 0
    $yaraRules = @($YaraRuleFiles | Where-Object { $_ })
    try {
        if (-not $yaraRules.Count) { $yaraRules = @(Get-ChildItem -LiteralPath $YaraRulesPath -Filter '*.yar*' -File -ErrorAction Stop) }
        if (-not $yaraRules.Count) { throw "No YARA rules found in $YaraRulesPath" }
        if (-not @($ScanPaths).Count) { throw "No scan targets found on $VolumeRoot" }
        foreach ($scanPath in $ScanPaths) {
            $inventory = Get-ScanInventory -Root $scanPath
            foreach ($failure in $inventory.Errors) { $errors.Add($failure) }
            foreach ($file in $inventory.Files) {
                if ($QuickScan) {
                    $relative = $file.Substring($VolumeRoot.TrimEnd('\','/').Length).TrimStart('\','/').Replace('\','/')
                    $selected = $false
                    foreach ($pattern in @('Users/*/Documents/*','Users/*/Desktop/*','Users/*/Downloads/*','Users/*/AppData/Local/Temp/*','Users/*/AppData/Roaming/*','Windows/Temp/*','ProgramData/*','inetpub/wwwroot/*','Windows/System32/config/*')) {
                        if ($relative -like $pattern) { $selected = $true; break }
                    }
                    if (-not $selected) { continue }
                }
                if ($seen.Add($file)) { $files.Add($file) }
            }
        }
        if ($QuickScan -and -not $files.Count) { throw "No QuickScan files found on $VolumeRoot. Supply each mounted disk root explicitly, or use a full scan." }
        # An empty readable root is a completed zero-file scope, but rules must
        # still compile. Never let an empty mount hide an invalid rule pack.
        $empty = $null
        $scanFiles = $files.ToArray()
        if (-not $files.Count) {
            $empty = [IO.Path]::GetTempFileName()
            $scanFiles = @($empty)
        }
        try {
            for ($offset = 0; $offset -lt $scanFiles.Count; $offset += 128) {
                $batch = @($scanFiles[$offset..([Math]::Min($offset + 127, $scanFiles.Count - 1))])
                $list = [IO.Path]::GetTempFileName()
                try {
                    # YARA's Windows scan-list reader treats raw bytes as wchar_t;
                    # Unix uses getline. Neither reader strips a BOM.
                    $listEncoding = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                        [Text.UnicodeEncoding]::new($false, $false)
                    } else { [Text.UTF8Encoding]::new($false) }
                    [IO.File]::WriteAllLines($list, [string[]]$batch, $listEncoding)
                    $batchComplete = $true
                    foreach ($ruleFile in $yaraRules) {
                        if (-not $empty) { $attempted += $batch.Count }
                        $result = Invoke-ProcessWithTimeout -FilePath $YaraPath -Arguments @('--scan-list','--no-follow-symlinks','-p','1','-s','-m','-w',$ruleFile.FullName,$list) -TimeoutSeconds $ScanTimeout
                        # Preserve available findings even when another file in
                        # the same batch failed. stderr is authoritative too.
                        if ($result.Output -and -not $empty) {
                            $parsed = @(Parse-YARAOutput -Output $result.Output -VolumeRoot $VolumeRoot -VMName $VMName)
                            foreach ($finding in $parsed) { $findings.Add($finding) }
                            if (-not $parsed.Count) { $errors.Add('YARA produced output that could not be parsed.'); $batchComplete = $false }
                        }
                        if ($result.TimedOut -or $result.ExitCode -ne 0 -or $result.StandardError) {
                            $errors.Add("YARA failed for '$VolumeRoot' with '$($ruleFile.Name)' (exit $($result.ExitCode), timed out: $($result.TimedOut)): $($result.StandardError -join '; ')")
                            $batchComplete = $false
                        }
                    }
                    if ($batchComplete -and -not $empty) { $completed += $batch.Count }
                } finally { Remove-Item -LiteralPath $list -Force -ErrorAction SilentlyContinue }
            }
        } finally { if ($empty) { Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue } }
    } catch { $errors.Add("Scan incomplete on '$VolumeRoot': $_") }
    $result = [pscustomobject]@{
        Root = $VolumeRoot; Findings = $findings.ToArray(); Errors = $errors.ToArray()
        EnumeratedFiles = $files.Count; CompletedFiles = $completed; FileRuleAttempts = $attempted
        Status = if ($errors.Count) { 'Error' } else { 'Completed' }
    }
    if ($Detailed) { return $result }
    if ($errors.Count) { throw ($errors -join '; ') }
    return $findings.ToArray()
}

function Parse-YARAOutput {
    param(
        [object[]]$Output,
        [string]$VolumeRoot,
        [string]$VMName
    )
    
    $findings = @()
    $currentRule = $null
    $currentFile = $null
    $currentStrings = @()
    $currentMetadata = @{}
    $currentEvidence = @()
    
    foreach ($line in $Output) {
        # Guard against null entries in the output array (a null .ToString()
        # would throw and abort parsing of every remaining finding).
        if ($null -eq $line) { continue }
        $lineStr = $line.ToString().TrimEnd("`r", "`n")

        # Skip empty lines and errors
        if ([string]::IsNullOrWhiteSpace($lineStr)) { continue }
        if ($lineStr -match '^error:') { continue }
        if ($lineStr -match '^warning:') { continue }
        
        # Match pattern: RuleName FilePath
        # Handles rule names with dots/dashes and paths with spaces
        if ($lineStr -match '^([A-Za-z0-9_.-]+)\s+(.+)$') {
            # Capture the regex groups IMMEDIATELY. The "save previous finding"
            # block below runs pipeline -match operations ($_ -match '\.onion')
            # that overwrite the automatic $Matches variable; reading
            # $Matches[1]/$Matches[2] after it would yield null and crash
            # parsing the moment a second rule block appears (i.e. any file that
            # matches more than one rule).
            $newRule = $Matches[1]
            $newFile = $Matches[2].Trim()

            # Save previous finding if exists
            if ($currentFile) {
                $findings += [PSCustomObject]@{
                    VMName = $VMName
                    Rule = $currentRule
                    File = $currentFile
                    WindowsPath = Convert-ToWindowsPath -MountedPath $currentFile -VolumeRoot $VolumeRoot
                    MatchedStrings = ($currentStrings | Where-Object { $_ } | Select-Object -Unique) -join ' | '
                    OnionLinks = ($currentStrings | Where-Object { $_ -match '\.onion' } | Select-Object -Unique) -join ' | '
                    Timestamp = Get-Date
                    Metadata = $currentMetadata
                    Evidence = @($currentEvidence)
                }
            }

            # Start new finding. Remove metadata/tags if present:
            # "Rule [tags] /path" -> "/path"
            $currentRule = $newRule
            $currentFile = $newFile
            $currentMetadata = @{}
            $header = [regex]::Match($newFile, '^\[(?<meta>(?:"(?:\\.|[^"\\])*"|[^"\]])*)\]\s+(?<path>.+)$')
            if ($header.Success) {
                $currentFile = $header.Groups['path'].Value
                foreach ($entry in [regex]::Matches($header.Groups['meta'].Value, '(?<key>\w+)=(?<value>"(?:\\.|[^"\\])*"|true|false|-?\d+)')) {
                    $raw = $entry.Groups['value'].Value
                    try { $value = ConvertFrom-Json -InputObject $raw -ErrorAction Stop }
                    catch { $value = $raw } # Preserve unusual vendor escapes verbatim.
                    $currentMetadata[$entry.Groups['key'].Value] = $value
                }
            }

            # Reset strings array
            $currentStrings = @()
            $currentEvidence = @()
        }
        # Match pattern: 0x<offset>:$<identifier>: <matched_string>
        # This captures the actual .onion URLs and other matched strings
        elseif ($lineStr -match '^0x([0-9a-f]+):(\$[^:]+): ?(.*)$') {
            $offsetValue = [Convert]::ToInt64($Matches[1], 16)
            $identifier = $Matches[2]
            $matchedString = $Matches[3]
            $currentEvidence += [pscustomobject]@{ Identifier = $identifier; Offset = $offsetValue; RawValue = $matchedString }
            if ($matchedString) {
                $currentStrings += $matchedString
            }
        }
    }
    
    # Save last finding
    if ($currentFile) {
        $findings += [PSCustomObject]@{
            VMName = $VMName
            Rule = $currentRule
            File = $currentFile
            WindowsPath = Convert-ToWindowsPath -MountedPath $currentFile -VolumeRoot $VolumeRoot
            MatchedStrings = ($currentStrings | Where-Object { $_ } | Select-Object -Unique) -join ' | '
            OnionLinks = ($currentStrings | Where-Object { $_ -match '\.onion' } | Select-Object -Unique) -join ' | '
            Timestamp = Get-Date
            Metadata = $currentMetadata
            Evidence = @($currentEvidence)
        }
    }
    
    foreach ($finding in $findings) {
        $indicators = @()
        foreach ($evidence in $finding.Evidence) {
            $text = $evidence.RawValue
            # Decode only the CLI's unambiguous ASCII-wide representation for
            # extraction. The original CLI bytes/escapes remain in RawValue.
            if ($text -cmatch '^(?:[ -~]\\x00)+$') { $text = $text -creplace '\\x00', '' }
            foreach ($hostMatch in [regex]::Matches($text, '(?i)(?<![a-z0-9_-])(?:[a-z2-7]{16}|[a-z2-7]{56})\.onion(?![a-z0-9_.-])')) {
                $indicators += $hostMatch.Value.ToLowerInvariant()
            }
        }
        $finding | Add-Member -NotePropertyName Indicators -NotePropertyValue @($indicators | Sort-Object -Unique)
    }
    return $findings
}

function Convert-ToWindowsPath {
    param(
        [string]$MountedPath,
        [string]$VolumeRoot
    )

    return $MountedPath
}

function Export-ScanResults {
    param(
        [object[]]$AllFindings,
        [ValidateSet('Completed', 'Error')][string]$Status = 'Completed',
        [string[]]$ScanError,
        [object[]]$Coverage = @(),
        [object[]]$Notifications = @()
    )
    
    if (-not $AllFindings) {
        $AllFindings = @()
    }

    # Drop any null entries a worker may have emitted so Group-Object /
    # Select-Object below never dereference a null finding.
    $AllFindings = @($AllFindings | Where-Object { $_ })

    # Group findings by file for cleaner output
    $groupedResults = $AllFindings | Group-Object -Property WindowsPath | ForEach-Object {
        $file = $_.Name
        $group = $_.Group
        
        [PSCustomObject]@{
            VMName = $group[0].VMName
            WindowsPath = $file
            MountedPath = $group[0].File
            MatchedRules = ($group | Select-Object -ExpandProperty Rule | Sort-Object -Unique) -join ', '
            OnionLinks = ($group | Select-Object -ExpandProperty OnionLinks | Where-Object {$_} | Sort-Object -Unique) -join ' | '
            MatchedStrings = ($group | Select-Object -ExpandProperty MatchedStrings | Where-Object {$_} | Sort-Object -Unique) -join ' | '
            RuleCount = $group.Count
            RuleEvidence = @($group | Select-Object Rule, Metadata, Evidence, Indicators)
            Indicators = @($group | ForEach-Object { $_.Indicators } | Where-Object { $_ } | Sort-Object -Unique)
        }
    }
    
    # Probe the YARA version best-effort and OUTSIDE the report-write try: a
    # missing/erroring yara binary must not prevent a report full of real
    # findings from being written.
    $yaraVersion = "unknown"
    try {
        $probe = Invoke-ProcessWithTimeout -FilePath $YaraPath -Arguments @('--version') -TimeoutSeconds 10
        if (-not $probe.TimedOut -and $probe.ExitCode -eq 0 -and $probe.Output) {
            $yaraVersion = ($probe.Output -join ' ').Trim()
        }
    } catch {
        # leave $yaraVersion = "unknown"
    }

    # Export to JSON
    try {
        $jsonOutput = @{
            SchemaVersion = 2
            NotificationStatus = @($Notifications)
            Assessment = 'Rule indicators only; analyst review required.'
            ScanTimestamp = (Get-Date).ToString('o')
            JobId = $jobId
            TotalMatches = $AllFindings.Count
            UniqueFiles = @($groupedResults).Count
            YaraVersion = $yaraVersion
            Findings = @($groupedResults)
            Status = $Status
            Errors = @($ScanError | Where-Object { $_ })
            ExecutionMode = $script:ParallelMode
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            Scope = if ($QuickScan) { 'Quick' } else { 'Full' }
            Runtime = $runtime
            Coverage = @($Coverage | Select-Object Root, Status, EnumeratedFiles, CompletedFiles, FileRuleAttempts, Errors)
        } | ConvertTo-Json -Depth 10

        # Specify UTF8 so non-ASCII characters in matched YARA strings are written
        # correctly on PS5.1, which defaults to the system ANSI code page otherwise.
        $temporaryReport = "$jsonReport.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            [IO.File]::WriteAllText($temporaryReport, $jsonOutput, [Text.UTF8Encoding]::new($false))
            if ([IO.File]::Exists($jsonReport)) { [IO.File]::Replace($temporaryReport, $jsonReport, [NullString]::Value) }
            else { [IO.File]::Move($temporaryReport, $jsonReport) }
        } finally {
            if (Test-Path -LiteralPath $temporaryReport) { Remove-Item -LiteralPath $temporaryReport -Force -ErrorAction SilentlyContinue }
        }
        Write-Log "JSON report saved: $jsonReport"
    } catch {
        throw "Failed to write JSON report to '${jsonReport}': $_"
    }
    
    return $groupedResults
}

function Invoke-VolumeScans {
    <#
    .SYNOPSIS
    Scans every mounted volume and returns the aggregated findings, using the
    best parallelism primitive available on the current PowerShell host.

    Tiers (chosen once at startup in $script:ParallelMode):
      ThreadJob   - in-process thread jobs, throttled via -ThrottleLimit (PS7,
                    or PS5.1 with the ThreadJob module).
      Job         - out-of-process Start-Job with manual batching/throttle
                    (plain Windows PowerShell 5.1).
      Sequential  - single-threaded fallback (no job infrastructure at all).

    All tiers run the SAME worker scriptblock and collect findings from the
    worker's output stream, so behaviour is identical across versions. The
    worker uses -ArgumentList only (no $using:, no -Parallel), so nothing here
    is PS7-only syntax.
    #>
    param(
        [object[]]$Volumes,
        [int]$Throttle,
        [object[]]$YaraRuleFiles
    )

    # Serialise the functions each worker runspace must rebuild from scratch.
    $fnTable = @{
        'Write-Log'                 = ${function:Write-Log}.ToString()
        'Invoke-ProcessWithTimeout' = ${function:Invoke-ProcessWithTimeout}.ToString()
        'Invoke-YARAScan'           = ${function:Invoke-YARAScan}.ToString()
        'Get-ScanInventory'         = ${function:Get-ScanInventory}.ToString()
        'Parse-YARAOutput'          = ${function:Parse-YARAOutput}.ToString()
        'Get-ScanTargets'           = ${function:Get-ScanTargets}.ToString()
        'Convert-ToWindowsPath'     = ${function:Convert-ToWindowsPath}.ToString()
    }

    # Worker: rebuild functions in this runspace, scan one volume, EMIT findings.
    # Identical for every tier. Script-scope settings arrive as parameters; the
    # rebuilt functions read them via normal scope lookup. The named log mutex is
    # re-opened lazily inside Write-Log, so nothing stateful is passed in.
    $worker = {
        param($volume, $fns, $YaraPath, $YaraRulesPath, $ScanTimeout, $QuickScan, $logFile, $YaraRuleFiles)
        foreach ($k in $fns.Keys) {
            Set-Item -Path "function:$k" -Value ([ScriptBlock]::Create($fns[$k]))
        }
        Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Log "Processing volume: $($volume.DriveLetter) (VM: $($volume.VMName))"
        $ErrorActionPreference = 'Stop'
        Invoke-YARAScan -ScanPaths @($volume.DriveLetter) -VolumeRoot $volume.DriveLetter -VMName $volume.VMName -YaraRuleFiles $YaraRuleFiles -Detailed

    }

    # Build the positional argument array for one volume. -ArgumentList unrolls
    # this into the worker's param() positionally; the same array is splatted
    # (@wArgs) for direct sequential invocation.
    function script:Get-WorkerArgs($v) {
        return ,@($v, $fnTable, $YaraPath, $YaraRulesPath, $ScanTimeout, $QuickScan, $logFile, $YaraRuleFiles)
    }

    $all = @()
    $jobs = @()
    try {
        foreach ($v in $Volumes) {
            $wArgs = Get-WorkerArgs $v
            if ($script:ParallelMode -eq 'Sequential') {
                $all += & $worker @wArgs
                continue
            }
            if ($script:ParallelMode -eq 'ThreadJob') {
                $jobs += Start-ThreadJob -ScriptBlock $worker -ThrottleLimit $Throttle -ArgumentList $wArgs -ErrorAction Stop
            } else {
                $jobs += Start-Job -ScriptBlock $worker -ArgumentList $wArgs -ErrorAction Stop
            }
            if ($jobs.Count -ge $Throttle) {
                $jobs | Wait-Job -ErrorAction Stop | Out-Null
                foreach ($job in $jobs) {
                    if ($job.State -ne 'Completed') {
                        $all += [pscustomobject]@{ Root = 'Worker'; Findings = @(); Errors = @("Scan worker ended in state $($job.State): $($job.ChildJobs[0].JobStateInfo.Reason)"); Status = 'Error'; EnumeratedFiles = 0; CompletedFiles = 0; FileRuleAttempts = 0 }
                        continue
                    }
                    $all += Receive-Job -Job $job -ErrorAction Stop
                }
                $jobs | Remove-Job -Force -ErrorAction Stop
                $jobs = @()
            }
        }
        if ($jobs.Count -gt 0) {
            $jobs | Wait-Job -ErrorAction Stop | Out-Null
            foreach ($job in $jobs) {
                if ($job.State -ne 'Completed') {
                        $all += [pscustomobject]@{ Root = 'Worker'; Findings = @(); Errors = @("Scan worker ended in state $($job.State): $($job.ChildJobs[0].JobStateInfo.Reason)"); Status = 'Error'; EnumeratedFiles = 0; CompletedFiles = 0; FileRuleAttempts = 0 }
                        continue
                    }
                $all += Receive-Job -Job $job -ErrorAction Stop
            }
        }
    } catch {
        # Never discard outcomes already collected because job infrastructure
        # failed later (launch, receive, wait, or cleanup).
        $all += [pscustomobject]@{ Root = 'Worker infrastructure'; Findings = @(); Errors = @("Scan orchestration failed: $_"); Status = 'Error'; EnumeratedFiles = 0; CompletedFiles = 0; FileRuleAttempts = 0 }
    } finally {
        foreach ($job in $jobs) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }

    return @($all)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

if (-not $script:DotSourced) {
    try {
        $runtime = Initialize-VbrRuntime -Mode $RuntimeMode -ScriptPath $PSCommandPath -Parameters $PSBoundParameters -Hop $RuntimeHop
        if ($runtime.Action -eq 'Exit') { exit $runtime.ExitCode }
        if ($PreflightOnly) {
            $runtime | ConvertTo-Json -Depth 4
            exit 0
        }
    } catch {
        [Console]::Error.WriteLine("Runtime preflight failed: $_")
        exit 2
    }
}

$script:PSMajor      = $PSVersionTable.PSVersion.Major
$script:HasThreadJob = [bool](Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)
if (-not $script:HasThreadJob -and (Get-Module -ListAvailable -Name ThreadJob)) {
    # PS5.1 can opt in to in-process thread jobs if the ThreadJob module is installed.
    Import-Module ThreadJob -ErrorAction SilentlyContinue
    $script:HasThreadJob = [bool](Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)
}
$script:HasStartJob  = [bool](Get-Command Start-Job -ErrorAction SilentlyContinue)
$script:ParallelMode =
    if     ($script:HasThreadJob) { 'ThreadJob' }   # in-process, shared bag, -ThrottleLimit
    elseif ($script:HasStartJob)  { 'Job' }         # out-of-process, manual throttle + collect
    else                          { 'Sequential' }  # last-resort single-threaded

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss_fff"
$jobId = if ($SessionId) { $SessionId -replace '[^a-zA-Z0-9_.-]', '_' } else { "Manual_$timestamp" }

# Initialize logging. Creating the log directory can fail (insufficient rights,
# missing parent, read-only volume); fall back to a temp location and keep going
# rather than aborting the entire scan before logging is even available.
if (-not $script:DotSourced) {
    try {
        New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop | Out-Null
    } catch {
        $fallbackLogPath = Join-Path ([System.IO.Path]::GetTempPath()) "Veeam-YARA-SecureRestore"
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARNING] Could not create log directory '$LogPath' ($_); falling back to '$fallbackLogPath'."
        try {
            New-Item -ItemType Directory -Path $fallbackLogPath -Force -ErrorAction Stop | Out-Null
            $LogPath = $fallbackLogPath
        } catch {
            Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Could not create fallback log directory '$fallbackLogPath' ($_); file logging disabled."
        }
    }
}

# Use [IO.Path]::Combine rather than Join-Path: Join-Path resolves the path's
# drive qualifier against the PSDrive list and throws if it is absent (e.g. a
# "C:\..." default evaluated on a non-Windows test/CI host), whereas Combine is
# pure string composition and yields identical results on Windows.
$logFile = [System.IO.Path]::Combine($LogPath, "scan_${jobId}_${timestamp}.log")
$jsonReport = [System.IO.Path]::Combine($LogPath, "results_${jobId}_${timestamp}.json")

# Flag to emit the Add-VBRJobLogEvent warning only once per run, not on every log call.
$script:VBRLogEventWarned = $false

# Skip the scan when the script was only dot-sourced for its functions (tests /
# tooling). All functions above are now defined in the caller's scope; returning
# here leaves them available without launching a real scan.
if ($script:DotSourced) { return }

try {
    Write-Log "=== Veeam YARA Secure Restore Scanner Started ==="
    Write-Log "YARA Path: $YaraPath"
    Write-Log "Rules Path: $YaraRulesPath"
    Write-Log "Job ID: $jobId"
    Write-Log "Scan Mode: $(if($QuickScan){'Quick'}else{'Full'})"
    
    $ErrorActionPreference = 'Stop'
    if ($ExecutionMode -ne 'Auto') {
        if ($ExecutionMode -eq 'ThreadJob' -and -not $script:HasThreadJob) { throw 'ThreadJob was requested but is unavailable.' }
        if ($ExecutionMode -eq 'Job' -and -not $script:HasStartJob) { throw 'Start-Job was requested but is unavailable.' }
        $script:ParallelMode = $ExecutionMode
    }
    Write-Log "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition); executable $((Get-Process -Id $PID).Path); execution $script:ParallelMode"
    if (-not (Test-Path -LiteralPath $YaraPath -PathType Leaf)) {
        throw "YARA not found at $YaraPath. Please install YARA for Windows."
    }
    
    $probe = Invoke-ProcessWithTimeout -FilePath $YaraPath -Arguments @('--version') -TimeoutSeconds 10
    if ($probe.TimedOut -or $probe.ExitCode -ne 0 -or -not $probe.Output) { throw 'YARA version probe failed.' }
    Write-Log "YARA Version: $($probe.Output -join ' ')"
    
    # Verify YARA rules exist
    if (-not (Test-Path -LiteralPath $YaraRulesPath)) {
        throw "YARA rules directory not found: $YaraRulesPath"
    }
    
    $yaraRules = @(Get-ChildItem -LiteralPath $YaraRulesPath -Filter "*.yar*" -File)
    $ruleCount = $yaraRules.Count
    if ($ruleCount -eq 0) {
        throw "No YARA rules found in $YaraRulesPath"
    }
    Write-Log "Found $ruleCount YARA rule file(s)"
    
    # Discover mounted volumes
    if ($ScanPath) {
        $volumes = @(foreach ($target in $ScanPath) {
            $resolved = Get-Item -LiteralPath $target -ErrorAction Stop
            if (-not $resolved.PSIsContainer -or $resolved.PSProvider.Name -ne 'FileSystem') {
                throw "ScanPath must be a local filesystem directory: $target"
            }
            [pscustomobject]@{ DriveLetter = $resolved.FullName; VMName = 'ExplicitTarget' }
        })
    } else {
        $volumes = @(Get-MountedVMVolumes)
    }
    if ($volumes.Count -eq 0) { throw 'No volumes to scan. Supply -ScanPath with the mounted restore directory.' }
    

    $throttle = [Environment]::ProcessorCount
    Write-Log "Scanning $($volumes.Count) volume(s) (throttle: $throttle)"

    $scanResults = @(Invoke-VolumeScans -Volumes $volumes -Throttle $throttle -YaraRuleFiles $yaraRules)
    $allFindings = @($scanResults | ForEach-Object { $_.Findings })
    $scanErrors = @($scanResults | ForEach-Object { $_.Errors })
    if ($scanErrors.Count) {
        $null = Export-ScanResults -AllFindings $allFindings -Status Error -ScanError $scanErrors -Coverage $scanResults
        Write-Log "Scan incomplete. Retained $($allFindings.Count) finding(s). $($scanErrors -join '; ')" -Level ERROR
        exit 2
    }
    
    # Display results
    Write-Log ""
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Log "=== SCAN SUMMARY ==="
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Log "Total Volumes Scanned: $($volumes.Count)"
    Write-Log "Total Matches: $($allFindings.Count)"
    
    if ($allFindings.Count -gt 0) {
        Write-Log ""
        Write-Log "⚠️⚠️⚠️  YARA INDICATORS MATCHED - REVIEW REQUIRED  ⚠️⚠️⚠️" -Level "WARNING"
        Write-Log ""

        # Persist primary evidence before any optional network activity.
        $results = @(Export-ScanResults -AllFindings $allFindings -Coverage $scanResults)
        $alertMsg = "YARA INDICATORS: $($allFindings.Count) match(es) across $($volumes.Count) volume(s). Job: $jobId; review required."
        $notifications = @()
        try { $notifications += @(Send-SyslogAlert -Message $alertMsg -Severity 4) }
        catch { $notifications += [pscustomobject]@{ Channel = 'Syslog'; Status = 'Failed'; Detail = "$_" } }
        try { $notifications += @(Send-VeeamOneAlarm -AlarmMessage $alertMsg -FindingsCount $allFindings.Count) }
        catch { $notifications += [pscustomobject]@{ Channel = 'VeeamONE'; Status = 'Failed'; Detail = "$_" } }
        if ($notifications.Count) { $null = Export-ScanResults -AllFindings $allFindings -Coverage $scanResults -Notifications $notifications }

        # Display detailed findings with onion links
        foreach ($result in $results) {
            Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -Level "WARNING"
            Write-Log "VM: $($result.VMName)" -Level "WARNING"
            Write-Log "Windows Path: $($result.WindowsPath)" -Level "WARNING"
            Write-Log "  Matched Rules: $($result.MatchedRules)"
            
            if ($result.OnionLinks) {
                Write-Log "  🔴 Onion Links: $($result.OnionLinks)" -Level "WARNING"
            }
            
            if ($result.MatchedStrings -and $result.MatchedStrings -ne $result.OnionLinks) {
                Write-Log "  Other Matches: $($result.MatchedStrings)"
            }
        }
        
        Write-Log ""
        Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Log ""
        Write-Log "⚠️  ACTION REQUIRED: Review matched files before restoring!" -Level "WARNING"
        Write-Log "Full report: $jsonReport"
        Write-Log ""
        
        # Exit with error code to fail Veeam job
        exit 1
        
    } else {
        Write-Log ""
        $null = Export-ScanResults -AllFindings @() -Coverage $scanResults
        Write-Log "Scan completed. No selected YARA rules matched within the scanned scope."
        Write-Log ""
        Write-Log "Full report: $jsonReport"
        exit 0
    }
    
} catch {
    Write-Log "FATAL ERROR: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    try { $null = Export-ScanResults -AllFindings @($allFindings) -Status Error -ScanError "$_" -Coverage @($scanResults) }
    catch { Write-Log "Could not persist the error report: $_" -Level ERROR }
    exit 2
}
