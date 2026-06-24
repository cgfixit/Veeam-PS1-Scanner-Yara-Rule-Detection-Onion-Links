#Requires -Version 5.1
# Veeam-YARA-SecureRestore.ps1
# Native Windows YARA scanner for Veeam Secure Restore
# Extracts matched onion link strings with full file path details
#
# Dual-version support:
#   * Primary target  : Windows PowerShell 5.1 (native Windows / Veeam v12 host).
#   * Accelerated path : PowerShell 7 (or 5.1 + ThreadJob module) for parallel
#                        per-volume scanning.
# The script runs correctly on either version; PS7-only features are detected
# at runtime and used only when available, never required. No PS7-only *syntax*
# is used in the script body, so it parses cleanly under Windows PowerShell 5.1.
#
# NOTE: save this file as UTF-8 *with BOM* — Windows PowerShell 5.1 reads
# BOM-less files as the system ANSI codepage, which corrupts the box-drawing /
# emoji characters used in log output.

param(
    [Parameter(Mandatory=$false)]
    [string]$YaraPath = "C:\Program Files\YARA\yara64.exe",
    
    [Parameter(Mandatory=$false)]
    [string]$YaraRulesPath = "C:\ProgramData\YARA\Rules",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\Veeam\Logs\YARA-SecureRestore",
    
    [Parameter(Mandatory=$false)]
    [string]$SessionId,
    
    [Parameter(Mandatory=$false)]
    [int]$ScanTimeout = 3600,  # 1 hour
    
    [Parameter(Mandatory=$false)]
    [switch]$QuickScan,  # Only scan common malware locations

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

# ── Runtime capability probe ────────────────────────────────────────────────
# Decide once which parallelism primitive is available, then cache the result.
# This is the heart of the "PS5.1-primary, PS7-accelerated" design: nothing is
# required, everything is detected.
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

# Named mutex serialises log-file writes across in-process runspaces AND
# out-of-process Start-Job children. A named mutex must be re-opened by name in
# each runspace (the object cannot cross a process boundary), so it is opened
# lazily inside Write-Log rather than passed around. See Write-Log below.

# ── Test / dot-source guard ──────────────────────────────────────────────────
# When this file is dot-sourced (e.g. by the Pester suite under tests/) we want
# the function definitions to load WITHOUT the start-up side effects (log
# directory creation) or the full volume scan firing. $MyInvocation.InvocationName
# is '.' only when dot-sourced; the VEEAM_YARA_NOEXEC env var is an explicit
# import-only override for any other tooling.
$script:DotSourced = ($MyInvocation.InvocationName -eq '.') -or [bool]$env:VEEAM_YARA_NOEXEC

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jobId = if ($SessionId) { $SessionId } else { "Manual_$timestamp" }

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

    # RFC 5424 syslog over UDP — no external module required
    $facility  = 16   # local0
    $pri       = ($facility * 8) + $Severity
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $hostname  = $env:COMPUTERNAME
    $appName   = "VeeamYARAScanner"
    $syslogMsg = "<$pri>1 $timestamp $hostname $appName - - - $Message"

    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($syslogMsg)
        $udp.Send($bytes, $bytes.Length, $SyslogServer, $SyslogPort) | Out-Null
        Write-Log "Syslog alert sent to ${SyslogServer}:${SyslogPort}"
    } catch {
        Write-Log "WARNING: Syslog send failed: $_" -Level "WARNING"
    } finally {
        $udp.Dispose()
    }
}

function Send-VeeamOneAlarm {
    param(
        [string]$AlarmMessage,
        [int]$FindingsCount
    )
    if (-not $EnableVeeamOne) { return }

    # CRITICAL NOTE: THIS veeam one alarm integrstion currently  inexplicably DOESNT REALLY DO ANYTHING DUE TO THERE BEING NO OFFICIAL POST API for VEEAM ONE TO GENERATE AN ALARM BUT I WAS JUST ILLUSTRATONG THE CONCEPT; can still have it post to vbr api or many othrr options
    # Veeam ONE REST API — raises a MalwareDetected alarm visible in the console.
    # Use HTTPS: the alarm payload includes sensitive scan details; plain HTTP
    # exposes them to network interception on the backup infrastructure segment.
    $uri  = "https://${VeeamOneServer}:${VeeamOnePort}/api/v2.1/alarms"
    $body = @{
        name    = "MalwareDetected"
        message = $AlarmMessage
        details = "Veeam YARA Secure Restore detected $FindingsCount malware indicator(s). Review before restoring."
    } | ConvertTo-Json

    try {
        $null = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
            -ContentType "application/json" -UseDefaultCredentials
        Write-Log "Veeam ONE alarm raised at ${VeeamOneServer}:${VeeamOnePort}"
    } catch {
        Write-Log "WARNING: Veeam ONE alarm failed: $_" -Level "WARNING"
    }
}

function Get-MountedVMVolumes {
    <#
    .SYNOPSIS
    Discovers mounted VM volumes from Veeam SureBackup or Instant Recovery
    #>
    
    Write-Log "Discovering mounted VM volumes..."

    # Get all volumes (mounted VMs appear as standard volumes). Get-Volume can
    # throw on hosts without the Storage module or when WMI/CIM is unhealthy;
    # treat that as "no volumes" so the caller exits cleanly instead of crashing.
    try {
        $volumes = Get-Volume -ErrorAction Stop | Where-Object {
            $_.DriveLetter -and
            $_.FileSystemType -in @('NTFS', 'ReFS') -and
            $_.DriveLetter -notin @('C')  # Exclude system drive
        }
    } catch {
        Write-Log "ERROR: Failed to enumerate volumes via Get-Volume: $_" -Level "ERROR"
        return @()
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
            $looksWindows = (Test-Path $systemRoot) -or (Test-Path $usersDir)
        } catch {
            Write-Log "WARNING: Could not probe paths on $driveLetter ($_); skipping volume." -Level "WARNING"
            continue
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
        $fullPath = Join-Path $VolumeRoot $target
        if (Test-Path $fullPath) {
            $scanPaths += $fullPath
        }
    }
    
    return $scanPaths
}

function Invoke-ProcessWithTimeout {
    <#
    .SYNOPSIS
    Runs an external executable with a hard timeout, returning its combined
    stdout/stderr lines. Version-neutral: uses System.Diagnostics.Process, which
    behaves identically on Windows PowerShell 5.1 and PowerShell 7, with no
    dependency on Start-Job / Start-ThreadJob.
    .OUTPUTS
    [pscustomobject] @{ TimedOut = [bool]; ExitCode = [int]; Output = [string[]] }
    #>
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [int]$TimeoutSeconds
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    # NOTE: ProcessStartInfo.ArgumentList is .NET Core 2.1+ only and does NOT
    # exist on .NET Framework 4.x (Windows PowerShell 5.1). Build a quoted
    # Arguments string instead so this runs on both runtimes. Quote any token
    # containing whitespace; YARA rule/scan paths never contain embedded quotes.
    $psi.Arguments = ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }) -join ' '

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi

    # Drain stdout/stderr asynchronously so a large match list can't deadlock the
    # pipe buffer while we wait on the process.
    $sb = [System.Text.StringBuilder]::new()
    $outHandler = {
        if ($EventArgs.Data -ne $null) { [void]$Event.MessageData.AppendLine($EventArgs.Data) }
    }
    $outSub = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action $outHandler -MessageData $sb
    $errSub = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived  -Action $outHandler -MessageData $sb

    $timedOut = $false
    $exitCode = -1
    try {
        [void]$proc.Start()
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $proc.Kill() } catch {}
            try { [void]$proc.WaitForExit(5000) } catch {}
        } else {
            # Ensure async buffers are fully flushed after a normal exit.
            try { $proc.WaitForExit() } catch {}
            # Capture exit code before Dispose() clears it. YARA exit codes:
            # 0 = match(es) found, 1 = no matches, >1 = error (bad rule, access denied, etc.)
            try { $exitCode = $proc.ExitCode } catch {}
        }
    } catch {
        # The process failed to start (missing/invalid executable, access denied)
        # or died mid-lifecycle. Surface it as an error exit code (>1, matching
        # YARA's error convention) with the message in Output so the caller logs
        # it cleanly instead of throwing out of the scan loop.
        [void]$sb.AppendLine("Invoke-ProcessWithTimeout failed to run '$FilePath': $_")
        $exitCode = 2
    } finally {
        Unregister-Event -SourceIdentifier $outSub.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errSub.Name -ErrorAction SilentlyContinue
        $proc.Dispose()
    }

    $lines = $sb.ToString() -split "`r?`n" | Where-Object { $_ -ne '' }
    return [pscustomobject]@{ TimedOut = $timedOut; ExitCode = $exitCode; Output = $lines }
}

function Invoke-YARAScan {
    param(
        [string[]]$ScanPaths,
        [string]$VolumeRoot,
        [string]$VMName
    )
    
    Write-Log "Starting YARA scan on: $VolumeRoot (VM: $VMName)"
    
    # Get all YARA rule files
    $yaraRules = Get-ChildItem -Path $YaraRulesPath -Filter "*.yar*" -File
    
    if ($yaraRules.Count -eq 0) {
        Write-Log "ERROR: No YARA rules found in $YaraRulesPath" -Level "ERROR"
        return $null
    }
    
    Write-Log "Using $($yaraRules.Count) YARA rule file(s)"
    
    $allFindings = @()
    $startTime = Get-Date
    
    foreach ($scanPath in $ScanPaths) {
        Write-Log "Scanning: $scanPath"
        
        foreach ($ruleFile in $yaraRules) {
            # Build YARA command with matched string output
            # -r = recursive, -s = show matched strings (CRITICAL), -m = metadata
            $yaraArgs = @(
                "-r",
                "-s",  # This extracts the actual .onion URLs
                "-m",
                "-w",  # no warnings
                $ruleFile.FullName,
                $scanPath
            )
            
            try {
                # Execute YARA with a hard timeout via a plain external process.
                # This is version-neutral (no Start-Job / Start-ThreadJob), so it
                # runs identically on Windows PowerShell 5.1 and PowerShell 7.
                $result = Invoke-ProcessWithTimeout -FilePath $YaraPath `
                            -Arguments $yaraArgs -TimeoutSeconds $ScanTimeout

                if ($result.TimedOut) {
                    Write-Log "WARNING: Scan timed out for $scanPath (rule: $($ruleFile.Name))" -Level "WARNING"
                } elseif ($result.ExitCode -gt 1) {
                    # YARA exit codes: 0=match, 1=no match, >1=error (bad rule syntax, permission denied, etc.)
                    $errDetail = ($result.Output -join '; ').Trim()
                    Write-Log "ERROR: YARA exited with code $($result.ExitCode) for rule '$($ruleFile.Name)' on '$scanPath'$(if ($errDetail) { ": $errDetail" })" -Level "ERROR"
                } elseif ($result.Output) {
                    # Parse YARA output
                    $findings = Parse-YARAOutput -Output $result.Output -VolumeRoot $VolumeRoot -VMName $VMName
                    $allFindings += $findings
                }
            } catch {
                Write-Log "ERROR scanning $scanPath : $_" -Level "ERROR"
            }
        }
    }
    
    $duration = ((Get-Date) - $startTime).TotalSeconds
    Write-Log "Scan completed in $duration seconds"
    
    return $allFindings
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
    
    foreach ($line in $Output) {
        # Guard against null entries in the output array (a null .ToString()
        # would throw and abort parsing of every remaining finding).
        if ($null -eq $line) { continue }
        $lineStr = $line.ToString().Trim()

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
                }
            }

            # Start new finding. Remove metadata/tags if present:
            # "Rule [tags] /path" -> "/path"
            $currentRule = $newRule
            $currentFile = $newFile -replace '^\[[^\]]*\]\s*', ''

            # Reset strings array
            $currentStrings = @()
        }
        # Match pattern: 0x<offset>:$<identifier>: <matched_string>
        # This captures the actual .onion URLs and other matched strings
        elseif ($lineStr -match '0x[0-9a-f]+:\$[^:]+:\s*(.+)$') {
            $matchedString = $Matches[1].Trim()
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
        }
    }
    
    return $findings
}

function Convert-ToWindowsPath {
    param(
        [string]$MountedPath,
        [string]$VolumeRoot
    )

    # Guard against a missing or too-short volume root (e.g. "" or "E"): the
    # Substring(0,2) below would throw and crash conversion for every finding.
    # Fall back to returning the original path unchanged.
    if ([string]::IsNullOrEmpty($VolumeRoot) -or $VolumeRoot.Length -lt 2) {
        return $MountedPath
    }

    # Return the path under the actual mounted drive letter.
    # VolumeRoot is the letter Veeam assigned (e.g. "E:\"); strip it then
    # re-prefix with that same letter so console and JSON both report E:\...
    # rather than the previously hard-coded C:\.
    $relativePath = $MountedPath -replace [regex]::Escape($VolumeRoot), ''
    $relativePath = $relativePath.TrimStart('\')
    $driveLetter  = $VolumeRoot.Substring(0, 2)   # e.g. "E:"
    return "$driveLetter\$relativePath"
}

function Export-ScanResults {
    param([object[]]$AllFindings)
    
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
        }
    }
    
    # Probe the YARA version best-effort and OUTSIDE the report-write try: a
    # missing/erroring yara binary must not prevent a report full of real
    # findings from being written.
    $yaraVersion = "unknown"
    try {
        $probe = & $YaraPath --version 2>&1 | Select-Object -First 1
        if ($probe) { $yaraVersion = "$probe".Trim() }
    } catch {
        # leave $yaraVersion = "unknown"
    }

    # Export to JSON
    try {
        $jsonOutput = @{
            ScanTimestamp = (Get-Date).ToString('o')
            JobId = $jobId
            TotalMatches = $AllFindings.Count
            UniqueFiles = $groupedResults.Count
            YaraVersion = $yaraVersion
            Findings = @($groupedResults)
        } | ConvertTo-Json -Depth 10

        # Specify UTF8 so non-ASCII characters in matched YARA strings are written
        # correctly on PS5.1, which defaults to the system ANSI code page otherwise.
        Set-Content -Path $jsonReport -Value $jsonOutput -Encoding UTF8
        Write-Log "JSON report saved: $jsonReport"
    } catch {
        Write-Log "ERROR: Failed to write JSON report to '${jsonReport}': $_" -Level "ERROR"
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
        [int]$Throttle
    )

    # Serialise the functions each worker runspace must rebuild from scratch.
    $fnTable = @{
        'Write-Log'                 = ${function:Write-Log}.ToString()
        'Invoke-ProcessWithTimeout' = ${function:Invoke-ProcessWithTimeout}.ToString()
        'Invoke-YARAScan'           = ${function:Invoke-YARAScan}.ToString()
        'Parse-YARAOutput'          = ${function:Parse-YARAOutput}.ToString()
        'Get-ScanTargets'           = ${function:Get-ScanTargets}.ToString()
        'Convert-ToWindowsPath'     = ${function:Convert-ToWindowsPath}.ToString()
    }

    # Worker: rebuild functions in this runspace, scan one volume, EMIT findings.
    # Identical for every tier. Script-scope settings arrive as parameters; the
    # rebuilt functions read them via normal scope lookup. The named log mutex is
    # re-opened lazily inside Write-Log, so nothing stateful is passed in.
    $worker = {
        param($volume, $fns, $YaraPath, $YaraRulesPath, $ScanTimeout, $QuickScan, $logFile)
        foreach ($k in $fns.Keys) {
            Set-Item -Path "function:$k" -Value ([ScriptBlock]::Create($fns[$k]))
        }
        Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        Write-Log "Processing volume: $($volume.DriveLetter) (VM: $($volume.VMName))"
        $scanTargets = Get-ScanTargets -VolumeRoot $volume.DriveLetter
        Write-Log "Scan targets: $($scanTargets.Count) path(s)"
        $findings = Invoke-YARAScan -ScanPaths $scanTargets `
                        -VolumeRoot $volume.DriveLetter -VMName $volume.VMName
        if ($findings) {
            Write-Log "⚠️  Found $($findings.Count) matches in $($volume.DriveLetter)" -Level "WARNING"
        } else {
            Write-Log "✓ No threats detected in $($volume.DriveLetter)"
        }
        # Emit findings for the parent to collect (works for ThreadJob, Job, and
        # direct invocation alike).
        $findings
    }

    # Build the positional argument array for one volume. -ArgumentList unrolls
    # this into the worker's param() positionally; the same array is splatted
    # (@wArgs) for direct sequential invocation.
    function script:Get-WorkerArgs($v) {
        return ,@($v, $fnTable, $YaraPath, $YaraRulesPath, $ScanTimeout, $QuickScan, $logFile)
    }

    $all = @()

    switch ($script:ParallelMode) {
        'ThreadJob' {
            Write-Log "Scan mode: ThreadJob (in-process, throttle: $Throttle)"
            $jobs = foreach ($v in $Volumes) {
                $wArgs = Get-WorkerArgs $v
                Start-ThreadJob -ScriptBlock $worker -ThrottleLimit $Throttle -ArgumentList $wArgs
            }
            $jobs | Wait-Job | Out-Null
            $all = $jobs | Receive-Job
            $jobs | Remove-Job -Force
        }
        'Job' {
            Write-Log "Scan mode: Start-Job (out-of-process, throttle: $Throttle)"
            $queue = [System.Collections.Queue]::new()
            foreach ($v in $Volumes) { $queue.Enqueue($v) }
            $running = @()
            while ($queue.Count -gt 0 -or $running.Count -gt 0) {
                while ($running.Count -lt $Throttle -and $queue.Count -gt 0) {
                    $v = $queue.Dequeue()
                    $wArgs = Get-WorkerArgs $v
                    $running += Start-Job -ScriptBlock $worker -ArgumentList $wArgs
                }
                $null = Wait-Job -Job $running -Any
                $finished = @($running | Where-Object { $_.State -in 'Completed','Failed','Stopped' })
                foreach ($f in $finished) {
                    $all += Receive-Job $f
                    Remove-Job $f -Force
                }
                $running = @($running | Where-Object { $_.State -eq 'Running' })
            }
        }
        default {
            Write-Log "Scan mode: Sequential (single-threaded fallback)"
            foreach ($v in $Volumes) {
                $wArgs = Get-WorkerArgs $v
                $all += & $worker @wArgs
            }
        }
    }

    return @($all)
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

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
    
    # Verify YARA is installed
    if (-not (Test-Path $YaraPath)) {
        throw "YARA not found at $YaraPath. Please install YARA for Windows."
    }
    
    $yaraVersion = & $YaraPath --version 2>&1 | Select-Object -First 1
    Write-Log "YARA Version: $yaraVersion"
    
    # Verify YARA rules exist
    if (-not (Test-Path $YaraRulesPath)) {
        throw "YARA rules directory not found: $YaraRulesPath"
    }
    
    $ruleCount = (Get-ChildItem -Path $YaraRulesPath -Filter "*.yar*" -File).Count
    if ($ruleCount -eq 0) {
        throw "No YARA rules found in $YaraRulesPath"
    }
    Write-Log "Found $ruleCount YARA rule file(s)"
    
    # Discover mounted volumes
    $volumes = Get-MountedVMVolumes
    
    if ($volumes.Count -eq 0) {
        Write-Log "No volumes to scan. Exiting." -Level "WARNING"
        exit 0
    }
    
    # Scan all mounted volumes using the best available parallelism tier
    # (ThreadJob / Start-Job / Sequential — chosen at startup in $script:ParallelMode).
    $throttle = [Environment]::ProcessorCount
    Write-Log "Scanning $($volumes.Count) volume(s) (throttle: $throttle)"

    $allFindings = @(Invoke-VolumeScans -Volumes $volumes -Throttle $throttle)
    
    # Display results
    Write-Log ""
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Log "=== SCAN SUMMARY ==="
    Write-Log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Log "Total Volumes Scanned: $($volumes.Count)"
    Write-Log "Total Matches: $($allFindings.Count)"
    
    if ($allFindings.Count -gt 0) {
        Write-Log ""
        Write-Log "⚠️⚠️⚠️  ONION LINKS DETECTED - INFECTED FILES  ⚠️⚠️⚠️" -Level "WARNING"
        Write-Log ""

        # Emit alerts to SIEM and/or Veeam ONE before displaying detail
        $alertMsg = "MALWARE DETECTED: $($allFindings.Count) YARA match(es) across $($volumes.Count) volume(s). Job: $jobId"
        Send-SyslogAlert -Message $alertMsg -Severity 2   # Critical
        Send-VeeamOneAlarm -AlarmMessage $alertMsg -FindingsCount $allFindings.Count

        $results = Export-ScanResults -AllFindings $allFindings
        
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
        Write-Log "⚠️  ACTION REQUIRED: Review infected files before restoring!" -Level "WARNING"
        Write-Log "Full report: $jsonReport"
        Write-Log ""
        
        # Exit with error code to fail Veeam job
        exit 1
        
    } else {
        Write-Log ""
        Write-Log "✅ SUCCESS: No onion links or malware detected - All volumes clean"
        Write-Log ""
        Write-Log "Full report: $jsonReport"
        exit 0
    }
    
} catch {
    Write-Log "FATAL ERROR: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 2
}
