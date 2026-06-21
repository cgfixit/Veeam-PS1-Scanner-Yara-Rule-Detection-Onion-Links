# Veeam-YARA-SecureRestore.ps1
# Native Windows YARA scanner for Veeam Secure Restore
# Extracts matched onion link strings with full file path details

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
    [switch]$QuickScan  # Only scan common malware locations
)

# Initialize logging
New-Item -ItemType Directory -Path $LogPath -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$jobId = if ($SessionId) { $SessionId } else { "Manual_$timestamp" }
$logFile = Join-Path $LogPath "scan_${jobId}_${timestamp}.log"
$jsonReport = Join-Path $LogPath "results_${jobId}_${timestamp}.json"

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
    Add-Content -Path $logFile -Value $logEntry
    
    <#
        Placeholder since that cmdlet doesnt exist yet (only relevant for unified veeam logging; otherwise the paths for this script log are defined
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

function Get-MountedVMVolumes {
    <#
    .SYNOPSIS
    Discovers mounted VM volumes from Veeam SureBackup or Instant Recovery
    #>
    
    Write-Log "Discovering mounted VM volumes..."
    
    # Get all volumes (mounted VMs appear as standard volumes)
    $volumes = Get-Volume | Where-Object {
        $_.DriveLetter -and 
        $_.FileSystemType -in @('NTFS', 'ReFS') -and
        $_.DriveLetter -notin @('C')  # Exclude system drive
    }
    
    $mountedVolumes = @()
    
    foreach ($vol in $volumes) {
        $driveLetter = "$($vol.DriveLetter):\"
        
        # Check if this looks like a Windows volume
        $systemRoot = Join-Path $driveLetter "Windows"
        $usersDir = Join-Path $driveLetter "Users"
        
        if ((Test-Path $systemRoot) -or (Test-Path $usersDir)) {
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
        Write-Log "No mounted Windows volumes found!" -Level "WARNING"
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
        Write-Log "No YARA rules found in $YaraRulesPath" -Level "ERROR"
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
            $yaraArgList = @(
                "-r",
                "-s",  # This extracts the actual .onion URLs
                "-m",
                "-w",  # no warnings
                $ruleFile.FullName,
                $scanPath
            )
            
            # FIX: Do NOT use $args as a param name inside Start-Job scriptblocks.
            # $args is a PowerShell automatic variable; naming a param $args causes
            # `& $exe @args` to splat the automatic (unbound) variable instead of
            # the named parameter, so YARA receives zero arguments on PS5.1.
            # Use $yaraArgList as both the outer variable and the inner param name.
            $job = $null
            try {
                $job = Start-Job -ScriptBlock {
                    param($exe, $yaraArgList)
                    & $exe @yaraArgList 2>&1
                } -ArgumentList $YaraPath, $yaraArgList
                
                $completed = Wait-Job $job -Timeout $ScanTimeout
                
                if ($completed) {
                    $output = Receive-Job $job
                    
                    if ($output) {
                        # Parse YARA output
                        $findings = Parse-YARAOutput -Output $output -VolumeRoot $VolumeRoot -VMName $VMName
                        $allFindings += $findings
                    }
                } else {
                    Write-Log "Scan timed out for $scanPath" -Level "WARNING"
                    Stop-Job $job
                }
                
            } catch {
                Write-Log "Error scanning ${scanPath}: $_" -Level "ERROR"
            } finally {
                # FIX: Always remove the job object to prevent job-table leaks,
                # even when Stop-Job or Receive-Job threw above.
                if ($null -ne $job) {
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
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
        $lineStr = $line.ToString().Trim()
        
        # Skip empty lines and errors
        if ([string]::IsNullOrWhiteSpace($lineStr)) { continue }
        if ($lineStr -match '^error:') { continue }
        if ($lineStr -match '^warning:') { continue }
        
        # Match pattern: RuleName FilePath
        # Handles rule names with dots/dashes and paths with spaces
        if ($lineStr -match '^([A-Za-z0-9_.-]+)\s+(.+)$') {
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
            
            # Start new finding
            $currentRule = $Matches[1]
            $currentFile = $Matches[2].Trim()
            
            # Remove metadata/tags if present: "Rule [tags] /path" -> "/path"
            $currentFile = $currentFile -replace '^\[[^\]]*\]\s*', ''
            
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

    # Return the path under the actual mounted drive letter.
    # VolumeRoot is the letter Veeam assigned (e.g. "E:\"); strip it then
    # re-prefix with that same letter so console and JSON both report E:\...
    # rather than the previously hard-coded C:\.
    $relativePath = $MountedPath -replace [regex]::Escape($VolumeRoot), ''
    $relativePath = $relativePath.TrimStart('\\')
    $driveLetter  = $VolumeRoot.Substring(0, 2)   # e.g. "E:"
    return "$driveLetter\$relativePath"
}

function Export-ScanResults {
    param([object[]]$AllFindings)
    
    if (-not $AllFindings) {
        $AllFindings = @()
    }
    
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
    
    # Export to JSON
    $jsonOutput = @{
        ScanTimestamp = (Get-Date).ToString('o')
        JobId = $jobId
        TotalMatches = $AllFindings.Count
        UniqueFiles = $groupedResults.Count
        YaraVersion = (& $YaraPath --version 2>&1 | Select-Object -First 1)
        Findings = @($groupedResults)
    } | ConvertTo-Json -Depth 10
    
    # Specify UTF8 so non-ASCII characters in matched YARA strings are written
    # correctly on PS5.1, which defaults to the system ANSI code page otherwise.
    Set-Content -Path $jsonReport -Value $jsonOutput -Encoding UTF8
    Write-Log "JSON report saved: $jsonReport"
    
    return $groupedResults
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

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
    
    $allFindings = @()
    
    # Scan each mounted volume
    foreach ($volume in $volumes) {
        Write-Log "Processing volume: $($volume.DriveLetter) (VM: $($volume.VMName))"
        
        $scanTargets = Get-ScanTargets -VolumeRoot $volume.DriveLetter
        Write-Log "Scan targets: $($scanTargets.Count) path(s)"
        
        $findings = Invoke-YARAScan -ScanPaths $scanTargets -VolumeRoot $volume.DriveLetter -VMName $volume.VMName
        
        if ($findings) {
            Write-Log "Found $($findings.Count) matches in $($volume.DriveLetter)" -Level "WARNING"
            $allFindings += $findings
        } else {
            Write-Log "No threats detected in $($volume.DriveLetter)"
        }
    }
    
    # Display results
    Write-Log "=== SCAN SUMMARY ==="
    Write-Log "Total Volumes Scanned: $($volumes.Count)"
    Write-Log "Total Matches: $($allFindings.Count)"
    
    if ($allFindings.Count -gt 0) {
        Write-Log "ONION LINKS DETECTED - INFECTED FILES" -Level "WARNING"
        
        $results = Export-ScanResults -AllFindings $allFindings
        
        # Display detailed findings with onion links
        foreach ($result in $results) {
            Write-Log "VM: $($result.VMName)" -Level "WARNING"
            Write-Log "Windows Path: $($result.WindowsPath)" -Level "WARNING"
            Write-Log "  Matched Rules: $($result.MatchedRules)"
            
            if ($result.OnionLinks) {
                Write-Log "  Onion Links: $($result.OnionLinks)" -Level "WARNING"
            }
            
            if ($result.MatchedStrings -and $result.MatchedStrings -ne $result.OnionLinks) {
                Write-Log "  Other Matches: $($result.MatchedStrings)"
            }
        }
        
        Write-Log "ACTION REQUIRED: Review infected files before restoring!" -Level "WARNING"
        Write-Log "Full report: $jsonReport"
        
        # Exit with error code to fail Veeam job
        exit 1
        
    } else {
        Write-Log "SUCCESS: No onion links or malware detected - All volumes clean"
        Write-Log "Full report: $jsonReport"
        exit 0
    }
    
} catch {
    Write-Log "FATAL ERROR: $_" -Level "ERROR"
    Write-Log $_.ScriptStackTrace -Level "ERROR"
    exit 2
}
