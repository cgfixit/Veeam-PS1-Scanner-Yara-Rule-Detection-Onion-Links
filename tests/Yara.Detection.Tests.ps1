#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Yara.Detection.Tests.ps1
    ------------------------
    Fixture-based detection tests that compile the real yara-malware-detection.yara
    rule file with the actual YARA engine and assert true positives (malicious
    fixtures match the intended rules) and true negatives (benign fixtures match
    nothing — exercising the false-positive exclusion strings).

    The final block is an end-to-end integration test: it runs YARA through the
    scanner's own Invoke-ProcessWithTimeout and feeds the output to the scanner's
    Parse-YARAOutput, proving the binary + parser cooperate to extract .onion IOCs.

    Requires the `yara` (or `yara64`) CLI on PATH. If absent, the whole file is
    skipped with a clear message rather than failing.

    Run:  pwsh -NoProfile -Command "Invoke-Pester -Path ./tests/Yara.Detection.Tests.ps1"
#>

BeforeDiscovery {
    $yaraCmd = Get-Command yara, yara64, yara64.exe -ErrorAction SilentlyContinue |
               Select-Object -First 1
    if (-not $yaraCmd) {
        foreach ($p in 'C:\Program Files\YARA\yara64.exe','C:\Program Files\YARA\yara.exe') {
            if (Test-Path $p) { $yaraCmd = Get-Command $p; break }
        }
    }
    $script:YaraAvailable = [bool]$yaraCmd
    $script:YaraExe = if ($yaraCmd) { $yaraCmd.Source } else { $null }
}

BeforeAll {
    $env:VEEAM_YARA_NOEXEC = '1'
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'Veeam-YARA-SecureRestore.ps1')

    $script:RuleFile = Join-Path (Split-Path -Parent $PSScriptRoot) 'yara-malware-detection.yara'
    $script:MalDir   = Join-Path $PSScriptRoot 'fixtures/malicious'
    $script:BenDir   = Join-Path $PSScriptRoot 'fixtures/benign'
    $script:YaraExe  = $script:YaraExe  # carried from BeforeDiscovery scope

    if (-not $script:YaraExe) {
        $yaraCmd = Get-Command yara, yara64, yara64.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($yaraCmd) { $script:YaraExe = $yaraCmd.Source }
    }

    function Get-YaraRuleHits {
        param([string]$RuleFile, [string]$Target)
        $out = & $script:YaraExe -w -r $RuleFile $Target 2>$null
        $hits = @()
        foreach ($line in $out) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $hits += (($line -split '\s+', 2)[0])
        }
        return ,@($hits | Sort-Object -Unique)
    }
}

Describe 'YARA rule file' -Skip:(-not $script:YaraAvailable) {

    It 'compiles cleanly (no syntax errors)' {
        $empty = Join-Path $TestDrive 'empty.bin'
        Set-Content -Path $empty -Value '' -NoNewline
        & $script:YaraExe -w $script:RuleFile $empty 2>$null | Out-Null
        # YARA exit codes: 0 = match, 1 = no match, >1 = error. An empty file
        # should yield "no match" (1); anything >1 means a rule syntax problem.
        $LASTEXITCODE | Should -BeLessOrEqual 1
    }
}

Describe 'True positives (malicious fixtures)' -Skip:(-not $script:YaraAvailable) {

    It '<File> matches <Rule>' -ForEach @(
        @{ File = 'ransom_note_onion.txt';     Rule = 'comprehensive_onion_detection' }
        @{ File = 'onion_only_reference.txt';  Rule = 'onion_links_simple' }
        @{ File = 'payment_portal.html';       Rule = 'ransomware_payment_portal' }
        @{ File = 'payment_portal.html';       Rule = 'comprehensive_onion_detection' }
        @{ File = 'tor_c2_config.json';        Rule = 'tor_c2_configuration' }
        @{ File = 'i2p_beacon.txt';            Rule = 'i2p_malware_indicator' }
        @{ File = 'freenet_note.txt';          Rule = 'freenet_darknet_indicator' }
    ) {
        $hits = Get-YaraRuleHits -RuleFile $script:RuleFile -Target (Join-Path $script:MalDir $File)
        $hits | Should -Contain $Rule -Because "$File should trip $Rule"
    }

    It 'onion_only_reference.txt trips ONLY the broad onion rule' {
        $hits = Get-YaraRuleHits -RuleFile $script:RuleFile -Target (Join-Path $script:MalDir 'onion_only_reference.txt')
        $hits | Should -Be @('onion_links_simple')
    }

    It 'every malicious fixture produces at least one match' {
        foreach ($f in Get-ChildItem $script:MalDir -File) {
            $hits = Get-YaraRuleHits -RuleFile $script:RuleFile -Target $f.FullName
            $hits.Count | Should -BeGreaterThan 0 -Because "$($f.Name) is a known-bad sample"
        }
    }
}

Describe 'True negatives (benign fixtures exercise FP exclusions)' -Skip:(-not $script:YaraAvailable) {

    It '<File> is clean (no rule fires)' -ForEach @(
        @{ File = 'tor_browser_doc.txt'  }
        @{ File = 'privacy_guide.md'     }
        @{ File = 'clean_app_config.json'}
        @{ File = 'i2pd_readme.txt'      }
    ) {
        $hits = Get-YaraRuleHits -RuleFile $script:RuleFile -Target (Join-Path $script:BenDir $File)
        $hits | Should -BeNullOrEmpty -Because "$File is benign and must not match"
    }

    It 'a ransom note that name-drops "Tor Browser" is still excluded from onion_links_simple' {
        # ransom_note_onion.txt mentions "Tor Browser", which is an FP-exclusion
        # string for onion_links_simple — so the broad rule must NOT fire even
        # though the context rule (comprehensive) does.
        $hits = Get-YaraRuleHits -RuleFile $script:RuleFile -Target (Join-Path $script:MalDir 'ransom_note_onion.txt')
        $hits | Should -Not -Contain 'onion_links_simple'
        $hits | Should -Contain 'comprehensive_onion_detection'
    }
}

Describe 'End-to-end: scanner process runner + parser extract .onion IOCs' -Skip:(-not $script:YaraAvailable) {

    It 'Invoke-ProcessWithTimeout + Parse-YARAOutput surface the onion link from a fixture' {
        $target = Join-Path $script:MalDir 'payment_portal.html'
        $res = Invoke-ProcessWithTimeout -FilePath $script:YaraExe `
                -Arguments @('-r','-s','-m','-w', $script:RuleFile, $target) -TimeoutSeconds 60
        $res.TimedOut | Should -BeFalse
        $res.ExitCode | Should -Be 0   # 0 = match found

        $findings = Parse-YARAOutput -Output $res.Output -VolumeRoot $script:MalDir -VMName 'FIXTURE-VM'
        $findings.Count | Should -BeGreaterThan 0
        ($findings.OnionLinks -join ' ') | Should -Match '\.onion'
        $findings.Rule | Should -Contain 'comprehensive_onion_detection'
    }
}
