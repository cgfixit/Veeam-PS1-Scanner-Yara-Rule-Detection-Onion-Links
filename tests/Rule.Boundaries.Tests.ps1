#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.7.1' }
BeforeAll {
    $script:Yara = (Get-Command yara, yara64, yara64.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $script:Yara) { throw 'Real YARA is required for boundary checks.' }
    $script:Rules = Join-Path (Split-Path $PSScriptRoot -Parent) 'yara-malware-detection.yara'
}
Describe 'Rule boundaries and context' {
    It 'finds ransom context in <Encoding> with uppercase hosts' -ForEach @(@{Encoding='utf-8'},@{Encoding='Unicode'}) {
        $file = Join-Path $TestDrive 'note.txt'
        $text = 'Files encrypted; decrypt after payment within 24 hours HTTP://ABCDEFGHIJKLMNOP.ONION/'
        [IO.File]::WriteAllText($file, $text, [Text.Encoding]::GetEncoding($Encoding))
        $hits = & $script:Yara -w $script:Rules $file
        $LASTEXITCODE | Should -Be 0
        $hits -join ' ' | Should -Match 'comprehensive_onion_detection'
    }
    It 'does not promote an ordinary endpoint into C2 evidence' {
        $file = Join-Path $TestDrive 'endpoint.json'
        Set-Content $file '{"endpoint":"http://abcdefghijklmnop.onion/"}'
        $hits = & $script:Yara -w $script:Rules $file
        $LASTEXITCODE | Should -Be 0
        $hits -join ' ' | Should -Match 'onion_links_simple'
        $hits -join ' ' | Should -Not -Match 'tor_c2_configuration'
    }
    It 'rejects a <Length>-character onion hostname' -ForEach @(@{Length=17},@{Length=55},@{Length=57}) {
        $file = Join-Path $TestDrive 'invalid.txt'
        Set-Content $file (('a' * $Length) + '.onion')
        $hits = & $script:Yara -w $script:Rules $file
        $LASTEXITCODE | Should -Be 0
        $hits | Should -BeNullOrEmpty
    }
    It 'does not exclude the word details as Tails' {
        $file = Join-Path $TestDrive 'details.txt'
        Set-Content $file 'Connection details http://abcdefghijklmnop.onion/'
        $hits = & $script:Yara -w $script:Rules $file
        $LASTEXITCODE | Should -Be 0
        $hits -join ' ' | Should -Match 'onion_links_simple'
    }
    It 'emits one payment onion string for one 56-character hostname' {
        $file = Join-Path $TestDrive 'payment.txt'
        Set-Content $file ('pay payment deadline ' + ('a' * 56) + '.onion')
        $hits = & $script:Yara -w -s -i ransomware_payment_portal $script:Rules $file
        $LASTEXITCODE | Should -Be 0
        @($hits | Where-Object { $_ -match ':\$onion:' }) | Should -HaveCount 1
    }
}
