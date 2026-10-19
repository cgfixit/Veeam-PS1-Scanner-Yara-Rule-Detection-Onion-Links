#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.7.1' }
BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Veeam-YARA-SecureRestore.ps1')
    . (Join-Path $PSScriptRoot 'Invoke-MockAcceptance.ps1')
}
Describe 'Coverage and retained findings' {
    It 'preserves findings across a later failure in <Mode>' -ForEach @(
        @{Mode='Sequential'}, @{Mode='Job'}, @{Mode='ThreadJob'}
    ) {
        $r = Invoke-ScannerFixture -Scenario PartialFailure -Mode $Mode -WorkRoot $TestDrive
        $r.ActualExit | Should -Be 2 -Because $r.Output
        $r.Report.Status | Should -Be Error
        $r.Report.TotalMatches | Should -BeGreaterThan 0
        $r.Report.Coverage | Should -HaveCount 2
        @($r.Report.Coverage | Where-Object Status -eq Completed) | Should -HaveCount 1
        $r.Report.Errors -join ' ' | Should -Match 'link/reparse'
    }
    It 'does not follow descendant directory links' {
        $root = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'root')
        $outside = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'outside')
        Set-Content (Join-Path $outside.FullName 'secret.txt') 'outside'
        New-Item -ItemType SymbolicLink -Path (Join-Path $root.FullName 'escape') -Target $outside.FullName -ErrorAction Stop | Out-Null
        $inventory = Get-ScanInventory -Root $root.FullName
        $inventory.Files | Should -HaveCount 0
        $inventory.Errors -join ' ' | Should -Match 'link/reparse'
    }
    It 'skips and reports deeper links without failing the scan' {
        # Every Windows volume carries junctions such as "Users\All Users".
        $root = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'vol')
        $users = New-Item -ItemType Directory -Path (Join-Path $root.FullName 'Users')
        $data = New-Item -ItemType Directory -Path (Join-Path $root.FullName 'ProgramData')
        Set-Content (Join-Path $data.FullName 'kept.txt') 'inside'
        $outside = New-Item -ItemType Directory -Path (Join-Path $TestDrive 'elsewhere')
        Set-Content (Join-Path $outside.FullName 'secret.txt') 'outside'
        New-Item -ItemType SymbolicLink -Path (Join-Path $users.FullName 'All Users') -Target $outside.FullName -ErrorAction Stop | Out-Null
        $inventory = Get-ScanInventory -Root $root.FullName
        $inventory.Errors | Should -HaveCount 0
        $inventory.Files | Should -HaveCount 1
        $inventory.Files[0] | Should -Match 'kept\.txt$'
        $inventory.Skipped | Should -HaveCount 1
        $inventory.Skipped[0] | Should -Match 'All Users'
    }
    It 'traverses a volume mount point directly under a mount parent' {
        $parent = 'M:\VeeamFLR\vm'
        $volume = 'M:\VeeamFLR\vm\Volume1'
        $junction = 'M:\VeeamFLR\vm\Volume1\Documents and Settings'
        $file = 'M:\VeeamFLR\vm\Volume1\note.txt'
        $dir = [IO.FileAttributes]::Directory
        $link = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
        Mock Get-Item -ParameterFilter { $LiteralPath -eq $parent } { [pscustomobject]@{ FullName = $parent; PSIsContainer = $true; Attributes = $dir } }
        Mock Get-Item -ParameterFilter { $LiteralPath -eq $volume } { [pscustomobject]@{ FullName = $volume; PSIsContainer = $true; Attributes = $link; Target = 'Volume{0b6b1a52-7f3c-4a77-9d1e-2c41f1d3a9b0}\' } }
        Mock Get-Item -ParameterFilter { $LiteralPath -eq $junction } { [pscustomobject]@{ FullName = $junction; PSIsContainer = $true; Attributes = $link; Target = 'C:\Users' } }
        Mock Get-Item -ParameterFilter { $LiteralPath -eq $file } { [pscustomobject]@{ FullName = $file; PSIsContainer = $false; Attributes = [IO.FileAttributes]::Archive; Length = 10 } }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq $parent } { [pscustomobject]@{ FullName = $volume } }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -eq $volume } { [pscustomobject]@{ FullName = $junction }; [pscustomobject]@{ FullName = $file } }
        $inventory = Get-ScanInventory -Root $parent
        $inventory.Errors | Should -HaveCount 0
        $inventory.Files | Should -Be @($file)
        $inventory.Skipped | Should -Be @("link: $junction")
    }
    It 'records enumeration failure instead of an empty success' {
        Mock Get-ChildItem { throw 'access denied by fixture' }
        $r = Get-ScanInventory -Root $TestDrive
        $r.Errors -join ' ' | Should -Match 'access denied'
        $r.Files | Should -HaveCount 0
    }
}
