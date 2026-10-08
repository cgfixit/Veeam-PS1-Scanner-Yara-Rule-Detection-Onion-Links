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
    It 'records enumeration failure instead of an empty success' {
        Mock Get-ChildItem { throw 'access denied by fixture' }
        $r = Get-ScanInventory -Root $TestDrive
        $r.Errors -join ' ' | Should -Match 'access denied'
        $r.Files | Should -HaveCount 0
    }
}
