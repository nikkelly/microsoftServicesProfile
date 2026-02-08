#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for the M365Connect module.

.DESCRIPTION
    Tests module import, function availability, aliases, and basic functionality.

.NOTES
    Run with: Invoke-Pester -Path .\Tests\M365Connect.Tests.ps1
#>

BeforeAll {
    # Import the module
    $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'M365Connect.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop

    # Helper to create test credentials without triggering PSScriptAnalyzer plaintext warnings
    function script:Get-TestCredential {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
        param([string]$User = 'user@test.com', [string]$Pass = 'TestPass123')
        $secPass = ConvertTo-SecureString $Pass -AsPlainText -Force
        return [System.Management.Automation.PSCredential]::new($User, $secPass)
    }
}

Describe 'Module Import' {
    It 'Should import without errors' {
        { Import-Module (Split-Path -Parent $PSScriptRoot) -Force } | Should -Not -Throw
    }

    It 'Should have the correct module version' {
        $module = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $module.Version | Should -Be '3.0.0'
    }
}

Describe 'Exported Functions' {
    BeforeAll {
        $script:expectedFunctions = @(
            'Connect-MSTeams',
            'Connect-MSExchange',
            'Connect-MSExchangeServer',
            'Connect-MSAzureAD',
            'Connect-MSGraph',
            'Connect-MSSharePoint',
            'Connect-MSSecurityCompliance',
            'Connect-MSIntune',
            'Connect-AllMSServices',
            'Disconnect-AllMSServices',
            'Add-MSAccount',
            'Remove-MSAccount',
            'Add-MSAppRegistration',
            'Remove-MSAppRegistration',
            'Add-MSMFA',
            'Remove-MSMFA',
            'Get-MSConnectionStatus',
            'Show-MSCommands'
        )
    }

    It "Should export function: <_>" -ForEach @(
        'Connect-MSTeams',
        'Connect-MSExchange',
        'Connect-MSExchangeServer',
        'Connect-MSAzureAD',
        'Connect-MSGraph',
        'Connect-MSSharePoint',
        'Connect-MSSecurityCompliance',
        'Connect-MSIntune',
        'Connect-AllMSServices',
        'Disconnect-AllMSServices',
        'Add-MSAccount',
        'Remove-MSAccount',
        'Add-MSAppRegistration',
        'Remove-MSAppRegistration',
        'Add-MSMFA',
        'Remove-MSMFA',
        'Get-MSConnectionStatus',
        'Show-MSCommands'
    ) {
        Get-Command -Name $_ -Module M365Connect -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe 'Exported Aliases' {
    It "Should have alias '<Alias>' pointing to '<Target>'" -ForEach @(
        @{ Alias = 'Teams'; Target = 'Connect-MSTeams' },
        @{ Alias = 'Exchange'; Target = 'Connect-MSExchange' },
        @{ Alias = 'ExchangeServer'; Target = 'Connect-MSExchangeServer' },
        @{ Alias = 'AzureAD'; Target = 'Connect-MSAzureAD' },
        @{ Alias = 'AzureADPreview'; Target = 'Connect-MSAzureAD' },
        @{ Alias = 'MSOnline'; Target = 'Connect-MSGraph' },
        @{ Alias = 'SharePoint'; Target = 'Connect-MSSharePoint' },
        @{ Alias = 'Security_Compliance'; Target = 'Connect-MSSecurityCompliance' },
        @{ Alias = 'Intune'; Target = 'Connect-MSIntune' },
        @{ Alias = 'connectAll'; Target = 'Connect-AllMSServices' },
        @{ Alias = 'Disconnect'; Target = 'Disconnect-AllMSServices' },
        @{ Alias = 'Add-Account'; Target = 'Add-MSAccount' },
        @{ Alias = 'Remove-Account'; Target = 'Remove-MSAccount' },
        @{ Alias = 'Add-MFA'; Target = 'Add-MSMFA' },
        @{ Alias = 'Remove-MFA'; Target = 'Remove-MSMFA' }
    ) {
        $aliasObj = Get-Alias -Name $Alias -ErrorAction SilentlyContinue
        $aliasObj | Should -Not -BeNullOrEmpty
        $aliasObj.ResolvedCommand.Name | Should -Be $Target
    }
}

Describe 'Get-MSConnectionStatus' {
    It 'Should return a PSCustomObject' {
        $status = Get-MSConnectionStatus
        $status | Should -BeOfType [PSCustomObject]
    }

    It 'Should have expected properties' {
        $status = Get-MSConnectionStatus
        $status.PSObject.Properties.Name | Should -Contain 'ConnectedServices'
        $status.PSObject.Properties.Name | Should -Contain 'AuthMethod'
        $status.PSObject.Properties.Name | Should -Contain 'PSVersion'
        $status.PSObject.Properties.Name | Should -Contain 'MFAEnabled'
    }

    It 'Should return additional properties with -Detailed' {
        $status = Get-MSConnectionStatus -Detailed
        $status.PSObject.Properties.Name | Should -Contain 'CredentialLoaded'
        $status.PSObject.Properties.Name | Should -Contain 'AppRegistrationConfigured'
    }
}

Describe 'Show-MSCommands' {
    It 'Should run without errors' {
        { Show-MSCommands -Quiet } | Should -Not -Throw
    }
}

Describe 'Module State' {
    It 'Should have initialized MSProfileState' {
        # Access via module scope - select the v3 module specifically
        $mod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $state = & $mod { $script:MSProfileState }
        $state | Should -Not -BeNullOrEmpty
        # ConnectedServices is initialized as empty ArrayList, so check it exists (not null)
        $state.ContainsKey('ConnectedServices') | Should -BeTrue
        $state.PSVersionInfo | Should -Not -BeNullOrEmpty
    }

    It 'Should have correct PS version info' {
        $mod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $state = & $mod { $script:MSProfileState }
        $state.PSVersionInfo.Major | Should -Be $PSVersionTable.PSVersion.Major
        $state.PSVersionInfo.IsCore | Should -Be ($PSVersionTable.PSEdition -eq 'Core')
    }
}

Describe 'PowerShell 7 Compatibility' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    It 'Should correctly identify PowerShell version capability' {
        $state = & $script:testMod { $script:MSProfileState }
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $state.PSVersionInfo.RequiresGraph | Should -BeTrue
            $state.PSVersionInfo.SupportsAzureAD | Should -BeFalse
        } else {
            $state.PSVersionInfo.RequiresGraph | Should -BeFalse
            $state.PSVersionInfo.SupportsAzureAD | Should -BeTrue
        }
    }
}

Describe 'Add-MSMFA and Remove-MSMFA' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    AfterEach {
        # Clean up by removing MFA setting
        & $script:testMod { $script:MSProfileState.MFAEnabled = $false }
    }

    It 'Add-MSMFA should enable MFA in module state' {
        Add-MSMFA
        $state = & $script:testMod { $script:MSProfileState }
        $state.MFAEnabled | Should -BeTrue
    }

    It 'Remove-MSMFA should disable MFA in module state' {
        Add-MSMFA
        Remove-MSMFA
        $state = & $script:testMod { $script:MSProfileState }
        $state.MFAEnabled | Should -BeFalse
    }
}

Describe 'Parameter Validation' {
    It 'Connect-MSTeams should accept valid AuthMethod values' {
        $cmd = Get-Command Connect-MSTeams
        $param = $cmd.Parameters['AuthMethod']
        $param.Attributes.ValidValues | Should -Contain 'Interactive'
        $param.Attributes.ValidValues | Should -Contain 'Credential'
        $param.Attributes.ValidValues | Should -Contain 'ServicePrincipal'
    }

    It 'Add-MSAppRegistration should require AppId parameter' {
        $cmd = Get-Command Add-MSAppRegistration
        $param = $cmd.Parameters['AppId']
        $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.Mandatory } | Should -Contain $true
    }

    It 'Add-MSAppRegistration should require TenantId parameter' {
        $cmd = Get-Command Add-MSAppRegistration
        $param = $cmd.Parameters['TenantId']
        $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
            ForEach-Object { $_.Mandatory } | Should -Contain $true
    }
}

Describe 'Connect-MSTeams (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    BeforeEach {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }

    It 'Should call Connect-MicrosoftTeams with credential when AuthMethod is Credential' {
        $testCred = Get-TestCredential

        InModuleScope M365Connect -Parameters @{ testCred = $testCred } {
            Mock Connect-MicrosoftTeams { } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            $script:MSProfileState.Credential = $testCred
            Connect-MSTeams -AuthMethod Credential -Credential $testCred

            Should -Invoke Connect-MicrosoftTeams -Times 1 -ModuleName M365Connect -ParameterFilter {
                $Credential -eq $testCred
            }
        }
    }

    It 'Should skip connection when already connected' {
        & $script:testMod {
            [void]$script:MSProfileState.ConnectedServices.Add('Teams')
        }

        InModuleScope M365Connect {
            Mock Connect-MicrosoftTeams { } -ModuleName M365Connect

            Connect-MSTeams

            Should -Invoke Connect-MicrosoftTeams -Times 0 -ModuleName M365Connect
        }
    }

    It 'Should add Teams to connected services on success' {
        InModuleScope M365Connect {
            Mock Connect-MicrosoftTeams { } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            $script:MSProfileState.MFAEnabled = $true
            Connect-MSTeams -AuthMethod Interactive

            $script:MSProfileState.ConnectedServices | Should -Contain 'Teams'
        }
    }
}

Describe 'Connect-MSGraph (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    BeforeEach {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }

    It 'Should call Connect-MgGraph with scopes for interactive auth' {
        InModuleScope M365Connect {
            Mock Connect-MgGraph { } -ModuleName M365Connect
            Mock Get-MgContext { $null } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            Connect-MSGraph -AuthMethod Interactive

            Should -Invoke Connect-MgGraph -Times 1 -ModuleName M365Connect
        }
    }

    It 'Should call Connect-MgGraph with custom scopes' {
        InModuleScope M365Connect {
            Mock Connect-MgGraph { } -ModuleName M365Connect
            Mock Get-MgContext { $null } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            Connect-MSGraph -Scopes 'Mail.Read'

            Should -Invoke Connect-MgGraph -Times 1 -ModuleName M365Connect -ParameterFilter {
                $Scopes -contains 'Mail.Read'
            }
        }
    }

    It 'Should call Connect-MgGraph with certificate for service principal' {
        InModuleScope M365Connect {
            Mock Connect-MgGraph { } -ModuleName M365Connect
            Mock Get-MgContext { $null } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            $script:MSProfileState.AppRegistration = @{
                AppId                 = 'test-app-id'
                TenantId              = 'test-tenant-id'
                CertificateThumbprint = 'AABB1122'
                ClientSecret          = $null
            }

            Connect-MSGraph -AuthMethod ServicePrincipal

            Should -Invoke Connect-MgGraph -Times 1 -ModuleName M365Connect -ParameterFilter {
                $ClientId -eq 'test-app-id' -and $TenantId -eq 'test-tenant-id' -and $CertificateThumbprint -eq 'AABB1122'
            }
        }
    }

    It 'Should add Graph to connected services on success' {
        InModuleScope M365Connect {
            Mock Connect-MgGraph { } -ModuleName M365Connect
            Mock Get-MgContext { $null } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            Connect-MSGraph -AuthMethod Interactive

            $script:MSProfileState.ConnectedServices | Should -Contain 'Graph'
        }
    }
}

Describe 'Connect-MSExchange (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    BeforeEach {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }

    It 'Should call Connect-ExchangeOnline with UPN for credential mode' {
        $testCred = Get-TestCredential -User 'admin@contoso.com'

        InModuleScope M365Connect -Parameters @{ testCred = $testCred } {
            Mock Connect-ExchangeOnline { } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            Connect-MSExchange -AuthMethod Credential -Credential $testCred

            Should -Invoke Connect-ExchangeOnline -Times 1 -ModuleName M365Connect -ParameterFilter {
                $UserPrincipalName -eq 'admin@contoso.com'
            }
        }
    }

    It 'Should warn and not call Connect-ExchangeOnline when no credential available' {
        InModuleScope M365Connect {
            Mock Connect-ExchangeOnline { } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            $script:MSProfileState.Credential = $null
            Connect-MSExchange -AuthMethod Credential 3>$null

            Should -Invoke Connect-ExchangeOnline -Times 0 -ModuleName M365Connect
        }
    }
}

Describe 'Connect-MSAzureAD PS7+ redirect (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    BeforeEach {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }

    It 'Should redirect to Connect-MSGraph on PS7+' {
        $isPS7 = $PSVersionTable.PSVersion.Major -ge 7
        if (-not $isPS7) {
            Set-ItResult -Skipped -Because 'Test only runs on PS7+'
            return
        }

        InModuleScope M365Connect {
            Mock Connect-MgGraph { } -ModuleName M365Connect
            Mock Get-MgContext { $null } -ModuleName M365Connect
            Mock Test-ModuleAvailable { $true } -ModuleName M365Connect

            Connect-MSAzureAD -AuthMethod Interactive 3>$null

            Should -Invoke Connect-MgGraph -Times 1 -ModuleName M365Connect
        }
    }
}

Describe 'Connect-AllMSServices (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    BeforeEach {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }

    It 'Should skip services in SkipServices list' {
        InModuleScope M365Connect {
            Mock Connect-MSGraph { } -ModuleName M365Connect
            Mock Connect-MSExchange { } -ModuleName M365Connect
            Mock Connect-MSTeams { } -ModuleName M365Connect
            Mock Connect-MSSharePoint { } -ModuleName M365Connect
            Mock Connect-MSSecurityCompliance { } -ModuleName M365Connect
            Mock Connect-MSIntune { } -ModuleName M365Connect
            Mock Connect-MSAzureAD { } -ModuleName M365Connect

            Connect-AllMSServices -SkipServices 'Exchange', 'SharePoint'

            Should -Invoke Connect-MSExchange -Times 0 -ModuleName M365Connect
            Should -Invoke Connect-MSSharePoint -Times 0 -ModuleName M365Connect
        }
    }
}

Describe 'Disconnect-AllMSServices (mocked)' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    It 'Should not throw when no services connected' {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }

        { Disconnect-AllMSServices } | Should -Not -Throw
    }

    It 'Should clear connected services list after disconnect' {
        & $script:testMod {
            [void]$script:MSProfileState.ConnectedServices.Add('Teams')
            [void]$script:MSProfileState.ConnectedServices.Add('Exchange')
        }

        InModuleScope M365Connect {
            Mock Disconnect-MicrosoftTeams { } -ModuleName M365Connect
            Mock Disconnect-ExchangeOnline { } -ModuleName M365Connect
            Mock Reset-MSPrompt { } -ModuleName M365Connect

            Disconnect-AllMSServices

            $script:MSProfileState.ConnectedServices.Count | Should -Be 0
        }
    }
}

Describe 'Test-AlreadyConnected' {
    BeforeAll {
        $script:testMod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
    }

    It 'Should return $false when no services are connected' {
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }

        $result = InModuleScope M365Connect {
            Test-AlreadyConnected -ServiceName 'Teams'
        }
        $result | Should -BeFalse
    }

    It 'Should return $true when service is already connected' {
        & $script:testMod {
            [void]$script:MSProfileState.ConnectedServices.Add('Teams')
        }

        $result = InModuleScope M365Connect {
            Test-AlreadyConnected -ServiceName 'Teams'
        }
        $result | Should -BeTrue

        # Clean up
        & $script:testMod { $script:MSProfileState.ConnectedServices.Clear() }
    }
}

Describe 'Export-MSAppRegistration' {
    It 'Should exist as a private function' {
        $mod = Get-Module -Name M365Connect | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $result = & $mod { Get-Command Export-MSAppRegistration -ErrorAction SilentlyContinue }
        $result | Should -Not -BeNullOrEmpty
    }
}

Describe 'ShouldProcess support' {
    It 'Add-MSMFA should support -WhatIf' {
        $cmd = Get-Command Add-MSMFA
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Add-MSAppRegistration should support -WhatIf' {
        $cmd = Get-Command Add-MSAppRegistration
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Remove-MSMFA should support -WhatIf' {
        $cmd = Get-Command Remove-MSMFA
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Remove-MSAccount should support -WhatIf' {
        $cmd = Get-Command Remove-MSAccount
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Remove-MSAppRegistration should support -WhatIf' {
        $cmd = Get-Command Remove-MSAppRegistration
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }
}

AfterAll {
    # Clean up - remove the module
    Remove-Module M365Connect -Force -ErrorAction SilentlyContinue
}
