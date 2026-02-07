#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for the microsoftServicesProfile module.

.DESCRIPTION
    Tests module import, function availability, aliases, and basic functionality.

.NOTES
    Run with: Invoke-Pester -Path .\Tests\microsoftServicesProfile.Tests.ps1
#>

BeforeAll {
    # Import the module
    $modulePath = Split-Path -Parent $PSScriptRoot
    Import-Module $modulePath -Force -ErrorAction Stop
}

Describe 'Module Import' {
    It 'Should import without errors' {
        { Import-Module (Split-Path -Parent $PSScriptRoot) -Force } | Should -Not -Throw
    }

    It 'Should have the correct module version' {
        $module = Get-Module -Name microsoftServicesProfile | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
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
        Get-Command -Name $_ -Module microsoftServicesProfile -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
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
        $mod = Get-Module -Name microsoftServicesProfile | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $state = & $mod { $script:MSProfileState }
        $state | Should -Not -BeNullOrEmpty
        # ConnectedServices is initialized as empty ArrayList, so check it exists (not null)
        $state.ContainsKey('ConnectedServices') | Should -BeTrue
        $state.PSVersionInfo | Should -Not -BeNullOrEmpty
    }

    It 'Should have correct PS version info' {
        $mod = Get-Module -Name microsoftServicesProfile | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
        $state = & $mod { $script:MSProfileState }
        $state.PSVersionInfo.Major | Should -Be $PSVersionTable.PSVersion.Major
        $state.PSVersionInfo.IsCore | Should -Be ($PSVersionTable.PSEdition -eq 'Core')
    }
}

Describe 'PowerShell 7 Compatibility' {
    BeforeAll {
        $script:testMod = Get-Module -Name microsoftServicesProfile | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
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
        $script:testMod = Get-Module -Name microsoftServicesProfile | Where-Object { $_.Version -eq '3.0.0' } | Select-Object -First 1
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

AfterAll {
    # Clean up - remove the module
    Remove-Module microsoftServicesProfile -Force -ErrorAction SilentlyContinue
}
