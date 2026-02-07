function Initialize-ModuleState {
    <#
    .SYNOPSIS
        Initializes the module state on load.

    .DESCRIPTION
        Imports saved credentials, MFA status, and app registration settings from
        environment variables. Called automatically when the module loads.

    .EXAMPLE
        Initialize-ModuleState
    #>
    [CmdletBinding()]
    param()

    # Import MFA status
    $script:MSProfileState.MFAEnabled = Test-Path env:microsoftConnectionMFA

    # Import credentials
    Import-MSCredential | Out-Null

    # Import app registration settings
    Import-MSAppRegistration | Out-Null

    # Import auth method preference
    if (Test-Path env:microsoftConnectionAuthMethod) {
        $authMethod = $env:microsoftConnectionAuthMethod
        if ($authMethod -in @('Interactive', 'Credential', 'ServicePrincipal')) {
            $script:MSProfileState.AuthMethod = $authMethod
        }
    }
}

function Import-MSAppRegistration {
    <#
    .SYNOPSIS
        Loads app registration settings from environment variables.
    #>
    [CmdletBinding()]
    param()

    if (Test-Path env:microsoftConnectionAppId) {
        $script:MSProfileState.AppRegistration.AppId = $env:microsoftConnectionAppId
    }

    if (Test-Path env:microsoftConnectionTenantId) {
        $script:MSProfileState.AppRegistration.TenantId = $env:microsoftConnectionTenantId
    }

    if (Test-Path env:microsoftConnectionCertThumbprint) {
        $script:MSProfileState.AppRegistration.CertificateThumbprint = $env:microsoftConnectionCertThumbprint
    }

    if (Test-Path env:microsoftConnectionClientSecret) {
        try {
            $script:MSProfileState.AppRegistration.ClientSecret = ConvertTo-SecureString $env:microsoftConnectionClientSecret -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to import client secret: $_"
        }
    }

    # If app registration is configured, set auth method
    if ($script:MSProfileState.AppRegistration.AppId -and $script:MSProfileState.AppRegistration.TenantId) {
        if (-not (Test-Path env:microsoftConnectionAuthMethod)) {
            $script:MSProfileState.AuthMethod = 'ServicePrincipal'
        }
    }
}
