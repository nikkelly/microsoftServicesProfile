function Connect-MSTeams {
    <#
    .SYNOPSIS
        Connects to Microsoft Teams.

    .DESCRIPTION
        Establishes a connection to Microsoft Teams using the MicrosoftTeams module.
        Supports interactive, credential-based, and service principal authentication.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.
        Defaults to the module's configured authentication method.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER TenantId
        The Azure AD tenant ID for service principal authentication.

    .PARAMETER AppId
        The application (client) ID for service principal authentication.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for service principal authentication.

    .EXAMPLE
        Connect-MSTeams

    .EXAMPLE
        Connect-MSTeams -AuthMethod ServicePrincipal -TenantId "contoso.onmicrosoft.com" -AppId "12345" -CertificateThumbprint "ABC123"

    .LINK
        https://github.com/nikkelly/M365Connect
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Teams is a proper noun (Microsoft Teams)')]
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [string]$TenantId,

        [string]$AppId,

        [string]$CertificateThumbprint
    )

    $serviceName = 'Teams'
    $moduleName = 'MicrosoftTeams'

    try {
        # Check if already connected
        if (Test-AlreadyConnected -ServiceName $serviceName) {
            return
        }

        # Check if module is available
        if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
            return
        }

        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan

        switch ($AuthMethod) {
            'ServicePrincipal' {
                $tenantIdValue = if ($TenantId) { $TenantId } else { $script:MSProfileState.AppRegistration.TenantId }
                $appIdValue = if ($AppId) { $AppId } else { $script:MSProfileState.AppRegistration.AppId }
                $thumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $script:MSProfileState.AppRegistration.CertificateThumbprint }

                if (-not $tenantIdValue -or -not $appIdValue -or -not $thumbprint) {
                    Write-Warning "Service principal authentication requires TenantId, AppId, and CertificateThumbprint"
                    Write-Warning "Use Add-MSAppRegistration to configure these settings"
                    return
                }

                Connect-MicrosoftTeams -TenantId $tenantIdValue -ApplicationId $appIdValue -CertificateThumbprint $thumbprint -ErrorAction Stop
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                Connect-MicrosoftTeams -Credential $cred -ErrorAction Stop
            }
            default {
                # Interactive
                if ($script:MSProfileState.MFAEnabled) {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    Connect-MicrosoftTeams -ErrorAction Stop
                } elseif ($script:MSProfileState.Credential) {
                    Connect-MicrosoftTeams -Credential $script:MSProfileState.Credential -ErrorAction Stop
                } else {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    Connect-MicrosoftTeams -ErrorAction Stop
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to $serviceName"

        if ($_.Exception.Message -match "AADSTS50076") {
            Write-Warning "`tMFA error detected"
            Write-ColorOutput -Text "`tTry ", "Add-MSMFA", " and re-run ", "Connect-MSTeams" -Color Yellow, Green, Yellow, Green
            return
        }

        Write-Warning $_.Exception.Message
    }
}
