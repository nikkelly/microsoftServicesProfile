function Connect-MSAzureAD {
    <#
    .SYNOPSIS
        Connects to Azure Active Directory.

    .DESCRIPTION
        Establishes a connection to Azure AD using the AzureAD module (PS 5.1) or
        redirects to Microsoft Graph (PS 7+).

        Note: The AzureAD module is deprecated and will be retired. Consider using
        Connect-MSGraph for new implementations.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER TenantId
        The Azure AD tenant ID.

    .PARAMETER AccountId
        The user account ID (UPN) for interactive authentication.

    .EXAMPLE
        Connect-MSAzureAD

    .EXAMPLE
        Connect-MSAzureAD -AuthMethod Credential -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [string]$TenantId,

        [string]$AccountId
    )

    $serviceName = 'AzureAD'
    $moduleName = 'AzureAD'
    $versionInfo = $script:MSProfileState.PSVersionInfo

    # Check if already connected
    if (Test-AlreadyConnected -ServiceName $serviceName) {
        return
    }

    # PowerShell 7+ - redirect to Microsoft Graph
    if ($versionInfo.RequiresGraph) {
        Write-Warning "AzureAD module is not supported in PowerShell 7+."
        Write-Host "`tRedirecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MSGraph @PSBoundParameters
        return
    }

    try {
        # Check if module is available
        if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
            return
        }

        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan

        switch ($AuthMethod) {
            'ServicePrincipal' {
                Write-Warning "Service principal authentication has limited support with AzureAD module."
                Write-Warning "Consider using Connect-MSGraph for service principal authentication."

                $tenantIdValue = if ($TenantId) { $TenantId } else { $script:MSProfileState.AppRegistration.TenantId }
                if ($tenantIdValue) {
                    AzureAD\Connect-AzureAD -TenantId $tenantIdValue -ErrorAction Stop
                } else {
                    Write-Warning "TenantId is required for service principal authentication"
                    return
                }
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                AzureAD\Connect-AzureAD -Credential $cred -ErrorAction Stop
            }
            default {
                # Interactive
                if ($script:MSProfileState.MFAEnabled) {
                    $account = if ($AccountId) { $AccountId } else { $script:MSProfileState.MicrosoftUser }
                    if ($account) {
                        AzureAD\Connect-AzureAD -AccountId $account -ErrorAction Stop
                    } else {
                        Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                        AzureAD\Connect-AzureAD -ErrorAction Stop
                    }
                } elseif ($script:MSProfileState.Credential) {
                    AzureAD\Connect-AzureAD -Credential $script:MSProfileState.Credential -ErrorAction Stop
                } else {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    AzureAD\Connect-AzureAD -ErrorAction Stop
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to Azure AD"
        Write-Warning $Error[0].Exception.Message
        Write-Warning "Ensure that MFA is configured correctly if required."
    }
}
