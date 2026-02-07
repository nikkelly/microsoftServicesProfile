function Connect-MSGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph.

    .DESCRIPTION
        Establishes a connection to Microsoft Graph using the Microsoft.Graph module.
        This is the recommended replacement for AzureAD and MSOnline modules,
        and is required for PowerShell 7+.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.

    .PARAMETER TenantId
        The Azure AD tenant ID.

    .PARAMETER AppId
        The application (client) ID for service principal authentication.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for service principal authentication.

    .PARAMETER ClientSecret
        The client secret for service principal authentication.

    .PARAMETER Scopes
        The permission scopes to request. Defaults to common user and group read scopes.

    .EXAMPLE
        Connect-MSGraph

    .EXAMPLE
        Connect-MSGraph -AuthMethod ServicePrincipal -TenantId "tenant-id" -AppId "app-id" -CertificateThumbprint "thumbprint"

    .EXAMPLE
        Connect-MSGraph -Scopes "User.Read.All", "Group.ReadWrite.All"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [string]$TenantId,

        [string]$AppId,

        [string]$CertificateThumbprint,

        [SecureString]$ClientSecret,

        [string[]]$Scopes = @('User.Read.All', 'Group.Read.All', 'Directory.Read.All')
    )

    $serviceName = 'Graph'
    $moduleName = 'Microsoft.Graph.Authentication'

    try {
        # Check if already connected
        if (Test-AlreadyConnected -ServiceName $serviceName) {
            return
        }

        # Check if module is available
        if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
            return
        }

        Write-Host "`t Connecting to Microsoft Graph" -ForegroundColor Cyan

        switch ($AuthMethod) {
            'ServicePrincipal' {
                $tenantIdValue = if ($TenantId) { $TenantId } else { $script:MSProfileState.AppRegistration.TenantId }
                $appIdValue = if ($AppId) { $AppId } else { $script:MSProfileState.AppRegistration.AppId }
                $thumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $script:MSProfileState.AppRegistration.CertificateThumbprint }
                $secret = if ($ClientSecret) { $ClientSecret } else { $script:MSProfileState.AppRegistration.ClientSecret }

                if (-not $tenantIdValue -or -not $appIdValue) {
                    Write-Warning "Service principal authentication requires TenantId and AppId"
                    Write-Warning "Use Add-MSAppRegistration to configure these settings"
                    return
                }

                if ($thumbprint) {
                    # Certificate-based authentication
                    Connect-MgGraph -ClientId $appIdValue -TenantId $tenantIdValue -CertificateThumbprint $thumbprint -NoWelcome -ErrorAction Stop
                } elseif ($secret) {
                    # Client secret authentication
                    $credential = New-Object System.Management.Automation.PSCredential($appIdValue, $secret)
                    Connect-MgGraph -ClientSecretCredential $credential -TenantId $tenantIdValue -NoWelcome -ErrorAction Stop
                } else {
                    Write-Warning "Service principal authentication requires either CertificateThumbprint or ClientSecret"
                    return
                }
            }
            'Credential' {
                # Microsoft Graph doesn't support direct credential auth like legacy modules
                # Use delegated permissions with interactive auth
                Write-Host "`tNote: Microsoft Graph uses interactive auth for delegated permissions" -ForegroundColor Yellow
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
            }
            default {
                # Interactive authentication with delegated permissions
                Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

        # Show connected context
        $context = Get-MgContext
        if ($context) {
            Write-Host "`tConnected as: $($context.Account)" -ForegroundColor Gray
            Write-Host "`tTenant: $($context.TenantId)" -ForegroundColor Gray
        }

    } catch {
        Write-Warning "`tUnable to connect to Microsoft Graph"
        Write-Warning $_.Exception.Message

        if ($_.Exception.Message -match "AADSTS700016") {
            Write-Warning "`tApp registration not found in tenant. Verify the AppId and TenantId."
        }
    }
}
