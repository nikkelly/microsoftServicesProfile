function Connect-MSIntune {
    <#
    .SYNOPSIS
        Connects to Microsoft Intune.

    .DESCRIPTION
        Establishes a connection to Microsoft Intune. In PowerShell 5.1, uses the
        Microsoft.Graph.Intune module. In PowerShell 7+, uses Microsoft Graph.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER AdminConsent
        If specified, connects with admin consent for the application.

    .EXAMPLE
        Connect-MSIntune

    .EXAMPLE
        Connect-MSIntune -AdminConsent
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [switch]$AdminConsent
    )

    $serviceName = 'Intune'
    $versionInfo = $script:MSProfileState.PSVersionInfo

    try {
        # Check if already connected
        if (Test-AlreadyConnected -ServiceName $serviceName) {
            return
        }

        # Check for MSOnline conflict
        if ($script:MSProfileState.ConnectedServices -contains 'MSOnline') {
            Write-ColorOutput -Text "`t*************" -Color Yellow
            Write-Host "`tImporting the MSOnline cmdlets before importing this Intune module will cause errors." -ForegroundColor $script:MSProfileState.ForegroundColor
            Write-Host "`tPlease use the AzureAD module instead, as the MSOnline module is deprecated." -ForegroundColor $script:MSProfileState.ForegroundColor
            Write-Host "`tMore info: https://github.com/Microsoft/Intune-PowerShell-SDK" -ForegroundColor Cyan
            Write-ColorOutput -Text "`t*************" -Color Yellow
        }

        # In PS7+, use Microsoft Graph
        if ($versionInfo.RequiresGraph) {
            Write-Host "`tUsing Microsoft Graph for Intune (PS7+ mode)" -ForegroundColor Yellow
            $moduleName = 'Microsoft.Graph.DeviceManagement'

            if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
                return
            }

            # Connect via Microsoft Graph with Intune scopes
            $intuneScopes = @(
                'DeviceManagementApps.Read.All',
                'DeviceManagementConfiguration.Read.All',
                'DeviceManagementManagedDevices.Read.All',
                'DeviceManagementServiceConfig.Read.All'
            )

            Connect-MSGraph -Scopes $intuneScopes -AuthMethod $AuthMethod
            Update-ConnectedServices -ServiceName $serviceName
            return
        }

        # PS 5.1 - use legacy Microsoft.Graph.Intune module
        $moduleName = 'Microsoft.Graph.Intune'

        if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
            return
        }

        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan

        # Note: These calls target the Intune SDK's Connect-MSGraph cmdlet (not this module's function).
        # Module-qualified to avoid name collision with this module's Connect-MSGraph.
        switch ($AuthMethod) {
            'ServicePrincipal' {
                Write-Warning "Service principal authentication for Intune works best with Microsoft Graph."
                Write-Warning "Consider upgrading to PowerShell 7+ for better Intune support."

                if ($AdminConsent) {
                    Microsoft.Graph.Intune\Connect-MSGraph -AdminConsent -ErrorAction Stop
                } else {
                    Microsoft.Graph.Intune\Connect-MSGraph -ErrorAction Stop
                }
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                Microsoft.Graph.Intune\Connect-MSGraph -PSCredential $cred -ErrorAction Stop
            }
            default {
                # Interactive
                if ($script:MSProfileState.MFAEnabled) {
                    if ($AdminConsent) {
                        Microsoft.Graph.Intune\Connect-MSGraph -AdminConsent -ErrorAction Stop
                    } else {
                        Microsoft.Graph.Intune\Connect-MSGraph -ErrorAction Stop
                    }
                } elseif ($script:MSProfileState.Credential) {
                    Microsoft.Graph.Intune\Connect-MSGraph -PSCredential $script:MSProfileState.Credential -ErrorAction Stop
                } else {
                    if ($AdminConsent) {
                        Microsoft.Graph.Intune\Connect-MSGraph -AdminConsent -ErrorAction Stop
                    } else {
                        Microsoft.Graph.Intune\Connect-MSGraph -ErrorAction Stop
                    }
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Host "`tGraph Connection Failed" -ForegroundColor Yellow
        Write-Host "`tYou may need to connect with 'Connect-MSIntune -AdminConsent'" -ForegroundColor Yellow
        Write-Host "`tMore Info: https://github.com/Microsoft/Intune-PowerShell-SDK" -ForegroundColor Yellow
        Write-Warning "`tUnable to connect to Intune"
        Write-Warning $Error[0].Exception.Message
    }
}
