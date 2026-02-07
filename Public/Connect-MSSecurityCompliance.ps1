function Connect-MSSecurityCompliance {
    <#
    .SYNOPSIS
        Connects to Security & Compliance Center.

    .DESCRIPTION
        Establishes a connection to the Microsoft 365 Security & Compliance Center
        using the ExchangeOnlineManagement module (Connect-IPPSSession).

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER AppId
        The application (client) ID for service principal authentication.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for service principal authentication.

    .PARAMETER Organization
        The organization domain for service principal authentication.

    .EXAMPLE
        Connect-MSSecurityCompliance

    .EXAMPLE
        Connect-MSSecurityCompliance -AuthMethod ServicePrincipal -AppId "12345" -CertificateThumbprint "ABC123" -Organization "contoso.onmicrosoft.com"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [string]$AppId,

        [string]$CertificateThumbprint,

        [string]$Organization
    )

    $serviceName = 'Security_Compliance'
    $moduleName = 'ExchangeOnlineManagement'

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
                $appIdValue = if ($AppId) { $AppId } else { $script:MSProfileState.AppRegistration.AppId }
                $thumbprint = if ($CertificateThumbprint) { $CertificateThumbprint } else { $script:MSProfileState.AppRegistration.CertificateThumbprint }
                $org = if ($Organization) { $Organization } else { $script:MSProfileState.Domain }

                if (-not $appIdValue -or -not $thumbprint) {
                    Write-Warning "Security & Compliance service principal authentication requires certificate-based auth."
                    Write-Warning "Client secret authentication is not supported."
                    return
                }

                if (-not $org) {
                    $org = Read-Host "`tEnter organization domain (e.g., contoso.onmicrosoft.com)"
                }

                Connect-IPPSSession -AppId $appIdValue -CertificateThumbprint $thumbprint -Organization $org -ErrorAction Stop
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                # Note: Fixed bug from original - was passing $credential instead of $credential.UserName
                Connect-IPPSSession -UserPrincipalName $cred.UserName -ErrorAction Stop
            }
            default {
                # Interactive
                if ($script:MSProfileState.MFAEnabled -and $script:MSProfileState.Credential) {
                    Connect-IPPSSession -UserPrincipalName $script:MSProfileState.Credential.UserName -ErrorAction Stop
                } elseif ($script:MSProfileState.MicrosoftUser) {
                    Connect-IPPSSession -UserPrincipalName $script:MSProfileState.MicrosoftUser -ErrorAction Stop
                } else {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    Connect-IPPSSession -ErrorAction Stop
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to Security & Compliance Center"

        # Check for MFA error
        foreach ($e in $Error[0..2]) {
            if ($e.Exception.Message -match "AADSTS50076") {
                Write-Warning "`tMFA error detected"
                Write-ColorOutput -Text "`tTry ", "Add-MSMFA", " and re-run ", "Connect-MSSecurityCompliance" -Color Yellow, Green, Yellow, Green
                return
            }
        }

        Write-Warning $Error[0].Exception.Message
    }
}
