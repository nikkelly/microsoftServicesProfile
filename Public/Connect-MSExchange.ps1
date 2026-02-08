function Connect-MSExchange {
    <#
    .SYNOPSIS
        Connects to Exchange Online.

    .DESCRIPTION
        Establishes a connection to Exchange Online using the ExchangeOnlineManagement module.
        Supports interactive, credential-based, and service principal (certificate) authentication.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive, Credential, or ServicePrincipal.
        Note: Exchange Online only supports certificate-based service principal authentication.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER Organization
        The organization domain (e.g., contoso.onmicrosoft.com) for service principal auth.

    .PARAMETER AppId
        The application (client) ID for service principal authentication.

    .PARAMETER CertificateThumbprint
        The certificate thumbprint for service principal authentication.

    .EXAMPLE
        Connect-MSExchange

    .EXAMPLE
        Connect-MSExchange -AuthMethod ServicePrincipal -Organization "contoso.onmicrosoft.com" -AppId "12345" -CertificateThumbprint "ABC123"

    .LINK
        https://github.com/nikkelly/M365Connect
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [string]$Organization,

        [string]$AppId,

        [string]$CertificateThumbprint
    )

    $serviceName = 'Exchange'
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
                    Write-Warning "Exchange Online service principal authentication requires certificate-based auth."
                    Write-Warning "Client secret authentication is not supported for Exchange Online."
                    Write-Warning "Use Add-MSAppRegistration to configure certificate authentication."
                    return
                }

                if (-not $org) {
                    $org = Read-Host "`tEnter organization domain (e.g., contoso.onmicrosoft.com)"
                }

                Connect-ExchangeOnline -AppId $appIdValue -CertificateThumbprint $thumbprint -Organization $org -ShowBanner:$false -ErrorAction Stop
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                # Exchange Online Management uses modern auth and does not accept PSCredential.
                # UPN is passed to pre-fill the interactive login prompt.
                Write-Host "`tNote: Exchange Online requires interactive auth (UPN pre-filled)" -ForegroundColor Yellow
                Connect-ExchangeOnline -UserPrincipalName $cred.UserName -ShowBanner:$false -ErrorAction Stop
            }
            default {
                # Interactive - Exchange Online V2 uses modern auth by default
                $upn = $script:MSProfileState.MicrosoftUser
                if ($upn) {
                    Connect-ExchangeOnline -UserPrincipalName $upn -ShowBanner:$false -ErrorAction Stop
                } else {
                    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to Exchange Online"

        if ($_.Exception.Message -match "AADSTS50076") {
            Write-Warning "`tMFA error detected"
            Write-ColorOutput -Text "`tTry ", "Add-MSMFA", " and re-run ", "Connect-MSExchange" -Color Yellow, Green, Yellow, Green
            return
        }

        Write-Warning $_.Exception.Message
    }
}
