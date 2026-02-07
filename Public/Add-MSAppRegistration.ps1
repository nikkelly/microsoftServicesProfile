function Add-MSAppRegistration {
    <#
    .SYNOPSIS
        Configures app registration (service principal) authentication.

    .DESCRIPTION
        Sets up service principal authentication using an Azure AD app registration.
        Supports both certificate-based and client secret authentication.

    .PARAMETER AppId
        The application (client) ID from Azure AD app registration.

    .PARAMETER TenantId
        The Azure AD tenant ID or domain (e.g., contoso.onmicrosoft.com).

    .PARAMETER CertificateThumbprint
        The thumbprint of the certificate for certificate-based authentication.

    .PARAMETER ClientSecret
        The client secret for secret-based authentication.

    .PARAMETER Save
        If specified, saves the app registration settings to environment variables.

    .EXAMPLE
        Add-MSAppRegistration -AppId "12345-abcd" -TenantId "contoso.onmicrosoft.com" -CertificateThumbprint "ABC123" -Save

    .EXAMPLE
        $secret = Read-Host -AsSecureString
        Add-MSAppRegistration -AppId "12345-abcd" -TenantId "contoso.onmicrosoft.com" -ClientSecret $secret -Save
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(ParameterSetName = 'Certificate')]
        [string]$CertificateThumbprint,

        [Parameter(ParameterSetName = 'Secret')]
        [SecureString]$ClientSecret,

        [switch]$Save
    )

    Write-Host "`n`tConfiguring App Registration Authentication" -ForegroundColor Cyan

    # Validate input
    if (-not $CertificateThumbprint -and -not $ClientSecret) {
        Write-Host "`tSelect authentication type:" -ForegroundColor Yellow
        Write-Host "`t[1] Certificate (thumbprint)"
        Write-Host "`t[2] Client Secret"
        $authChoice = Read-Host "`tEnter choice (1-2)"

        switch ($authChoice) {
            '1' {
                $CertificateThumbprint = Read-Host "`tEnter Certificate Thumbprint"
                if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                    Write-Warning "Certificate thumbprint is required"
                    return
                }
            }
            '2' {
                $ClientSecret = Read-Host "`tEnter Client Secret" -AsSecureString
                if ($ClientSecret.Length -eq 0) {
                    Write-Warning "Client secret is required"
                    return
                }
            }
            default {
                Write-Warning "Invalid choice"
                return
            }
        }
    }

    if (-not $PSCmdlet.ShouldProcess("App Registration (AppId: $AppId)", 'Configure service principal authentication')) {
        return
    }

    # Update module state
    $script:MSProfileState.AppRegistration = @{
        AppId                 = $AppId
        TenantId              = $TenantId
        CertificateThumbprint = $CertificateThumbprint
        ClientSecret          = $ClientSecret
    }
    $script:MSProfileState.AuthMethod = 'ServicePrincipal'

    Write-Host "`tApp registration configured:" -ForegroundColor Green
    Write-Host "`t  App ID: $AppId" -ForegroundColor Gray
    Write-Host "`t  Tenant ID: $TenantId" -ForegroundColor Gray
    Write-Host "`t  Auth Type: $(if ($CertificateThumbprint) { 'Certificate' } else { 'Client Secret' })" -ForegroundColor Gray

    # Save if requested
    if ($Save) {
        Write-Host "`tSaving app registration to environment variables..." -ForegroundColor Yellow

        [Environment]::SetEnvironmentVariable('microsoftConnectionAppId', $AppId, 'User')
        [Environment]::SetEnvironmentVariable('microsoftConnectionTenantId', $TenantId, 'User')
        [Environment]::SetEnvironmentVariable('microsoftConnectionAuthMethod', 'ServicePrincipal', 'User')

        if ($CertificateThumbprint) {
            [Environment]::SetEnvironmentVariable('microsoftConnectionCertThumbprint', $CertificateThumbprint, 'User')
        }

        if ($ClientSecret) {
            try {
                $encrypted = ConvertFrom-SecureString $ClientSecret
                [Environment]::SetEnvironmentVariable('microsoftConnectionClientSecret', $encrypted, 'User')
            } catch {
                Write-Warning "Failed to save client secret: $_"
            }
        }

        Write-Host "`tApp registration saved successfully." -ForegroundColor Green
        Write-Host "`n`tPlease close and reopen PowerShell for changes to take effect.`n" -ForegroundColor Green
    } else {
        # Prompt to save
        $saveChoice = $(Write-ColorOutput -Text "`tSave app registration for later? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
        if ($saveChoice.ToUpper() -eq "Y") {
            Add-MSAppRegistration -AppId $AppId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -ClientSecret $ClientSecret -Save
        }
    }
}
