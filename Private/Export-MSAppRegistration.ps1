function Export-MSAppRegistration {
    <#
    .SYNOPSIS
        Saves app registration settings to environment variables.

    .DESCRIPTION
        Persists the current app registration configuration (AppId, TenantId,
        CertificateThumbprint, ClientSecret) to user-level environment variables.

    .EXAMPLE
        Export-MSAppRegistration
    #>
    [CmdletBinding()]
    param()

    $appReg = $script:MSProfileState.AppRegistration

    if (-not $appReg.AppId) {
        Write-Warning "No app registration configured. Use Add-MSAppRegistration first."
        return
    }

    Write-Host "`tSaving app registration to environment variables..." -ForegroundColor Yellow

    [Environment]::SetEnvironmentVariable('microsoftConnectionAppId', $appReg.AppId, 'User')
    [Environment]::SetEnvironmentVariable('microsoftConnectionTenantId', $appReg.TenantId, 'User')
    [Environment]::SetEnvironmentVariable('microsoftConnectionAuthMethod', 'ServicePrincipal', 'User')

    if ($appReg.CertificateThumbprint) {
        [Environment]::SetEnvironmentVariable('microsoftConnectionCertThumbprint', $appReg.CertificateThumbprint, 'User')
    }

    if ($appReg.ClientSecret) {
        try {
            $encrypted = ConvertFrom-SecureString $appReg.ClientSecret
            [Environment]::SetEnvironmentVariable('microsoftConnectionClientSecret', $encrypted, 'User')
        } catch {
            Write-Warning "Failed to save client secret: $_"
        }
    }

    Write-Host "`tApp registration saved successfully." -ForegroundColor Green
    Write-Host "`n`tPlease close and reopen PowerShell for changes to take effect.`n" -ForegroundColor Green
}
