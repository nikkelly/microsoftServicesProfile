function Remove-MSAppRegistration {
    <#
    .SYNOPSIS
        Removes app registration (service principal) configuration.

    .DESCRIPTION
        Clears the app registration settings from environment variables and
        resets the authentication method to interactive.

    .EXAMPLE
        Remove-MSAppRegistration

    .LINK
        https://github.com/nikkelly/M365Connect
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $envVars = @(
        'microsoftConnectionAppId',
        'microsoftConnectionTenantId',
        'microsoftConnectionCertThumbprint',
        'microsoftConnectionClientSecret',
        'microsoftConnectionAuthMethod'
    )

    $removedItems = @()

    foreach ($var in $envVars) {
        if ((Test-Path "env:$var") -and $PSCmdlet.ShouldProcess($var, 'Remove environment variable')) {
            [Environment]::SetEnvironmentVariable($var, $null, 'User')
            Remove-Item "env:$var" -ErrorAction SilentlyContinue
            Write-Host "`t$var removed" -ForegroundColor Yellow
            $removedItems += $var
        }
    }

    # Reset module state
    if ($PSCmdlet.ShouldProcess('AppRegistration state', 'Reset to defaults')) {
        $script:MSProfileState.AuthMethod = 'Interactive'
        $script:MSProfileState.AppRegistration = @{
            AppId                 = $null
            TenantId              = $null
            CertificateThumbprint = $null
            ClientSecret          = $null
        }
    }

    if ($removedItems.Count -gt 0) {
        Write-Host "`n`tApp registration cleared from this session and persistent storage.`n" -ForegroundColor Green
    } else {
        Write-Host "`tNo app registration found to remove." -ForegroundColor Yellow
    }
}
