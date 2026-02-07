function Remove-MSAccount {
    <#
    .SYNOPSIS
        Removes saved Microsoft 365 credentials.

    .DESCRIPTION
        Deletes the saved username, password, and MFA settings from environment variables
        and clears them from the current session.

    .PARAMETER KeepMFA
        If specified, keeps the MFA setting and only removes username/password.

    .EXAMPLE
        Remove-MSAccount

    .EXAMPLE
        Remove-MSAccount -KeepMFA
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$KeepMFA
    )

    $removedItems = @()

    # Remove username
    try {
        if ((Test-Path env:microsoftConnectionUser) -and $PSCmdlet.ShouldProcess('microsoftConnectionUser', 'Remove environment variable')) {
            [System.Environment]::SetEnvironmentVariable("microsoftConnectionUser", $null, "User")
            $script:MSProfileState.MicrosoftUser = $null
            $script:MSProfileState.Domain = $null
            Write-Host "`tMicrosoft connection user removed" -ForegroundColor Yellow
            $removedItems += 'User'
        }
    } catch {
        Write-Warning "Failed to remove user: $_"
    }

    # Remove password
    try {
        if ((Test-Path env:microsoftConnectionPass) -and $PSCmdlet.ShouldProcess('microsoftConnectionPass', 'Remove environment variable')) {
            [System.Environment]::SetEnvironmentVariable("microsoftConnectionPass", $null, "User")
            $script:MSProfileState.Credential = $null
            Write-Host "`tMicrosoft connection password removed" -ForegroundColor Yellow
            $removedItems += 'Password'
        }
    } catch {
        Write-Warning "Failed to remove password: $_"
    }

    # Remove MFA setting
    if (-not $KeepMFA) {
        try {
            if ((Test-Path env:microsoftConnectionMFA) -and $PSCmdlet.ShouldProcess('microsoftConnectionMFA', 'Remove environment variable')) {
                [System.Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
                $script:MSProfileState.MFAEnabled = $false
                Write-Host "`tMicrosoft connection MFA removed" -ForegroundColor Yellow
                $removedItems += 'MFA'
            }
        } catch {
            Write-Warning "Failed to remove MFA setting: $_"
        }
    }

    if ($removedItems.Count -gt 0) {
        Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
    } else {
        Write-Host "`tNo saved account found to remove." -ForegroundColor Yellow
    }
}
