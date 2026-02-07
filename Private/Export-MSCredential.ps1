function Export-MSCredential {
    <#
    .SYNOPSIS
        Saves Microsoft 365 credentials to environment variables.

    .DESCRIPTION
        Encrypts and stores the username and password in user-level environment variables.
        On Windows, uses DPAPI for encryption. On other platforms, provides a warning
        about limited encryption capabilities.

    .PARAMETER Credential
        The PSCredential object to save. If not specified, uses the credential from module state.

    .EXAMPLE
        Export-MSCredential -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCredential]$Credential = $script:MSProfileState.Credential
    )

    if ($null -eq $Credential) {
        Write-Warning "No credential to save. Use Get-MSCredential first."
        return
    }

    $versionInfo = $script:MSProfileState.PSVersionInfo

    # Warn about non-Windows encryption limitations
    if (-not $versionInfo.IsWindows) {
        Write-Warning "Credential encryption on non-Windows platforms is less secure."
        Write-Warning "Consider using App Registration with certificate authentication instead."
    }

    Write-Host "`tSaving to environment variables..." -ForegroundColor Yellow

    # Save Username
    if ([string]::IsNullOrWhiteSpace($Credential.UserName)) {
        Write-Host "`tUsername is blank - skipping save" -ForegroundColor Yellow
        $userSaved = $false
    } else {
        try {
            $secureUser = [System.Security.SecureString]::new()
            try {
                foreach ($char in $Credential.UserName.ToCharArray()) {
                    $secureUser.AppendChar($char)
                }
                $encryptedUser = ConvertFrom-SecureString $secureUser
                [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $encryptedUser, [System.EnvironmentVariableTarget]::User)
                $userSaved = $true
            } finally {
                $secureUser.Dispose()
            }
        } catch {
            Write-Warning "Failed to save username: $_"
            $userSaved = $false
        }
    }

    $userColor = if ($userSaved) { "Green" } else { "Red" }
    Write-Host "`tUser Saved: $userSaved" -ForegroundColor $userColor

    # Save Password
    if ($Credential.Password.Length -eq 0) {
        Write-Host "`tPassword is blank - skipping save" -ForegroundColor Yellow
        $passwordSaved = $false
    } else {
        try {
            $encryptedPass = ConvertFrom-SecureString $Credential.Password
            [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $encryptedPass, [System.EnvironmentVariableTarget]::User)
            $passwordSaved = $true
        } catch {
            Write-Warning "Failed to save password: $_"
            $passwordSaved = $false
        }
    }

    $passColor = if ($passwordSaved) { "Green" } else { "Red" }
    Write-Host "`tPassword Saved: $passwordSaved" -ForegroundColor $passColor

    Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
}
