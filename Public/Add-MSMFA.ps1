function Add-MSMFA {
    <#
    .SYNOPSIS
        Enables MFA mode for Microsoft 365 connections.

    .DESCRIPTION
        Sets the MFA flag to indicate that the stored account requires multi-factor
        authentication. This affects how connection functions authenticate.

    .PARAMETER Save
        If specified, saves the MFA setting to environment variables for future sessions.

    .EXAMPLE
        Add-MSMFA

    .EXAMPLE
        Add-MSMFA -Save

    .LINK
        https://github.com/nikkelly/microsoftServicesProfile
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$Save
    )

    if ($PSCmdlet.ShouldProcess('MFA setting', 'Enable MFA mode')) {
        $script:MSProfileState.MFAEnabled = $true

        if ($Save) {
            try {
                [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', 'true', [System.EnvironmentVariableTarget]::User)
                Write-Host "`tMFA Saved: True" -ForegroundColor Green
            } catch {
                Write-Warning "Failed to save MFA setting: $_"
            }
        } else {
            Write-Host "`tMFA enabled for this session" -ForegroundColor Green
        }
    }
}
