function Remove-MSMFA {
    <#
    .SYNOPSIS
        Disables MFA mode for Microsoft 365 connections.

    .DESCRIPTION
        Clears the MFA flag from environment variables and the current session.

    .EXAMPLE
        Remove-MSMFA
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('microsoftConnectionMFA', 'Remove MFA environment variable')) {
        try {
            [Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
            Remove-Item env:microsoftConnectionMFA -ErrorAction SilentlyContinue
            $script:MSProfileState.MFAEnabled = $false
            Write-Host "`tMFA disabled" -ForegroundColor Yellow
        } catch {
            Write-Warning "Failed to remove MFA setting: $_"
        }
    }
}
