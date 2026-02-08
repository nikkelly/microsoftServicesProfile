function Get-MSCredential {
    <#
    .SYNOPSIS
        Prompts the user for Microsoft 365 admin credentials.

    .DESCRIPTION
        Displays a credential prompt and validates the input. Stores the credential
        in the module state for use by connection functions.

    .OUTPUTS
        System.Management.Automation.PSCredential

    .EXAMPLE
        $cred = Get-MSCredential
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param()

    Write-Host "`tPrompting user for credential input" -ForegroundColor Yellow
    $credential = Get-Credential -Message "Enter your Microsoft 365 admin account credentials"

    if ($null -eq $credential) {
        Write-Warning "Credential prompt was cancelled"
        return $null
    }

    $blankUsername = [string]::IsNullOrWhiteSpace($credential.UserName)
    $blankPassword = $credential.Password.Length -eq 0

    if ($blankUsername) {
        Write-Host "`tUsername is blank" -ForegroundColor Yellow
    }

    if ($blankPassword) {
        Write-Host "`tPassword is blank" -ForegroundColor Yellow
    }

    if ($blankUsername -or $blankPassword) {
        Write-Warning "One of your credentials is blank - please verify this is intended."
    }

    # Update module state
    $script:MSProfileState.Credential = $credential
    $script:MSProfileState.MicrosoftUser = $credential.UserName

    # Extract domain from username (clear stale domain if no @)
    if ($credential.UserName -match '@') {
        $script:MSProfileState.Domain = $credential.UserName.Split('@')[-1]
    } else {
        $script:MSProfileState.Domain = $null
    }

    return $credential
}
