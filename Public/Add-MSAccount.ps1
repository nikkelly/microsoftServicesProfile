function Add-MSAccount {
    <#
    .SYNOPSIS
        Adds and optionally saves Microsoft 365 admin credentials.

    .DESCRIPTION
        Prompts for Microsoft 365 admin credentials and optionally saves them to
        environment variables for future sessions.

    .PARAMETER Save
        If specified, automatically saves credentials without prompting.

    .PARAMETER NoSave
        If specified, does not prompt to save credentials.

    .EXAMPLE
        Add-MSAccount

    .EXAMPLE
        Add-MSAccount -Save

    .LINK
        https://github.com/nikkelly/M365Connect
    #>
    [CmdletBinding()]
    param(
        [switch]$Save,
        [switch]$NoSave
    )

    try {
        $credential = Get-MSCredential

        if ($null -eq $credential) {
            return
        }

        # Check for blank credentials
        $blankUser = [string]::IsNullOrWhiteSpace($credential.UserName)
        $blankPass = $credential.Password.Length -eq 0

        if ($blankUser -or $blankPass) {
            Write-Warning "One of your credentials is blank - please verify this is intended."
        }

        # Prompt for MFA preference
        $mfaCheck = $(Write-ColorOutput -Text "`tDoes this account need MFA enabled? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
        if ($mfaCheck.ToUpper() -eq "Y") {
            Add-MSMFA -Save
        }

        # Handle save preference
        if ($NoSave) {
            Write-Host "`tCredentials not saved" -ForegroundColor Yellow
            return
        }

        if ($Save) {
            Export-MSCredential -Credential $credential
            return
        }

        # Prompt to save
        $saveChoice = $(Write-ColorOutput -Text "`tWould you like to save this account for later? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)

        if ($saveChoice.ToUpper() -eq "Y") {
            Export-MSCredential -Credential $credential
        } else {
            Write-Host "`tCredentials not saved" -ForegroundColor Red
        }

    } catch {
        Write-Warning "Unable to add account"
        Write-Warning $_.Exception.Message
    }
}
