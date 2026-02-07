function Import-MSCredential {
    <#
    .SYNOPSIS
        Loads Microsoft 365 credentials from environment variables.

    .DESCRIPTION
        Retrieves encrypted username and password from user-level environment variables
        and creates a PSCredential object. Updates the module state with the loaded credentials.

    .OUTPUTS
        System.Management.Automation.PSCredential or $null if no credentials found.

    .EXAMPLE
        $cred = Import-MSCredential
    #>
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param()

    $script:MSProfileState.MicrosoftUser = $null
    $script:MSProfileState.Credential = $null

    # Check for saved username
    if (Test-Path env:microsoftConnectionUser) {
        try {
            $secureUser = ConvertTo-SecureString $env:microsoftConnectionUser -ErrorAction Stop
            $script:MSProfileState.MicrosoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUser)
            )
        } catch {
            Write-Warning "Failed to decrypt saved username. Credentials may need to be re-saved with Add-MSAccount."
            Write-Verbose "Decryption error: $_"
        }
    }

    # Check for saved password
    if (Test-Path env:microsoftConnectionPass) {
        try {
            $securePass = ConvertTo-SecureString $env:microsoftConnectionPass -ErrorAction Stop

            if ($script:MSProfileState.MicrosoftUser) {
                $script:MSProfileState.Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $script:MSProfileState.MicrosoftUser, $securePass
            }
        } catch {
            Write-Warning "Failed to decrypt saved password. Credentials may need to be re-saved with Add-MSAccount."
            Write-Verbose "Decryption error: $_"
        }
    }

    # Extract domain from username
    if ($script:MSProfileState.MicrosoftUser -match '@') {
        $script:MSProfileState.Domain = $script:MSProfileState.MicrosoftUser.Split('@')[-1]
    }

    return $script:MSProfileState.Credential
}
