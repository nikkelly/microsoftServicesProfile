function Get-PSVersionInfo {
    <#
    .SYNOPSIS
        Gets PowerShell version and platform information.

    .DESCRIPTION
        Returns a hashtable containing PowerShell version details, platform information,
        and module compatibility flags.

    .OUTPUTS
        System.Collections.Hashtable

    .EXAMPLE
        $info = Get-PSVersionInfo
        if ($info.RequiresGraph) { Write-Host "Use Microsoft Graph instead of AzureAD" }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        Major           = $PSVersionTable.PSVersion.Major
        Minor           = $PSVersionTable.PSVersion.Minor
        Full            = $PSVersionTable.PSVersion.ToString()
        IsCore          = $PSVersionTable.PSEdition -eq 'Core'
        IsWindows       = $IsWindows -or ($PSVersionTable.PSVersion.Major -lt 6)
        IsLinux         = $IsLinux -eq $true
        IsMacOS         = $IsMacOS -eq $true
        SupportsAzureAD = $PSVersionTable.PSVersion.Major -lt 7
        RequiresGraph   = $PSVersionTable.PSVersion.Major -ge 7
    }
}
