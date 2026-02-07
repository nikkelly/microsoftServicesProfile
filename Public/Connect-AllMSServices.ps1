function Connect-AllMSServices {
    <#
    .SYNOPSIS
        Connects to all Microsoft 365 services.

    .DESCRIPTION
        Establishes connections to all available Microsoft 365 services in sequence.
        In PowerShell 7+, uses Microsoft Graph instead of deprecated AzureAD/MSOnline modules.

    .PARAMETER SkipServices
        An array of service names to skip during connection.

    .PARAMETER AuthMethod
        The authentication method to use for all connections.

    .EXAMPLE
        Connect-AllMSServices

    .EXAMPLE
        Connect-AllMSServices -SkipServices 'SharePoint', 'Intune'

    .LINK
        https://github.com/nikkelly/microsoftServicesProfile
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Plural is intentional - connects to multiple services')]
    [CmdletBinding()]
    param(
        [string[]]$SkipServices = @(),

        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod
    )

    $versionInfo = $script:MSProfileState.PSVersionInfo

    Write-Host "`n`tConnecting to all Microsoft 365 services..." -ForegroundColor Cyan
    Write-Host "`tPowerShell Version: $($versionInfo.Major).$($versionInfo.Minor) ($($PSVersionTable.PSEdition))" -ForegroundColor Gray

    # Define services based on PS version
    if ($versionInfo.RequiresGraph) {
        # PowerShell 7+ - use Graph instead of AzureAD/MSOnline
        $services = @(
            @{ Name = 'Graph'; Function = 'Connect-MSGraph' },
            @{ Name = 'Exchange'; Function = 'Connect-MSExchange' },
            @{ Name = 'Teams'; Function = 'Connect-MSTeams' },
            @{ Name = 'SharePoint'; Function = 'Connect-MSSharePoint' },
            @{ Name = 'Security_Compliance'; Function = 'Connect-MSSecurityCompliance' },
            @{ Name = 'Intune'; Function = 'Connect-MSIntune' }
        )

        Write-Host "`t[PS7+ Mode] Using Microsoft Graph instead of AzureAD/MSOnline" -ForegroundColor Yellow
    } else {
        # PowerShell 5.1 - use legacy modules
        $services = @(
            @{ Name = 'AzureAD'; Function = 'Connect-MSAzureAD' },
            @{ Name = 'Exchange'; Function = 'Connect-MSExchange' },
            @{ Name = 'Teams'; Function = 'Connect-MSTeams' },
            @{ Name = 'SharePoint'; Function = 'Connect-MSSharePoint' },
            @{ Name = 'Security_Compliance'; Function = 'Connect-MSSecurityCompliance' },
            @{ Name = 'Intune'; Function = 'Connect-MSIntune' }
        )
    }

    foreach ($service in $services) {
        if ($SkipServices -contains $service.Name) {
            Write-Host "`tSkipping $($service.Name)..." -ForegroundColor Gray
            continue
        }

        Write-Host "" # Empty line for readability
        try {
            & $service.Function -AuthMethod $AuthMethod
        } catch {
            Write-Warning "Failed to connect to $($service.Name): $_"
        }
    }

    Write-Host "`n`tConnection process complete." -ForegroundColor Green

    # Show summary
    if ($script:MSProfileState.ConnectedServices.Count -gt 0) {
        Write-Host "`tConnected services: $($script:MSProfileState.ConnectedServices -join ', ')" -ForegroundColor Cyan
    } else {
        Write-Host "`tNo services connected." -ForegroundColor Yellow
    }
}
