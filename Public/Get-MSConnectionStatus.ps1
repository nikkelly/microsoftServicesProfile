function Get-MSConnectionStatus {
    <#
    .SYNOPSIS
        Gets the current Microsoft 365 connection status.

    .DESCRIPTION
        Returns information about the current authentication configuration,
        connected services, and PowerShell version.

    .PARAMETER Detailed
        If specified, includes additional details like credential status.

    .OUTPUTS
        PSCustomObject with connection status information.

    .EXAMPLE
        Get-MSConnectionStatus

    .EXAMPLE
        Get-MSConnectionStatus -Detailed

    .LINK
        https://github.com/nikkelly/M365Connect
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$Detailed
    )

    $versionInfo = $script:MSProfileState.PSVersionInfo

    $status = [PSCustomObject]@{
        ConnectedServices = $script:MSProfileState.ConnectedServices.ToArray()
        ServiceCount      = $script:MSProfileState.ConnectedServices.Count
        AuthMethod        = $script:MSProfileState.AuthMethod
        User              = $script:MSProfileState.MicrosoftUser
        Domain            = $script:MSProfileState.Domain
        MFAEnabled        = $script:MSProfileState.MFAEnabled
        PSVersion         = "$($versionInfo.Major).$($versionInfo.Minor)"
        PSEdition         = $PSVersionTable.PSEdition
        IsPS7Plus         = $versionInfo.RequiresGraph
    }

    if ($Detailed) {
        Add-Member -InputObject $status -NotePropertyName 'CredentialLoaded' -NotePropertyValue ($null -ne $script:MSProfileState.Credential)
        Add-Member -InputObject $status -NotePropertyName 'AppRegistrationConfigured' -NotePropertyValue (
            $null -ne $script:MSProfileState.AppRegistration.AppId -and
            $null -ne $script:MSProfileState.AppRegistration.TenantId
        )
        Add-Member -InputObject $status -NotePropertyName 'AppId' -NotePropertyValue $script:MSProfileState.AppRegistration.AppId
        Add-Member -InputObject $status -NotePropertyName 'TenantId' -NotePropertyValue $script:MSProfileState.AppRegistration.TenantId
        Add-Member -InputObject $status -NotePropertyName 'HasCertificate' -NotePropertyValue ($null -ne $script:MSProfileState.AppRegistration.CertificateThumbprint)
        Add-Member -InputObject $status -NotePropertyName 'HasClientSecret' -NotePropertyValue ($null -ne $script:MSProfileState.AppRegistration.ClientSecret)
    }

    # Display formatted output
    Write-Host "`n`tMicrosoft 365 Connection Status" -ForegroundColor Cyan
    Write-Host -Object ("`t" + ("=" * 40))

    $foregroundColor = $script:MSProfileState.ForegroundColor

    # Connected services
    if ($status.ServiceCount -gt 0) {
        Write-ColorOutput -Text "`tConnected Services: ", ($status.ConnectedServices -join ', ') -Color $foregroundColor, Green
    } else {
        Write-ColorOutput -Text "`tConnected Services: ", "None" -Color $foregroundColor, Yellow
    }

    # Auth method
    $authColor = switch ($status.AuthMethod) {
        'ServicePrincipal' { 'Cyan' }
        'Credential' { 'Green' }
        default { 'Yellow' }
    }
    Write-ColorOutput -Text "`tAuth Method: ", $status.AuthMethod -Color $foregroundColor, $authColor

    # User
    if ($status.User) {
        Write-ColorOutput -Text "`tUser: ", $status.User -Color $foregroundColor, Green
    } else {
        Write-ColorOutput -Text "`tUser: ", "Not configured" -Color $foregroundColor, Yellow
    }

    # MFA
    $mfaColor = if ($status.MFAEnabled) { 'Green' } else { 'Red' }
    $mfaText = if ($status.MFAEnabled) { 'Enabled' } else { 'Disabled' }
    Write-ColorOutput -Text "`tMFA Status: ", $mfaText -Color $foregroundColor, $mfaColor

    # PS Version
    $psVersionText = "$($status.PSVersion) ($($status.PSEdition))"
    if ($status.IsPS7Plus) { $psVersionText += " [Graph Mode]" }
    Write-ColorOutput -Text "`tPowerShell: ", $psVersionText -Color $foregroundColor, Gray

    if ($Detailed) {
        Write-Host -Object ("`t" + ("-" * 40))

        # Credential status
        $credColor = if ($status.CredentialLoaded) { 'Green' } else { 'Yellow' }
        $credText = if ($status.CredentialLoaded) { 'Loaded' } else { 'Not loaded' }
        Write-ColorOutput -Text "`tCredential: ", $credText -Color $foregroundColor, $credColor

        # App registration
        if ($status.AppRegistrationConfigured) {
            Write-ColorOutput -Text "`tApp Registration: ", "Configured" -Color $foregroundColor, Green
            Write-ColorOutput -Text "`t  App ID: ", $status.AppId -Color $foregroundColor, Gray
            Write-ColorOutput -Text "`t  Tenant: ", $status.TenantId -Color $foregroundColor, Gray
            $authType = if ($status.HasCertificate) { 'Certificate' } elseif ($status.HasClientSecret) { 'Client Secret' } else { 'None' }
            Write-ColorOutput -Text "`t  Credential Type: ", $authType -Color $foregroundColor, Gray
        } else {
            Write-ColorOutput -Text "`tApp Registration: ", "Not configured" -Color $foregroundColor, Yellow
        }
    }

    Write-Host ""

    return $status
}
