function Show-MSCommands {
    <#
    .SYNOPSIS
        Displays available Microsoft Services Profile commands.

    .DESCRIPTION
        Shows the module banner, available connection commands, account management
        commands, and current configuration status.

    .PARAMETER Quiet
        If specified, only shows the banner and account status without command list.

    .EXAMPLE
        Show-MSCommands

    .EXAMPLE
        Show-MSCommands -Quiet

    .LINK
        https://github.com/nikkelly/microsoftServicesProfile
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Plural is intentional - shows multiple commands')]
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )

    $mod = Get-Module microsoftServicesProfile
    $version = if ($mod) { $mod.Version.ToString() } else { '3.0.0' }
    $versionInfo = $script:MSProfileState.PSVersionInfo
    $foregroundColor = $script:MSProfileState.ForegroundColor

    # Banner
    Write-ColorOutput -Text "--==Microsoft Services Profile v", $version, " loaded==--" -Color Yellow, Green, Yellow
    Write-Host "PowerShell $($versionInfo.Major).$($versionInfo.Minor) ($($PSVersionTable.PSEdition))" -ForegroundColor Gray

    # Account status
    $userLoaded = $null -ne $script:MSProfileState.MicrosoftUser
    $passLoaded = $null -ne $script:MSProfileState.Credential
    $mfaStatus = if ($script:MSProfileState.MFAEnabled) { 'Enabled' } else { 'Disabled' }

    $userColor = if ($userLoaded) { 'Green' } else { 'Red' }
    $passColor = if ($passLoaded) { 'Green' } else { 'Red' }
    $mfaColor = if ($script:MSProfileState.MFAEnabled) { 'Green' } else { 'Red' }

    Write-ColorOutput -Text "Account Imported: ", $userLoaded.ToString() -Color $foregroundColor, $userColor
    Write-ColorOutput -Text "Password Imported: ", $passLoaded.ToString() -Color $foregroundColor, $passColor
    Write-ColorOutput -Text "MFA Status: ", $mfaStatus -Color $foregroundColor, $mfaColor

    # App registration status
    if ($script:MSProfileState.AppRegistration.AppId) {
        Write-ColorOutput -Text "Auth Mode: ", "Service Principal" -Color $foregroundColor, Cyan
    }

    if ($Quiet) {
        return
    }

    # Connection commands
    Write-Host "`nConnect to Microsoft online services with these commands:" -ForegroundColor Green

    if ($versionInfo.RequiresGraph) {
        # PS7+ commands
        Write-Host "Connect-MSGraph | Connect-MSTeams | Connect-MSExchange | Connect-MSSharePoint | Connect-MSSecurityCompliance | Connect-MSIntune | Connect-AllMSServices | Disconnect-AllMSServices" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[PS7+ Mode] Legacy AzureAD/MSOnline aliases redirect to Connect-MSGraph" -ForegroundColor DarkYellow
    } else {
        # PS5.1 commands
        Write-Host "Teams | Exchange | ExchangeServer | MSOnline | AzureAD | AzureADPreview | SharePoint | Security_Compliance | Intune | connectAll | Disconnect" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[DEPRECATION] AzureAD and MSOnline modules are being retired. Consider using Connect-MSGraph." -ForegroundColor DarkYellow
    }

    # Account management commands
    Write-Host "`nManage Account Credentials with:" -ForegroundColor Green
    Write-Host "Add-MSAccount | Remove-MSAccount | Add-MSMFA | Remove-MSMFA" -ForegroundColor Yellow

    # App registration commands
    Write-Host "`nManage App Registration (Service Principal) with:" -ForegroundColor Green
    Write-Host "Add-MSAppRegistration | Remove-MSAppRegistration" -ForegroundColor Yellow

    # Status command
    Write-Host "`nView connection status with:" -ForegroundColor Green
    Write-Host "Get-MSConnectionStatus [-Detailed]" -ForegroundColor Yellow

    # Variables
    Write-Host "`nHelpful Variables:" -ForegroundColor Green
    if ($script:MSProfileState.MicrosoftUser) {
        Write-ColorOutput -Text '$microsoftUser = ', $script:MSProfileState.MicrosoftUser -Color Yellow, $foregroundColor
    } else {
        Write-ColorOutput -Text '$microsoftUser = ', 'Not set' -Color Yellow, $foregroundColor
    }
    if ($script:MSProfileState.Domain) {
        Write-ColorOutput -Text '$domain = ', $script:MSProfileState.Domain -Color Yellow, $foregroundColor
    } else {
        Write-ColorOutput -Text '$domain = ', 'Not set' -Color Yellow, $foregroundColor
    }

    Write-ColorOutput -Text "`nRe-display commands with: ", 'Show-MSCommands' -Color Green, $foregroundColor
}
