#Requires -Version 5.1
<#
.SYNOPSIS
    Microsoft Services Profile - Connect to Microsoft 365 services with a single command.

.DESCRIPTION
    This module provides unified authentication and connection management for multiple
    Microsoft 365 services including Teams, Exchange Online, Azure AD, SharePoint,
    Security & Compliance, and Intune.

    Supports:
    - PowerShell 5.1 (Desktop) and PowerShell 7+ (Core)
    - Interactive authentication with optional MFA
    - Stored credential authentication
    - Service principal/app registration authentication (certificate or secret)

.NOTES
    Version: 3.0.0
    Author: nikkelly
    GitHub: https://github.com/nikkelly/microsoftServicesProfile
#>

# Initialize module state
$script:MSProfileState = @{
    ConnectedServices     = [System.Collections.ArrayList]@()
    Credential            = $null
    MicrosoftUser         = $null
    Domain                = $null
    MFAEnabled            = $false
    AuthMethod            = 'Interactive'  # Interactive, Credential, ServicePrincipal
    AppRegistration       = @{
        AppId                 = $null
        TenantId              = $null
        CertificateThumbprint = $null
        ClientSecret          = $null
    }
    PSVersionInfo         = @{
        Major        = $PSVersionTable.PSVersion.Major
        Minor        = $PSVersionTable.PSVersion.Minor
        IsCore       = $PSVersionTable.PSEdition -eq 'Core'
        IsWindows    = $IsWindows -or ($PSVersionTable.PSVersion.Major -lt 6)
        SupportsAzureAD = $PSVersionTable.PSVersion.Major -lt 7
        RequiresGraph   = $PSVersionTable.PSVersion.Major -ge 7
    }
    OriginalPrompt        = $null
    ForegroundColor       = $host.UI.RawUI.ForegroundColor
}

# Dot-source all Private function files first
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Private) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import private function $($file.FullName): $_"
    }
}

# Dot-source all Public function files
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
foreach ($file in $Public) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import public function $($file.FullName): $_"
    }
}

# Create backward-compatible aliases (Script scope for proper module export)
Set-Alias -Name Teams -Value Connect-MSTeams -Scope Script
Set-Alias -Name Exchange -Value Connect-MSExchange -Scope Script
Set-Alias -Name ExchangeServer -Value Connect-MSExchangeServer -Scope Script
Set-Alias -Name AzureAD -Value Connect-MSAzureAD -Scope Script
Set-Alias -Name AzureADPreview -Value Connect-MSAzureAD -Scope Script
Set-Alias -Name MSOnline -Value Connect-MSGraph -Scope Script
Set-Alias -Name SharePoint -Value Connect-MSSharePoint -Scope Script
Set-Alias -Name Security_Compliance -Value Connect-MSSecurityCompliance -Scope Script
Set-Alias -Name Intune -Value Connect-MSIntune -Scope Script
Set-Alias -Name connectAll -Value Connect-AllMSServices -Scope Script
Set-Alias -Name Disconnect -Value Disconnect-AllMSServices -Scope Script
Set-Alias -Name Add-Account -Value Add-MSAccount -Scope Script
Set-Alias -Name Remove-Account -Value Remove-MSAccount -Scope Script
Set-Alias -Name Add-MFA -Value Add-MSMFA -Scope Script
Set-Alias -Name Remove-MFA -Value Remove-MSMFA -Scope Script

# Auto-import credentials and settings on module load
Initialize-ModuleState

# Display startup message
Show-MSCommands -Quiet
