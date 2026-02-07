@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'microsoftServicesProfile.psm1'

    # Version number of this module.
    ModuleVersion = '3.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID = 'f8d7e3c2-5a1b-4c9d-8e0f-6b2a3d4c5e6f'

    # Author of this module
    Author = 'nikkelly'

    # Company or vendor of this module
    CompanyName = 'Unknown'

    # Copyright statement for this module
    Copyright = '(c) nikkelly. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Connect to Microsoft 365 services with a single command. Supports PowerShell 5.1 and 7+, interactive authentication, stored credentials, and service principal/app registration authentication.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-MSTeams',
        'Connect-MSExchange',
        'Connect-MSExchangeServer',
        'Connect-MSAzureAD',
        'Connect-MSGraph',
        'Connect-MSSharePoint',
        'Connect-MSSecurityCompliance',
        'Connect-MSIntune',
        'Connect-AllMSServices',
        'Disconnect-AllMSServices',
        'Add-MSAccount',
        'Remove-MSAccount',
        'Add-MSAppRegistration',
        'Remove-MSAppRegistration',
        'Add-MSMFA',
        'Remove-MSMFA',
        'Get-MSConnectionStatus',
        'Show-MSCommands'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @(
        'Teams',
        'Exchange',
        'ExchangeServer',
        'AzureAD',
        'AzureADPreview',
        'MSOnline',
        'SharePoint',
        'Security_Compliance',
        'Intune',
        'connectAll',
        'Disconnect',
        'Add-Account',
        'Remove-Account',
        'Add-MFA',
        'Remove-MFA'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module for module discovery
            Tags = @('Microsoft365', 'Azure', 'Teams', 'Exchange', 'SharePoint', 'AzureAD', 'Graph', 'Intune', 'Office365')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/nikkelly/microsoftServicesProfile'

            # ReleaseNotes of this module
            ReleaseNotes = @'
## 3.0.0
- Converted to PowerShell module format with .psd1 manifest
- Added PowerShell 7 support with Microsoft Graph fallback for deprecated modules
- Added service principal/app registration authentication support
- Added backward-compatible aliases for all original commands
- Fixed Security_Compliance connection bug with -UserPrincipalName parameter
- Added Get-MSConnectionStatus function for connection monitoring
- Added deprecation warnings for AzureAD and MSOnline modules
'@

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''
}
