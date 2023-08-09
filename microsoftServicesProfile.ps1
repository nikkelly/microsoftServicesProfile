
<# microsoftServicesProfile.ps1
.SYNOPSIS
This profile is used to simplify connecting to Microsoft 365 services with PowerShell
.DESCRIPTION
This script can be used to authenticate your management account to all Microsoft 365 services.
.EXAMPLE
.\microsoftServicesProfile -Install
Add the Microsoft Services Profile to your current PowerShell $profile
Teams
Connect to Teams using the MicrosoftTeams Powershell module
Invoke-AddAccount
Save your management account information to an environment variable
.NOTES
Name: microsoftServicesProfile
#>
param (
[Switch]$install,
[Switch]$uninstall
)
$version = '2.0'
$foregroundColor = $host.UI.RawUI.ForegroundColor
function Write-ColoredText {
    param (
        [String[]]$Text,
        [ConsoleColor[]]$Color,
        [switch]$NewLine = $true
    )
    for ($i = 0; $i -lt $Text.Length; $i++) {
        Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
    }
    if ($NewLine) { Write-Host }
}
function Invoke-DisplayCommand {
    Write-Host "`nConnect to Microsoft online services with these commands: " -ForegroundColor Green
    Write-Host "Teams | ExchangeServer | Exchange | MSOnline (AAD V1) | AzureAD (AAD V2) | AzureADPreview | SharePoint | Security_Compliance | Intune | connectAll | Disconnect`n" -ForegroundColor Yellow
    Write-Host 'Manage Account Credentials with: ' -ForegroundColor Green
    Write-Host "Invoke-AddAccount | Clear-Account | Invoke-AddMFA | Clear-MFA `n" -ForegroundColor Yellow
    Write-Host 'Helpful Variables' -ForegroundColor Green
    if ($null -eq $script:microsoftUser) {
        Write-ColoredText '$microsoftUser = ', 'Not set' -Color Yellow, $foregroundColor
    } else {
        Write-ColoredText '$microsoftUser = ', $script:microsoftUser -Color Yellow, $foregroundColor
    }
    if ($null -eq $script:domain) {
        Write-ColoredText '$domain = ', 'Not set' -Color Yellow, $foregroundColor
    } else {
        Write-ColoredText '$domain = ', $script:domain -Color Yellow, $foregroundColor
    }
    Write-ColoredText "`nRe-display commands with: ", 'Invoke-DisplayCommand' -Color Green, $foregroundColor
}
function Import-Domain {
    if ($script:microsoftUser) {
        $script:domain = $script:microsoftUser.Split('@') | Select-Object -Last 1
    } else {
        $script:domain = $null
    }
}
function Add-Domain {
    $script:domain = Read-Host 'Enter your domain:'
    if ($script:domain.Length -eq 0) {
        Write-Host 'Domain cannot be blank.'
        $script:domain = $null
        Exit
    }
}
function Invoke-AddAccount {
    try {
        Invoke-CredentialPrompt
        if (($script:blankPassword -eq $true) -or ($script:blankUser -eq $true)) {
            Write-Warning 'One of your credentials is blank - please verify this is intended.'
        } else {
            Get-MFA
            $saveCreds = $(Write-ColoredText "`tWould you like to save this account for later? [", 'Y', '/', 'N', ']' -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
            if ($saveCreds.ToUpper() -ne 'Y') {
                Write-Host "`tCredentials not saved" -ForegroundColor Red
            } else {
                try {
                    Export-Credential $script:microsoftCredential
                } catch {
                    Write-Warning 'Unable to add account'
                    Write-Warning $Error[0]
                    Write-Warning 'Ensure that MFA is not required.'
                }
            }
        }
    } catch {
        Write-Warning 'Unable to add account'
    }
}
function Clear-Account {
    # Delete environment variable
    try {
        if (Test-Path env:microsoftConnectionUser) {
            [system.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $null, 'User')
            $script:microsoftUser = $null
            $script:domain = $null
            $script:microsoftUserLoaded = $false
            Write-Host "`tMicrosoft connection user removed" -ForegroundColor Yellow
        }
    } catch {
        throw
    }
    try {
        if (Test-Path env:microsoftConnectionPass) {
            [system.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $null, 'User')
            $script:microsoftPass = $null
            $script:microsoftPassLoaded = $false
            Write-Host "`tMicrosoft connection password removed" -ForegroundColor Yellow
        }
    } catch {
        throw
    }
    try {
        if (Test-Path env:microsoftConnectionMFA) {
            [system.Environment]::SetEnvironmentVariable('microsoftConnectionMfa', $null, 'User')
            $script:mfaStatus = $null
            Write-Host "`tMicrosoft connection MFA removed" -ForegroundColor Yellow
        }
    } catch {
        throw
    }
    Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
}
function Invoke-DisplayAccount {
    $script:microsoftUserLoaded = $false
    $script:microsoftPassLoaded = $false
    $script:microsoftMFALoaded = 'Disabled'
    if (($null -eq $script:microsoftUser) -or ($script:microsoftUser -eq $false)) {
        Write-ColoredText 'Account Imported: ', $script:microsoftUserLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftUserLoaded = $True
        Write-ColoredText 'Account Imported: ', $script:microsoftUserLoaded -Color $foregroundColor, Green
    }
    if (($null -eq $script:microsoftPass) -or ($script:microsoftPass -eq $false)) {
        Write-ColoredText 'Password Imported: ', $script:microsoftPassLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftPassLoaded = $True
        Write-ColoredText 'Password Imported: ', $script:microsoftPassLoaded -Color $foregroundColor, Green
    }
    if (($null -eq $script:mfaStatus) -or ($script:mfaStatus -eq $false)) {
        Write-ColoredText 'MFA Status: ', $script:microsoftMFALoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftMFALoaded = 'Enabled'
        Write-ColoredText 'MFA Status: ', $script:microsoftMFALoaded -Color $foregroundColor, Green
    }
}
Function Get-IsAdministrator {
    <#
    Determine if the script is running in the context of an administrator or not
    #>
    Write-Host "`tChecking for administrative privileges." -ForegroundColor Yellow
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isAdmin = $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($null -ne $script:isAdmin) {
        Write-Host "`tUser is an admin" -ForegroundColor Green
    }
}
#TODO Need to check if there's an updated version, and then use this to remove the old one
Function Uninstall-OldModule {
    <#
    Removes old versions of a module
    #>
    Param(
    $Module
    )
    $Modules = (Get-Module $Module -ListAvailable | Sort-Object Version -Descending)
    $Latest = $Modules[0]
    If ($Modules.Count -gt 1) {
        ForEach ($Module in $Modules) {
            If ($Module.Version -ne $Latest.Version) {
                # Not the latest version, remove it.
                Write-Host "$(Get-Date) Uninstalling $($Module.Name) Version $($Module.Version)"
                Try {
                    Uninstall-Module $Module.Name -RequiredVersion $($Module.Version) -ErrorAction:Stop
                } Catch {
                    throw
                }
            }
        }
    }
}
function Install-ModuleFromGallery {
    Param(
    $Module,
    [Switch]$update
    )
    Install-Module $Module -Force -Scope:AllUsers -AllowClobber
    if ($update) {
        #remove old versions of this module
        Uninstall-OldModules -Module $Module
    }
}
function connectAll {
    AzureAD
    AzureADPreview
    Exchange
    ExchangeServer
    Intune
    MSOnline
    SharePoint
    Teams
}
function Import-ProfileSetting {
    Import-MFAStatus
    Import-Credential
    Import-Domain
}
function Invoke-ProfileStart {
    $script:connectedServices = @()
    Write-ColoredText '--==Microsoft Services Profile v', $($version), ' loaded==--' -Color Yellow, Green, Yellow
    Import-ProfileSetting
    Invoke-DisplayAccount
    Invoke-DisplayCommand
}
function Invoke-UpdateConnectedService {
    $script:connectedServices += $serviceName
    if ($script:connectedServices.Length -eq 1) {
        $script:joinedServices = "[$script:connectedServices]"
        Invoke-UpdatePrompt
        Write-Host "`tConnected to $serviceName!" -ForegroundColor Green
    } else {
        $script:joinedServices = "[$($script:connectedServices -join '|')]"
        Write-Host "`tConnected to $serviceName!" -ForegroundColor Green
    }
}
function Invoke-UpdatePrompt {
    $script:userPrompt = $function:prompt
    $function:prompt = & {
        $__last_prompt = $function:prompt
        { & $script:__last_prompt;
        Write-Host " $($joinedServices) " -NoNewline -ForegroundColor Yellow
    }.GetNewClosure()
}
}
function Invoke-CredentialPrompt {
Write-Host "`tPrompting user for credential input" -ForegroundColor Yellow
$script:microsoftCredential = Get-Credential -Message 'Enter your admin account credentials'
if ($script:microsoftCredential.Username.Length -eq 0) {
    Write-Host 'Username is blank' -ForegroundColor Yellow
    $script:blankUsername = $true
} else {
    $script:blankUsername = $false
}
if ($script:microsoftCredential.Password.Length -eq 0) {
    Write-Host 'Password is blank' -ForegroundColor Yellow
    $script:blankPassword = $true
} else {
    $script:blankPassword = $false
}
}
function Get-MFA {

$mfaCheck = $(Write-ColoredText "`tDoes this account need to have MFA enabled? [", 'Y', '/', 'N', ']' -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
if (($mfaCheck).ToUpper() -ne 'Y') {
    Write-Host "`tMFA status not saved" -ForegroundColor Red
    $script:mfaStatus = $false
} else {
    $script:mfaStatus = $true
}
}
function Export-Credential {
Write-Host "`tSaving to environment variables ..." -ForegroundColor Yellow
# Save Username
if ($script:microsoftCredential.Username.Length -eq 0) {
    Write-Host 'Username is blank - skipping save' -ForegroundColor Yellow
    $userSaved = $false
    $userSavedColor = 'Red'
} else {
    $encryptedUser = $script:microsoftCredential.Username | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString #Saves User as numbers
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $encryptedUser, [System.EnvironmentVariableTarget]::User)
    $userSaved = $true
    $userSavedColor = 'Green'
}
Write-Host "`tUser Saved:$($userSaved)" -ForegroundColor $userSavedColor
# Save Password
if ($script:microsoftCredential.Password.Length -eq 0) {
    Write-Host 'Password is blank - skipping save' -ForegroundColor Yellow
    $passwordSaved = $false
    $passwordSavedColor = 'Red'
} else {
    #DEBUG $script:microsoftCredential = Get-Credential
    $encryptedPass = ConvertFrom-SecureString $script:microsoftCredential.Password
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $encryptedPass, [System.environmentVariableTarget]::User)
    $passwordSaved = $true
    $passwordSavedColor = 'Green'
}
Write-Host "`tPassword Saved: $($passwordSaved)" -ForegroundColor $passwordSavedColor
Invoke-AddMFA
Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
}
function Import-MFAStatus {
$script:mfaStatus = Test-Path env:microsoftConnectionMFA
}
function Invoke-AddMFA() {
# Save MFA Status
$script:mfaStatus = $true
if ($script:mfaStatus -eq $true) {
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
    $script:mfaStatus = $true
    $mfaSavedColor = 'Green'
    $mfaSaved = $true
} else {
    Write-Host 'MFS status is blank - skipping save'
    $mfaSaved = $false
    $mfaSavedColor = 'Red'
}
Write-Host "`tMFA Saved: $($mfaSaved)" -ForegroundColor $mfaSavedColor
}

function Clear-MFA() {
[Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $null, 'User')
$script:mfaStatus = $false
}
function Import-Credential {
$script:microsoftUser = $null
$script:microsoftPass = $null
$script:microsoftCredential = $null
# Check for saved username
if (Test-Path env:microsoftConnectionUser) {
    $script:microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto( [Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString ($env:microsoftconnectionUser))))
}
# Check for saved password
if (Test-Path env:microsoftConnectionPass) {
    $script:microsoftPass = ConvertTo-SecureString ($env:microsoftConnectionPass)
    $script:microsoftCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $script:microsoftUser, $script:microsoftPass
}

}
Function Invoke-ConnectedServiceCheck {
$script:alreadyConnected = 0
# [Parameter(Mandatory)]$serviceName
# Only check for connections if there's been service connected already
if ($script:connectedServices.Length -ne 0 ) {
    if ($script:connectedServices.ToLower().Contains($serviceName.ToLower())) {
        Write-ColoredText $serviceName, ' is already connected.' -Color Yellow, $foregroundColor
        $script:alreadyConnected = 1
    }
}
}
#TODO Add a check for updated module if it's already insatlled
function Invoke-ModuleCheck {
# [String]$moduleName
if (!(Get-Module -Name $moduleName -ListAvailable)) {
    Write-ColoredText "`tModule ", $moduleName, ' is missing.' -Color $foregroundColor, Yellow, $foregroundColor
    # $Prompt = "`t`tInstall [Y/N]"
    $installPrompt = $(Write-ColoredText "`t`tInstall? [", 'Y', '/', 'N', ']' -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
    If ($installPrompt.ToUpper() -ne 'Y') {
        Write-ColoredText "`tModule ", $moduleName, ' not installed.' -Color $foregroundColor, Yellow, $foregroundColor
        break
    }
    Get-IsAdministrator
    if ($script:isAdmin -eq $true) {
        Install-ModuleFromGallery -Module $moduleName
    } else {
        Write-Error "`tLoad PowerShell as administrator in order to install modules"
        break
    }
}
}
function debugModule {
$serviceName = $MyInvocation.MyCommand.Name
Invoke-ConnectedServiceCheck $serviceName
try {
    Invoke-UpdateConnectedService $serviceName
} catch {
    Write-Warning "Unable to connect to $($MyInvocation.MyCommand.Name)"
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function debugModule2 {
$serviceName = $MyInvocation.MyCommand.Name
Invoke-ConnectedServiceCheck $serviceName
try {
    Invoke-UpdateConnectedService $serviceName
} catch {
    Write-Warning "Unable to connect to $($MyInvocation.MyCommand.Name)"
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function Teams {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'MicrosoftTeams'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        if ($script:mfaStatus) {
            Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
            # Connect with MFA enforced
            Connect-MicrosoftTeams
        } else {
            # Connect without MFA enforced
            Connect-MicrosoftTeams -Credential $script:microsoftCredential
        }
        Invoke-UpdateConnectedService
    }
} catch {
    Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
    foreach ($e in $error[0..2] ) {
        if ($e.Exception.Message.Contains('AADSTS50076:')) {
            Write-Warning "`tMFA error detected"
            Write-ColoredText "`tTry ", 'Invoke-AddMFA', ' and re-run ', $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
        }
    }
}
}
function ExchangeServer {
$serviceName = $MyInvocation.MyCommand.Name
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        $serverFQDN = Read-Host -Prompt 'Enter Exchange Server FQDN: '
        $exchangeServerSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$serverFQDN/PowerShell/ -Authentication Kerberos -Credential $script:microsoftCredential
        Import-PSSession $exchangeServerSession -DisableNameChecking
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning 'Unable to connect to Exchange Service'
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function Exchange {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'ExchangeOnlineManagement'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        # Exchange Online V2 uses modern auth by default and supports MFA
        Connect-ExchangeOnline -UserPrincipalName $script:microsoftCredential.UserName
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning 'Unable to connect to Exchange Online'
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function MSOnline {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'MSOnline'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        # Doesn't appear to be any need for differnt auth types
        Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
        Connect-MsolService -Credential $script:microsoftCredential
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning 'Unable to connect to MSOnline'
    Write-Warning $Error[0]
}
}
function AzureAD {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'AzureAD'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        
        #! 3.9.22 this is causing issues
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        if ($script:mfaStatus) {
            if ($script:microsoftUser) {
                AzureAD\Connect-AzureAD -AccountId $script:microsoftUser
            }
            Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
            AzureAD\Connect-AzureAD
            
        } else {
            AzureAD\Connect-AzureAD -Credential $script:microsoftCredential
        }
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning 'Unable to connect to Azure AD'
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function AzureADPreview {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'AzureADPreview'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        if ($script:mfaStatus) {
            if ($script:microsoftUser) {
                AzureADPreview\Connect-AzureAD -AccountId $script:microsoftUser
            }
            Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
            AzureADPreview\Connect-AzureAD
        } else {
            AzureADPreview\Connect-AzureAD -Credential $script:microsoftCredential
        }
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning 'Unable to connect to Azure AD'
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function SharePoint {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'Microsoft.Online.SharePoint.PowerShell'
try {
    Invoke-ConnectedServiceCheck $serviceName
    # Check if module is installed
    if ($script:alreadyConnected -eq 0) {
        Invoke-ModuleCheck -moduleName $moduleName
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        Write-Host "`tEnter your SharePoint organization name below:" -ForegroundColor Yellow
        $orgName = $(Write-ColoredText "`tExample: ", 'https://', 'tenantname', '-admin.sharepoint.com' -Color Yellow, $foregroundColor, Green, $foregroundColor; Read-Host)
        # Check for and remove -admin
        if ($orgname -like '*-admin') {
            $orgname = $orgName.split('-')[0]
        }
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com
        } else {
            # Connect without MFA enforced
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $script:microsoftCredential
        }
        Invoke-UpdateConnectedService $serviceName
    }
    
} catch {
    Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
    Write-Warning 'Ensure that MFA is not required.'
    foreach ($e in $error[0..2] ) {
        if ($e.Exception.Message.Contains('AADSTS50076:')) {
            Write-Warning "`tMFA error detected"
            Write-ColoredText "`tTry ", 'Invoke-AddMFA', ' and re-run ', $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
        }
    }
}
}
function Security_Compliance {
$serviceName = $MyInvocation.MyCommand.Name
$moduleName = 'ExchangeOnlineManagement'
try {
    Invoke-ConnectedServiceCheck $serviceName
    if ($script:alreadyConnected -eq 0) {
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-IPPSSession -UserPrincipalName $script:microsoftCredential.Username
        } else {
            # Connect without MFA enforced
            Connect-IPPSSession -UserPrincipalName $script:microsoftCredential
        }
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
    foreach ($e in $error[0..2] ) {
        if ($e.Exception.Message.Contains('AADSTS50076:')) {
            Write-Warning "`tMFA error detected"
            Write-ColoredText "`tTry ", 'Invoke-AddMFA', ' and re-run ', $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
        }
    }
}
}
function Intune {
$serviceName = $MyInvocation.MyCommand.Name
Invoke-ConnectedServiceCheck $serviceName
$moduleName = 'Microsoft.Graph.Intune'
try {
    if ($script:alreadyConnected -eq 0) {
        # Loading MSonline before Intune can cause issues
        if ($script:connectedServices -contains 'MSOnline') {
            Write-ColoredText "`t*************", "`t`nImporting the MSOnline cmdlets before importing this Intune module will cause errors. Please use the AzureAD module instead, as the MSOnline module is deprecated.
            If you absolutely must use the MSOnline module, it should be imported AFTER the Intune module. Note, however, that this is not officially supported. More info available here:", "https://github.com/Microsoft/Intune-PowerShell-SDK`n", "`t*************" -Color Yellow, $foregroundColor, Cyan, Yellow
        }
        # Check if module is installed
        Invoke-ModuleCheck -moduleName $moduleName
        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
        # Not sure if this will allow for MFA and not
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-MSGraph
        } else {
            # Connect without MFA enforced
            Connect-MSGraph -PSCredential $script:microsoftCredential
        }
        Invoke-UpdateConnectedService $serviceName
    }
} catch {
    Write-Host "`tGraph Connection Failed" -ForegroundColor Yellow
    Write-Host "`tYou may need to connect with 'Connect-MSGraph -AdminConsent'" -ForegroundColor Yellow
    Write-Host "`tMore Info: https://github.com/Microsoft/Intune-PowerShell-SDK" -ForegroundColor Yellow
    Write-Warning 'Unable to connect to Intune'
    Write-Warning $Error[0]
    Write-Warning 'Ensure that MFA is not required.'
}
}
function disconnect {
foreach ($service in $script:connectedServices) {
    Switch ($service) {
        'Teams' {
            Disconnect-MicrosoftTeams
        }
        'ExchangeServer' {
            Remove-PSSession $exchangeServerSession
        }
        'Exchange' {
            Get-PSSession | Remove-PSSession
        }
        'MSOnline' {
            [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
        }
        'AzureAD' {
            Disconnect-AzureAD
        }
        'SharePoint' {
            Disconnect-SPOService
        }
        'Security_Compliance' {
            Disconnect-ExchangeOnline
        }
        'Intune' {
            # No documented way to disconnect
        }
    }
    $script:joinedServices = $script:connectedServices | Where-Object { $_ -NE $service }
    Write-Host 'Disconnected Service: ' $($service) -ForegroundColor Yellow
}
$script:connectedServices = @()
$function:prompt = & { $script:userPrompt }
}

# Run these on startup
# Check for the -Install switch
$script:installCommand = "Import-Module $($PSCommandPath) -Force" # this wouldn't be necessary if the it's created as a module
if ($install.IsPresent) {
# Create a profile if it doesn"t exist already
if (!(Test-Path -Path $Profile)) {
    New-Item -ItemType File -Path $Profile -Force
}
if ((Get-Content $Profile | Select-String -Pattern ( [regex]::Escape($script:installCommand))).Matches.Success) {
    Write-ColoredText "`tProfile is already installed" -Color Red
    break
} else {
    Add-Content $Profile -Value ($script:installCommand)
    Write-ColoredText -Text 'Added command ', $script:installCommand, " to $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
    exit
}
}
if ($uninstall.IsPresent) {
if ((Get-Content $Profile | Select-String -Pattern ( [regex]::Escape($script:installCommand))).Matches.Success) {
    (Get-Content $Profile).Replace(($script:installCommand), '') | Set-Content $Profile
    Clear-Account
    Clear-MFA
    Write-ColoredText -Text 'Removed ', $script:installCommand, " from $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
    break
} else {
    Write-ColoredText "`tProfile is not installed" -Color Red
    break
}
}

# Import profile settings
Invoke-ProfileStart