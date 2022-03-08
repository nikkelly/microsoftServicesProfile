<#
TODO 
https://curi0usjack.blogspot.com/2017/08/creating-self-updating-powershell.html
- force version checking to make sure the user is using the latest version of the script
- notify if a new version is avaialble 
https://docs.microsoft.com/en-us/powershell/scripting/gallery/concepts/publishing-guidelines?view=powershell-7.2
https://docs.microsoft.com/en-us/powershell/module/psscriptanalyzer/?view=ps-modules
- run the script analyzer to make sure it's adhering to best practices
- publish a version to PSGallery? 
list dependencies and track them
- all the different modules 
https://docs.microsoft.com/en-us/powershell/scripting/developer/module/how-to-write-a-powershell-script-module?view=powershell-7.2
- make it a powershell module 
# microsoftServicesProfile.ps1
  .SYNOPSIS
    Connect to Microsoft 365 services with a single command.
  .DESCRIPTION 
    https://github.com/nikkelly/microsoftServicesProfile
  .PREREQUISITES
    Set-ExeuctionPolicy RemoteSigned
    
#>

param (
    [Switch]$install,
    [Switch]$uninstall
)

$version = "2.0"
$foregroundColor = $host.UI.RawUI.ForegroundColor

function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
    for ($i = 0; $i -lt $Text.Length; $i++) {
        Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
    }
    Write-Host
}

function Invoke-DisplayCommands {
    Write-Host "`nConnect to Microsoft online services with these commands: " -ForegroundColor Green
    Write-Host "Teams | ExchangeServer | Exchange | MSOnline (AAD V1) | AzureAD (AAD V2) | AzureADPreview | SharePoint | Security_Compliance | Intune | connectAll | Disconnect`n" -ForegroundColor Yellow
    Write-Host "Manage Account Credentials with: " -ForegroundColor Green
    Write-Host "Add-Account | Remove-Account | Add-MFA | Remove-MFA `n" -ForegroundColor Yellow
    Write-Host "Helpful Variables" -ForegroundColor Green
    if ($null -eq $script:microsoftUser) {
        Write-Color '$microsoftUser = ', 'Not set' -Color Yellow, $foregroundColor
    } else {
        Write-Color '$microsoftUser = ', $script:microsoftUser -Color Yellow, $foregroundColor

    }
    if ($null -eq $script:domain) {
        Write-Color '$domain = ', "Not set" -Color Yellow, $foregroundColor
    } else {
        Write-Color '$domain = ', $script:domain -Color Yellow, $foregroundColor
    }
    Write-Color "`nRe-display commands with: ", 'Invoke-DisplayCommands' -Color Green, $foregroundColor
}
function Import-Domain {
    # Split the domain from $script:microsoftUser
    if ($script:microsoftUser) {
        $script:domain = $script:microsoftUser.Split('@') | Select-Object -Last 1
    } else {
        $script:domain = $null
    }
    # return $script:domain
}
function Set-Domain {
    $script:domain = Read-Host "Enter your domain:"
    if ($script:domain.Length -eq 0) {
        Write-Host "Domain cannot be blank."
        $script:domain = $null
        Exit
    }
    # return $script:domain
}
function Add-Account {
    Get-Credentials
    if (($script:blankPassword -eq $true) -or ($script:blankUser -eq $true)) {
        Write-Warning "One of your credentials is blank - please verify this is intended."
    }
    $saveCreds = $(Write-Color "`tWould you like to save this account for later? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
    if ($saveCreds.ToUpper() -ne "Y") {
        Write-Host "`tCredentials not saved" -ForegroundColor Red
    } else {
        try {
            Export-Credentials $script:microsoftCredential
            # Write-Host "`tCredentials saved to environment variables" -ForegroundColor Yellow
        } catch {
            Write-Warning "Unable to add account"
            Write-Warning $Error[0]
        }
    }
}
# [X] remove the environment variable
function Remove-Account {
    # Delete environment variable 
    try {
        if (Test-Path env:microsoftConnectionUser) {
            [Environment]::SetEnvironmentVariable("microsoftConnectionUser", $null, "User")
            Write-Color "`tMicrosoft connection user removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally blank
    } 
    try {
        if (Test-Path env:microsoftConnectionPass) {
            [Environment]::SetEnvironmentVariable("microsoftConnectionPass", $null, "User")
            Write-Color "`tMicrosoft connection password removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally Blank
    }
    try { 
        if (Test-Path env:microsoftConnectionMFA) {
            [Environment]::SetEnvironmentVariable("microsoftConnectionMfa", $null, "User")
            Write-Color "`tMicrosoft connection MFA removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally Blank
    }
    $script:microsoftUser = $null
    $script:microsoftPass = $null
    $script:mfaStatus = $null
    $script:domain = $null
    # return $script:microsoftUser, $script:microsoftPass, $script:mfaStatus
}
function Invoke-DisplayAccount {
    $script:microsoftPassLoaded = $false
    $script:microsoftUserLoaded = $false
    if ($null -eq $script:microsoftUser) {
        Write-Color "Account Imported: ", $script:microsoftUserLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftUserLoaded = $True
        Write-Color "Account Imported: ", $script:microsoftUserLoaded -Color $foregroundColor, Green
    }
    if ($null -eq $script:microsoftPass) {
        Write-Color "Password Imported: ", $script:microsoftPassLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftPassLoaded = $True
        Write-Color "Password Imported: ", $script:microsoftPassLoaded -Color $foregroundColor, Green
    }

}
Function Get-IsAdministrator {
    <#
        Determine if the script is running in the context of an administrator or not
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Not currently used, need to add remediation logic
# Need to check if there's an updated version, and then use this to remove the old one
Function Uninstall-OldModules {
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
                    # Some code needs to be placed here to catch possible error.
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
# [X] Check if all modules are installed, if not prompt user for install
# How to use it? where can i save persistant variables
# Need to split this into two diffent functions 
# 1/2 is in Invoke-ModuleCheck
# 2/2 should install all modules 

# function Invoke-ModuleCheck-OLD {
#     $requiredModules = @(
#         "MicrosoftTeams",
#         "AzureAD",
#         "ExchangeOnlineManagement",
#         "Microsoft.Online.SharePoint.PowerShell",
#         "MSOnline",
#         "ExchangeOnlineManagement",
#         "Microsoft.Graph.Intune"
#     )
#     $missingModules = @()
#     foreach ($m in $requiredModules) {
#         if (!(Get-Module -Name $m -ListAvailable)) {
#             Write-Color "Module ", $m, " is missing." -Color $foregroundColor, Yellow, $foregroundColor
#             $missingModules += $m
#         }
#     }
#     if ($missingModules.length -gt 0) {
#         $Prompt = "$($missingModules.length) Modules are missing. Install [Y/N]"
#         $Answer = Read-Host -Prompt $Prompt
#         If ($answer.ToUpper() -ne "Y") {
#             break
#         }
#         if (Get-IsAdministrator -eq $true) {
#             foreach ($missing in $missingModules) {
#                 Install-ModuleFromGallery -Module $missing
#             }
#         } else {
#             Write-Error "Load PowerShell as administrator in order to install modules"
#         }
#     }
# }
# [ ] Add All service functions here
function connectAll {
    Teams
    Exchange
    SharePoint
    Security_Compliance
    AzureAD
    MSOnline
    exchangeServer
    Intune
}
# [X] Run import function when the profile loads 
function Import-ProfileSettings {
    Import-MFAStatus
    Import-Credentials
    Import-Domain
}
function Start-Profile {
    # These functions will run on ever new profile load 
    # Clear-Host
    Write-Color "--==Microsoft Services Profile v", $($version), " loaded==--" -Color Yellow, Green, Yellow
    Import-ProfileSettings
    Invoke-DisplayAccount
    Invoke-DisplayCommands
    # Initialize Variabels that may be used later 
    $connectedServices = @()
    # return $connectedServices
}
# [X] Ammend the current prompt
function Update-Prompt {
    $function:prompt = & {
        $__last_prompt = $function:prompt
        { & $script:__last_prompt
            Write-Host $($connectedServices) -NoNewline -ForegroundColor Yellow
        }.GetNewClosure()
    }
}
# [X] Prompt user for credentials
function Get-Credentials {
    Write-Host "`tPrompting user for credential input" -ForegroundColor Yellow
    $script:microsoftCredential = Get-Credential -Message "Enter your admin account credentials"
    if ($script:microsoftCredential.Username.Length -eq 0) {
        Write-Host "Username is blank" -ForegroundColor Yellow
        $script:blankUsername = $true
    } else {
        $script:blankUsername = $false
    }
    if ($script:microsoftCredential.Password.Length -eq 0) {
        Write-Host "Password is blank" -ForegroundColor Yellow
        $script:blankPassword = $true
    } else {
        $script:blankPassword = $false
    }
}
# [X] Save credentials to environment variables
function Export-Credentials {
    Param (
        [Parameter(Mandatory)]$script:microsoftCredential
    )
    Write-Host "`tSaving Variables ..." -ForegroundColor Yellow
    # Save Username
    if ($script:microsoftCredential.Username.Length -eq 0) {
        Write-Host "Username is blank - skipping save" -ForegroundColor Yellow
        $userSaved = $false
        $userSavedColor = "Red"
    } else {
        $encryptedUser = $script:microsoftCredential.Username | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString #Saves User as numbers 
        [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $encryptedUser, [System.EnvironmentVariableTarget]::User)
        $userSaved = $true
        $userSavedColor = "Green"
    }
    Write-Host "`tUser Saved:$($userSaved)" -ForegroundColor $userSavedColor
    # Save Password
    if ($script:microsoftCredential.Password.Length -eq 0) {
        Write-Host "Password is blank - skipping save" -ForegroundColor Yellow
        $passwordSaved = $false
        $passwordSavedColor = "Red"
    } else {
        #DEBUG $script:microsoftCredential = Get-Credential
        $encryptedPass = ConvertFrom-SecureString $script:microsoftCredential.Password 
        [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $encryptedPass, [System.environmentVariableTarget]::User)
        $passwordSaved = $true  
        $passwordSavedColor = "Green"
    }
    Write-Host "`tPassword Saved: $($passwordSaved)" -ForegroundColor $passwordSavedColor
    Write-Host "`n`tPlease reload PowerShell for changes to take effect.`n" -ForegroundColor Green
}
# [X] Check MFA Status
function Import-MFAStatus { 
    # Check for saved password
    # if (-not [Environment]::GetEnvironmentVariable('microsoftConnectionMfa', 'User')) {
    #     "Microsoft connection MFA status not found."
    #     $script:mfaStatus = $false
    # } else {
    #     $script:mfaStatus = $true
    # }
    $script:mfaStatus = Test-Path env:microsoftConnectionMFA
    # return $script:mfaStatus
}
function Add-MFA() {
    Write-Host "Saving MFA settings to environment variable"
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
    $script:mfaStatus = $true
    # return $script:mfaStatus
}
  
function Remove-MFA() {
    [Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
    $script:mfaStatus = $false 
    # return $script:mfaStatus
}

#! 2.22 broken [X] Load credentials 
function Import-Credentials {
    $script:microsoftUser = $null
    $script:microsoftPass = $null
    $script:microsoftCredential = $null
    #! Debug start
    # Check for saved username
    if (Test-Path env:microsoftConnectionUser) {
        $script:microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString ($env:microsoftconnectionUser))))
    } 
    # else {
    #     $script:microsoftUser = $null
    # }
    # Check for saved password
    if (Test-Path env:microsoftConnectionPass) {
        $script:microsoftPass = ConvertTo-SecureString ($env:microsoftConnectionPass)
        $script:microsoftCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $script:microsoftUser, $script:microsoftPass
    } 
    # else {
    #     $script:microsoftPass = $null   
    # }
    #! Debug End 
    # #NOTE 3.3.22 code below is working
    # # Load User
    # $script:microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString ($env:microsoftconnectionUser))))
    # # Load Password
    # try {
    #     $script:microsoftPass = ConvertTo-SecureString ($env:microsoftConnectionPass)
    #     $script:microsoftCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $script:microsoftUser, $script:microsoftPass
    #     return $script:microsoftCredential
    # } catch {
    #     #! need to handle blank password and blank username
    # }
    # return $script:microsoftUser, $script:microsoftPass, $script:microsoftCredential
}

Function Invoke-ConnectedServiceCheck {
    [Parameter(Mandatory)]$serviceName
    # Only check for connections if there's been service connected already
    if ($connectedServices.Length -ne 0 ) {
        if ($connectedServices.ToLower().Contains($serviceName)) {
            Write-Color $serviceName, " is already connected." -Color Yellow, $foregroundColor
            break
        }
    }
}

#TODO Add a check for updated module if it's already insatlled
function Invoke-ModuleCheck {
    # [String]$moduleName
    if (!(Get-Module -Name $moduleName -ListAvailable)) {
        Write-Color "`tModule ", $moduleName, " is missing." -Color $foregroundColor, Yellow, $foregroundColor
        # $Prompt = "`t`tInstall [Y/N]"
        $prompt = $(Write-Color "`t`tInstall? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
        $Answer = Read-Host -Prompt $Prompt
        If ($answer.ToUpper() -ne "Y") {
            Write-Color "`tModule ", $moduleName, " not installed." -Color $foregroundColor, Yellow, $foregroundColor
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

# [ ] Individual Service connection commands
# [X] Teams 
function Teams { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    $moduleName = 'MicrosoftTeams'
    try {
    # Check if module is installed

        Invoke-ModuleCheck -moduleName $moduleName
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-MicrosoftTeams
            $connectedServices += 'Teams'

        } else { 
            # Connect without MFA enforcedd
            Connect-MicrosoftTeams -Credential $script:microsoftCredential
        }
        # return $connectedServices
    } catch {
        Write-Warning "Unable to connect to $($MyInvocation.MyCommand.Name)"
        Write-Warning $Error[0]
    }
}
# [X]
function ExchangeServer { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    try {
        $serverFQDN = Read-Host -Prompt "Enter Exchange Server FQDN: "
        $exchangeServerSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$serverFQDN/PowerShell/ -Authentication Kerberos -Credential $script:microsoftCredential
        Import-PSSession $exchangeServerSession -DisableNameChecking  
        $connectedServices += 'ExchangeServer'

    } catch {
        Write-Warning 'Unable to connect to Exchnage Service'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function Exchange { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    $moduleName = 'ExchangeOnlineManagement'
    # Invoke-ModuleCheck('ExchangeOnlineManagement')

    try {
    # Check if module is installed

    Invoke-ModuleCheck -moduleName $moduleName

        # Exchange Online V2 uses modern auth by default and supports MFA
        Connect-ExchangeOnline -UserPrincipalName $script:microsoftCredential.UserName
        $connectedServices += 'Exchange'

    } catch {
        Write-Warning 'Unable to connect to Exchange Online'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function MSOnline { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
   $moduleName = 'MSOnline'
    try {
         # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName

        # Doesn't appear to be any need for differnt auth types
        Connect-MsolService -Credential $script:microsoftCredential
        $connectedServices += 'MSOnline'

    } catch {
        Write-Warning 'Unable to connect to MSOnline'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function AzureAD { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installe
    # Invoke-ModuleCheck('AzureAD')
    $moduleName = 'AzureAD'
    try {
                 # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName
        AzureAD\Connect-AzureAD -Credential $script:microsoftCredential
        $connectedServices += 'AzureAD'
        
    } catch {
        Write-Warning 'Unable to connect to Azure AD'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function AzureADPreview {
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    # Invoke-ModuleCheck('AzureADPreview')
    $moduleName = 'AzureADPreview'
    try {
                     # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName
        AzureADPreview\Connect-AzureAD -Credential $script:microsoftCredential
        $connectedServices += 'AzureADPreview'
        
    } catch {
        Write-Warning 'Unable to connect to Azure AD'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function SharePoint { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    # Invoke-ModuleCheck('Microsoft.Online.SharePoint.PowerShell')
    $moduleName = 'Microsoft.Online.SharePoint.PowerShell'
    try {
                     # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName
        $orgName = Read-Host -Prompt "Enter your SharePoint organization name" 
        Write-Color "Example: ", "https://", "tenantname", "-admin.sharepoint.com" -Color Yellow, $foregroundColor, Green, $foregroundColor
        # Check for and remove -admin
        if ($orgname -like '*-admin') {
            $orgname = $orgName.split('-')[0]
        }
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com
        } else { 
            # Connect without MFA enforced
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $script:microsoftCredential
        }
        $connectedServices += 'SharePoint'
    } catch {
        Write-Warning 'Unable to connect to SharePoint'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function Security_Compliance { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    # Invoke-ModuleCheck('ExchangeOnlineManagement')
    $moduleName = 'ExchangeOnlineManagement'
    try {
                            # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-IPPSSession -UserPrincipalName $script:microsoftCredential.Username
        } else { 
            # Connect without MFA enforced
            Connect-IPPSSession -UserPrincipalName $script:microsoftCredential
        }
        $connectedServices += 'Security_Compliance'
    } catch {
        Write-Warning 'Unable to connect to Teams'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}
function Intune { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    # Invoke-ModuleCheck('Microsoft.Graph.Intune')
    $moduleName = 'Microsoft.Graph.Intune'
    # Loading MSonline before Intune can cause issues
    if ($connectedServices -contains 'MSOnline') {
        Write-Color "*************", "Importing the MSOnline cmdlets before importing this Intune module will cause errors. Please use the AzureAD module instead, as the MSOnline module is deprecated.
        If you absolutely must use the MSOnline module, it should be imported AFTER the Intune module. Note, however, that this is not officially supported. More info available here:", "https://github.com/Microsoft/Intune-PowerShell-SDK", "*************" -Color Yellow, $foregroundColor, Cyan, Yellow
    }
    try {
                                    # Check if module is installed
    Invoke-ModuleCheck -moduleName $moduleName
        Connect-MSGraph PSCredential $script:microsoftCredential        
        # Not sure if this will allow for MFA and not 
        # if ($script:mfaStatus) {
        #     # Connect with MFA enforced
            
        # } else { 
        #     # Connect without MFA enforced
        # }
        $connectedServices += 'Intune'
    } catch {
        Write-Host Graph Connection Failed
        Write-Host You may need to connect with /'Connect-MSGraph -Consent'/
        Write-Host More Info: https://github.com/Microsoft/Intune-PowerShell-SDK
        Write-Warning 'Unable to connect to Intune'
        Write-Warning $Error[0]
    }
    # return $connectedServices
}

#! End specific service connection functions
function disconnect {
    foreach ($service in $connectedServices) {
        Switch ($service) {
            "Teams" { 
                Disconnect-MicrosoftTeams
            }
            "ExchangeServer" {
                Remove-PSSession $exchangeServerSession
            }
            "Exchange" { 
                Get-PSSession | Remove-PSSession
            }
            "MSOnline" {
                [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
            }
            "AzureAD" { 
                Disconnect-AzureAD
            }
            "SharePoint" { 
                Disconnect-SPOService
            }
            "Security_Compliance" { 
                Disconnect-ExchangeOnline
            }
            "Intune" { 
# No documented way to disconnect
#TODO is there a catchall command for disconnect-msgraph? 
            }

        }
        $connectedServices = $connectedServices | Where-Object { $_ -NE $service }
        Write-Host "Disconnected Service: " $($service) -ForegroundColor Yellow
    }
    $connectedServices = @()
    # return $connectedServices
}


# Run these on startup
# Check for the -Install switch
$installCommand = "Import-Module $($PSCommandPath) -Force" # this wouldn't be necessary if the it's created as a module
if ($install.IsPresent) {
    # Create a profile if it doesn"t exist already
    if (!(Test-Path -Path $Profile)) {
        New-Item -ItemType File -Path $Profile -Force
    }
    if ((Get-Content $Profile | Select-String -Pattern ([regex]::Escape($installCommand))).Matches.Success) {
        Write-Color "`tProfile is already installed" -Color Red
        break
    } else {
        Add-Content $Profile -Value ($installCommand)
        Write-Color -Text "Added command ", $installCommand, " to $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
        exit
    }
}
if ($uninstall.IsPresent) {
    if ((Get-Content $Profile | Select-String -Pattern ([regex]::Escape($installCommand))).Matches.Success) {
    (Get-Content $Profile).Replace(($installCommand), "") | Set-Content $Profile
        Write-Color -Text "Removed ", $installCommand, " from $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
        break
    } else {
        Write-Color "`tProfile is not installed" -Color Red
        break
    }
}

# Import profile settings
Start-Profile

#! Debug Starting
# Write-Host "Connected Services: " $connectedServices