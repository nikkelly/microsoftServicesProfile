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
function Write-Color([String[]]$Text, [ConsoleColor[]]$Color) {
    for ($i = 0; $i -lt $Text.Length; $i++) {
        Write-Host $Text[$i] -Foreground $Color[$i] -NoNewline
    }
    Write-Host
}

function Invoke-DisplayCommands {
    Write-Host "`nConnect to Microsoft online services with these commands: " -ForegroundColor Green
    Write-Host "Teams | ExchangeServer | Exchange | MSOnline (AAD V1) | AzureAD (AAD V2) | SharePoint | Security_Compliance | Intune | connectAll | Disconnect`n" -ForegroundColor Yellow
    Write-Host "Manage Account Credentials with: " -ForegroundColor Green
    Write-Host "Remove-Account | Add-MFA | Remove-MFA `n" -ForegroundColor Yellow
    Write-Host "Helpful Variables" -ForegroundColor Green
    Write-Color '$microsoftUser = ', $microsoftUser -Color Yellow, White
    Write-Color '$domain = ', $domain - Color Yellow, White
    Write-Color 'Re-display commands with: ', 'Invoke-DisplayCommands' -Color Green, White
}
function Import-Domain {
    # Split the domain from $microsoftUser
    if ($microsoftUser) {
        $domain = $microsoftUser.Split('@') | Select-Object -Last 1
    } else {
        $domain = $null
    }
    return $domain
}
function Set-Domain {
    $domain = Read-Host "Enter your domain:"
    if ($domain.Length -eq 0) {
        Write-Host "Domain cannot be blank."
        $domain = $null
        Exit
    }
    return $domain
}
# [X] remove the environment variable
function Remove-Account {
    # Delete environment variable 
    if ([Environment]::GetEnvironmentVariable('microsoftConnectionUser', 'User')) {
        [Environment]::SetEnvironmentVariable("microsoftConnectionUser", $null, "User")
    } 
    if ([Environment]::GetEnvironmentVariable('microsoftConnectionPass', 'User')) {
        [Environment]::SetEnvironmentVariable("microsoftConnectionPass", $null, "User")
    } 
    
    if ([Environment]::GetEnvironmentVariable('microsoftConnectionMfa', 'User')) {
        [Environment]::SetEnvironmentVariable("microsoftConnectionMfa", $null, "User")
    } 
    $microsoftUser = $null
    $microsoftPass = $null
    $mfaStatus = $null
    return $microsoftUser, $microsoftPass, $mfaStatus
}
function Invoke-DisplayAccount {
    [Parameter(Mandatory)]$microsoftUser
    [Parameter(Mandatory)][String]$microsoftPass
    Write-Color "Account: ", $microsftUser -Color White, Green
    Write-Color "Password Imported: ", $microsoftPass -Color White, Green
    Write-Color "Domain: ", $domain -Color White, Green
}
Function Get-IsAdministrator {
    <#
        Determine if the script is running in the context of an administrator or not
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
# Not currently used, need to add remediation logic
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
#             Write-Color "Module ", $m, " is missing." -Color White, Yellow, White
#             $missingModules += $m
#         }
#     }
#     if ($missingModules.length -gt 0) {
#         $Prompt = "$($missingModules.length) Modules are missing. Install [Y/N]"
#         $Answer = Read-Host -Prompt $Prompt
#         If ($answer.ToUpper() -ne "Y") {
#             break
#         }
#         if (Get-IsAdministrator -eq $True) {
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
    # These functions should run on ever new profile load 
    Import-ProfileSettings
    Invoke-DisplayAccount
    Invoke-DisplayCommands
    # Initialize Variabels that may be used later 
    $connectedServices = @()
    return $connectedServices
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
    $microsoftCredential = Get-Credential
    return $microsoftCredential
}
# [X] Save credentials to environment variables
function Export-Credentials {
    Param (
        [Parameter(Mandatory)][SecureString]$microsoftCredential
    )
    # Save Username
    if ($microsoftCredential.Username.Length -eq 0) {
        Write-Host "Username is blank - skipping save" -ForegroundColor Yellow
    } else {
        $encryptedUser = $microsoftCredential.Username | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString #Saves User as numbers 
        [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $encryptedUser, [System.EnvironmentVariableTarget]::User)
    }
    # Save Password
    if ($microsoftCredential.Password.Length -eq 0) {
        Write-Host "Password is blank - skipping save" -ForegroundColor Yellow
    } else {
        $microsoftCredential = Get-Credential
        $encryptedPass = ConvertFrom-SecureString $microsoftCredential.Password 
        [Sustem.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $encryptedPass, [System.environmentVariableTarget]::User)
    }
    Write-Host "`tPlease reload PowerShell for changes to take effect." -ForegroundColor Green
}
# [X] Check MFA Status
function Import-MFAStatus { 
    # Check for saved password
    if (-not [Environment]::GetEnvironmentVariable('microsoftConnectionMfa', 'User')) {
        "Microsoft connection MFA status not found."
        $mfaStatus = false
    } else {
        $mfaStatus = True
    }
    return $mfaStatus
}
function Add-MFA() {
    Write-Host "Saving MFA settings to environment variable"
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
    $mfaStatus = True
    return $mfaStatus
}
  
function Remove-MFA() {
    [Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
    $mfaStatus = False 
    return $mfaStatus
}

#! 2.22 broken [X] Load credentials 
function Import-Credentials {
    
    #! Debug start
    # Check for saved username
    if (-not [Environment]::GetEnvironmentVariable('microsoftConnectionUser', 'User')) {
        "Microsoft connection user not found."
    } else {
        $microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString ($env:microsoftconnectionUser))))
    }
    # Check for saved password
    if (-not [Environment]::GetEnvironmentVariable('microsoftConnectionPass', 'User')) {
        "Microsoft connection password not found."
    } else {
        $microsoftPass = ConvertTo-SecureString ($env:microsoftConnectionPass)
        $microsoftCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $microsoftUser, $microsoftPass
        return $microsoftCredential
    }
    #! Debug End 
    # #NOTE 3.3.22 code below is working
    # # Load User
    # $microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((ConvertTo-SecureString ($env:microsoftconnectionUser))))
    # # Load Password
    # try {
    #     $microsoftPass = ConvertTo-SecureString ($env:microsoftConnectionPass)
    #     $microsoftCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $microsoftUser, $microsoftPass
    #     return $microsoftCredential
    # } catch {
    #     #! need to handle blank password and blank username
    # }
}

Function Invoke-ConnectedServiceCheck {
    [Parameter(Mandatory)]$serviceName
    if ($connectedServices.ToLower().Contains($serviceName)) {
        Write-Color $serviceName, " is already connected." -Color Yellow, White
        break
    }
}

#TODO Add a check for updated module if it's already insatlled
function Invoke-ModuleCheck {
    [Parameter(Mandatory)]$moduleName
    if (!(Get-Module -Name $moduleName -ListAvailable)) {
        Write-Color "Module ", $moduleName, " is missing." -Color White, Yellow, White
        $Prompt = "Install [Y/N]"
        $Answer = Read-Host -Prompt $Prompt
        If ($answer.ToUpper() -ne "Y") {
            Write-Color "Module ", $moduleName, " not installed." -Color White, Yellow, White
            break
        }
        if (Get-IsAdministrator -eq $True) {
            Install-ModuleFromGallery -Module $moduename
        } else {
            Write-Error "Load PowerShell as administrator in order to install modules"
            break
        }
    }
}

# [ ] Individual Service connection commands
# [X] Teams 
function Teams { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    # Check if module is installed
    Invoke-ModuleCheck('MicrosoftTeams')
    try {
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-MicrosoftTeams
            $connectedServices += 'Teams'

        } else { 
            # Connect without MFA enforcedd
            Connect-MicrosoftTeams -Credential $microsoftCredential
        }
        return $connectedServices
    } catch {
        Write-Warning 'Unable to connect to Teams'
        Write-Warning $Error[0]
    }
}
# [X]
function ExchangeServer { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    try {
        $serverFQDN = Read-Host -Prompt "Enter Exchange Server FQDN: "
        $exchangeServerSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$serverFQDN/PowerShell/ -Authentication Kerberos -Credential $microsoftCredential
        Import-PSSession $exchangeServerSession -DisableNameChecking  
        $connectedServices += 'ExchangeServer'

    } catch {
        Write-Warning 'Unable to connect to Exchnage Service'
        Write-Warning $Error[0]
    }
    return $connectedServices
}
function Exchange { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    # Check if module is installed
    Invoke-ModuleCheck('ExchangeOnlineManagement')
    try {
        # Exchange Online V2 uses modern auth by default and supports MFA
        Connect-ExchangeOnline -UserPrincipalName $microsoftCredential.UserName
        $connectedServices += 'Exchange'

    } catch {
        Write-Warning 'Unable to connect to Exchange Online'
        Write-Warning $Error[0]
    }
    return $connectedServices
}
function MSOnline { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name) 
    # Check if module is installed
    Invoke-ModuleCheck('MSOnline')
    try {
        # Doesn't appear to be any need for differnt auth types
        Connect-MsolService -Credential $microsoftCredential
        $connectedServices += 'MSOnline'

    } catch {
        Write-Warning 'Unable to connect to MSOnline'
        Write-Warning $Error[0]
    }
    return $connectedServices
}
function AzureAD { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    Invoke-ModuleCheck('AzureAD')
    try {
        Connect-AzureAD -Credential $microsoftCredential
        $connectedServices += 'AzureAD'
        
    } catch {
        Write-Warning 'Unable to connect to Azure AD'
        Write-Warning $Error[0]
    }
    return $connectedServices
}

#! 3.5.22 left off here
function SharePoint { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    Invoke-ModuleCheck('Microsoft.Online.SharePoint.PowerShell')
    try {
        $orgName = Read-Host -Prompt "Enter your SharePoint organization name" 
        Write-Color "Example: ", "https://", "tenantname", "-admin.sharepoint.com" -Color Yellow, White, Green, White
        # Check for and remove -admin
        if ($orgname -like '*-admin') {
            $orgname = $orgName.split('-')[0]
        }
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com
        } else { 
            # Connect without MFA enforced
            Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $microsoftCredential
        }
        $connectedServices += 'SharePoint'
    } catch {
        Write-Warning 'Unable to connect to SharePoint'
        Write-Warning $Error[0]
    }
    return $connectedServices
}
function Security_Compliance { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    Invoke-ModuleCheck('ExchangeOnlineManagement')
    try {
        if ($script:mfaStatus) {
            # Connect with MFA enforced
            Connect-IPPSSession -UserPrincipalName $microsoftCredential.Username
        } else { 
            # Connect without MFA enforced
            Connect-IPPSSession -UserPrincipalName $microsoftCredential
        }
        $connectedServices += 'Security_Compliance'
    } catch {
        Write-Warning 'Unable to connect to Teams'
        Write-Warning $Error[0]
    }
    return $connectedServices
}
function Intune { 
    # Check $connectedServices
    Invoke-ConnectedServiceCheck($MyInvocation.MyCommand.Name)
    # Check if module is installed
    Invoke-ModuleCheck('Microsoft.Graph.Intune')
    if ($connectedServices -contains 'MSOnline'){
        Write-Color "*************","Importing the MSOnline cmdlets before importing this Intune module will cause errors. Please use the AzureAD module instead, as the MSOnline module is deprecated.
        If you absolutely must use the MSOnline module, it should be imported AFTER the Intune module. Note, however, that this is not officially supported. More info available here:","https://github.com/Microsoft/Intune-PowerShell-SDK","*************" -Color Yellow,White,Cyan,Yellow
    }
    try {
        Connect-MSGraph PSCredential $microsoftCredential        
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
    return $connectedServices
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

            }

        }
        $connectedServices = $connectedServices | Where-Object { $_ -NE $service }
        Write-Host "Disconnected Service: " $($service) -ForegroundColor Yellow
    }
    $connectedServices = @()
    return $connectedServices
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
        Break
    } else {
        Add-Content $Profile -Value ($installCommand)
        Write-Color -Text "Added command ", $installCommand, " to $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color White, Yellow, White, Green
        exit
    }
}
if ($uninstall.IsPresent) {
    if ((Get-Content $Profile | Select-String -Pattern ([regex]::Escape($installCommand))).Matches.Success) {
    (Get-Content $Profile).Replace(($installCommand), "") | Set-Content $Profile
        Write-Color -Text "Removed ", $installCommand, " from $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color White, Yellow, White, Green
        break
    } else {
        Write-Color "`tProfile is not installed" -Color Red
        break
    }
}

# Import profile settings
Start-Profile
