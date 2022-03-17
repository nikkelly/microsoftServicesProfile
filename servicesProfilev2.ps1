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
    try { Get-Credentials
        if (($script:blankPassword -eq $true) -or ($script:blankUser -eq $true)) {
            Write-Warning "One of your credentials is blank - please verify this is intended."
        } else {
            Get-MFA
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
                    Write-Warning 'Ensure that MFA is not required.'
                }
            }
        }
    } catch { 
        Write-Warning "Unable to add account"
    }
}
# [X] remove the environment variable
function Remove-Account {
    # Delete environment variable 
    try {
        if (Test-Path env:microsoftConnectionUser) {
            [system.Environment]::SetEnvironmentVariable("microsoftConnectionUser", $null, "User")
            $script:microsoftUser = $null
            $script:domain = $null
            $script:microsoftUserLoaded = $false
            Write-Host "`tMicrosoft connection user removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally blank
    } 
    try {
        if (Test-Path env:microsoftConnectionPass) {
            [system.Environment]::SetEnvironmentVariable("microsoftConnectionPass", $null, "User")
            $script:microsoftPass = $null
            $script:microsoftPassLoaded = $false
            Write-Host "`tMicrosoft connection password removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally Blank
    }
    try { 
        if (Test-Path env:microsoftConnectionMFA) {
            [system.Environment]::SetEnvironmentVariable("microsoftConnectionMfa", $null, "User")
            $script:mfaStatus = $null
            Write-Host "`tMicrosoft connection MFA removed" -ForegroundColor Yellow
        } 
    } catch { 
        # Intentionally Blank
    }
    # return $script:microsoftUser, $script:microsoftPass, $script:mfaStatus]
    Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
}
function Invoke-DisplayAccount {
    $script:microsoftUserLoaded = $false
    $script:microsoftPassLoaded = $false
    $script:microsoftMFALoaded = 'Disabled'
    if (($null -eq $script:microsoftUser) -or ($script:microsoftUser -eq $false)) {
        Write-Color "Account Imported: ", $script:microsoftUserLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftUserLoaded = $True
        Write-Color "Account Imported: ", $script:microsoftUserLoaded -Color $foregroundColor, Green
    }
    if (($null -eq $script:microsoftPass) -or ($script:microsoftPass -eq $false)) {
        Write-Color "Password Imported: ", $script:microsoftPassLoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftPassLoaded = $True
        Write-Color "Password Imported: ", $script:microsoftPassLoaded -Color $foregroundColor, Green
    }
    if (($null -eq $script:mfaStatus) -or ($script:mfaStatus -eq $false)) {
        Write-Color "MFA Status: ", $script:microsoftMFALoaded -Color $foregroundColor, Red
    } else {
        $script:microsoftMFALoaded = 'Enabled'
        Write-Color "MFA Status: ", $script:microsoftMFALoaded -Color $foregroundColor, Green
    }
}
Function Get-IsAdministrator {
    <#
        Determine if the script is running in the context of an administrator or not
    #>
    Write-Host "`tChecking for administrative privileges." -ForegroundColor Yellow
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($null -ne $script:isAdmin) {
        Write-Host "`tUser is an admin" -ForegroundColor Green
    }
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
    AzureAD
    AzureADPreview
    Exchange
    ExchangeServer
    Intune
    MSOnline
    SharePoint
    Teams
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
    $script:connectedServices = @()
    Write-Color "--==Microsoft Services Profile v", $($version), " loaded==--" -Color Yellow, Green, Yellow
    # Update-Prompt
    Import-ProfileSettings
    Invoke-DisplayAccount
    Invoke-DisplayCommands
    # Initialize Variabels that may be used later 
    # return $script:connectedServices
}
# Update Connectedservices to display for prompt
function Update-ConnectedServices {
    # use $serviceName 
    # $script:connectedServices = @($script:connectedServices; $serviceName)
    $script:connectedServices += $serviceName
    if ($script:connectedServices.Length -eq 1) {
        #? How can i get color into the prompt?
        $script:joinedServices = "[$script:connectedServices]"
        Update-Prompt
        Write-Host "`tConnected to $serviceName!" -ForegroundColor Green
        # $script:joinedServices = $script:connectedServices -join " | "
        # Write-Color '[', $joinedServices, ']' -Color White, Yellow, White
    } else {
        $script:joinedServices = "[$($script:connectedServices -join "|")]"
        Write-Host "`tConnected to $serviceName!" -ForegroundColor Green
        # if (($script:connectedServices.Length -eq 0)) {
        # $script:joinedServices = Write-Color '[', $script:connectedServices, ']' -Color White, Yellow, White
        # $script:joinedServices = $script:connectedServices # this works
        # $string = Write-Color '[', $script:connectedServices, ']' -Color White, Yellow, White
        # $script:joinedServices = $string
    } 
    # Write-Color '[', $script:connectedServices, ']' -Color White, Yellow, White
}
# [X] Ammend the current prompt
function Update-Prompt {
    # else {
    #     $script:joinedServices = 'test'
    # }
    # $script:count = 0
    # $function:prompt = & {
    #     $__last_prompt = $function:prompt
    #     { & $script:__last_prompt;
    #         Write-Host $script:joinedServices -NoNewline -ForegroundColor Yellow
    #     }.GetNewClosure()
    # }
    $script:userPrompt = $function:prompt
    $function:prompt = & {
        # Write-Host $script:joinedServices -NoNewline
        $__last_prompt = $function:prompt
        { & $script:__last_prompt;
            Write-Host " $($joinedServices) " -NoNewline -ForegroundColor Yellow
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
# [ ] prompt the user for their MFA status
function Get-MFA { 

    $mfaCheck = $(Write-Color "`tDoes this account need to have MFA enabled? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
    if (($mfaCheck).ToUpper() -ne "Y") {
        Write-Host "`tMFA status not saved" -ForegroundColor Red
        $script:mfaStatus = $false
    } else { 
        $script:mfaStatus = $true
    }
}
# [X] Save credentials to environment variables
function Export-Credentials {
    Write-Host "`tSaving to environment variables ..." -ForegroundColor Yellow
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
    Add-MFA
    Write-Host "`n`tPlease close and reopen your PowerShell window for changes to take effect.`n" -ForegroundColor Green
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
    # return $script:mfaStatus
    # Save MFA Status
    $script:mfaStatus = $true
    if ($script:mfaStatus -eq $true) {
        [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
        $script:mfaStatus = $true
        $mfaSavedColor = "Green"
        $mfaSaved = $true
    } else {
        Write-Host "MFS status is blank - skipping save"
        $mfaSaved = $false
        $mfaSavedColor = "Red"
    }
    Write-Host "`tMFA Saved: $($mfaSaved)" -ForegroundColor $mfaSavedColor


    # Save Password
    #     if ($script:microsoftCredential.Password.Length -eq 0) {
    #         Write-Host "Password is blank - skipping save" -ForegroundColor Yellow
    #         $passwordSaved = $false
    #         $passwordSavedColor = "Red"
    #     } else {
    #         #DEBUG $script:microsoftCredential = Get-Credential
    #         $encryptedPass = ConvertFrom-SecureString $script:microsoftCredential.Password 
    #         [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $encryptedPass, [System.environmentVariableTarget]::User)
    #         $passwordSaved = $true  
    #         $passwordSavedColor = "Green"
    #     }
    #     Write-Host "`tPassword Saved: $($passwordSaved)" -ForegroundColor $passwordSavedColor
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
    $script:alreadyConnected = 0 
    # [Parameter(Mandatory)]$serviceName
    # Only check for connections if there's been service connected already
    if ($script:connectedServices.Length -ne 0 ) {
        if ($script:connectedServices.ToLower().Contains($serviceName.ToLower())) {
            Write-Color $serviceName, " is already connected." -Color Yellow, $foregroundColor
            $script:alreadyConnected = 1
        }
    }
}
#TODO Add a check for updated module if it's already insatlled
function Invoke-ModuleCheck {
    # [String]$moduleName
    if (!(Get-Module -Name $moduleName -ListAvailable)) {
        Write-Color "`tModule ", $moduleName, " is missing." -Color $foregroundColor, Yellow, $foregroundColor
        # $Prompt = "`t`tInstall [Y/N]"
        $installPrompt = $(Write-Color "`t`tInstall? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)
        If ($installPrompt.ToUpper() -ne "Y") {
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
function fakeModule {
    $serviceName = $MyInvocation.MyCommand.Name
    Invoke-ConnectedServiceCheck $serviceName
    try {
        # $script:connectedServices = 'FakeModule'
        Update-ConnectedServices $serviceName
    } catch {
        Write-Warning "Unable to connect to $($MyInvocation.MyCommand.Name)"
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
}
function fakeModule2 {
    $serviceName = $MyInvocation.MyCommand.Name
    Invoke-ConnectedServiceCheck $serviceName
    try {
        # $script:connectedServices = 'FakeModule2'
        Update-ConnectedServices $serviceName
    } catch {
        Write-Warning "Unable to connect to $($MyInvocation.MyCommand.Name)"
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
}
# [X] Teams 
function Teams { 
    # Check $script:connectedServices
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
            Update-ConnectedServices
        }
    } catch {
        # if ($error[1].Exception.Message.Contains("AADSTS50076")) {
        #     Write-Host "TRY MFA"
        #     Pause
        # }
        # Check the past 3 errors for an MFA warning
        Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
        foreach ($e in $error[0..2]) {
            if ($e.Exception.Message.Contains("AADSTS50076:")) {
                Write-Warning "`tMFA error detected"
                Write-Color "`tTry ", "Add-MFA", " and re-run ", $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
            }
        }
    }
}
# [X]
function ExchangeServer { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name

    try {
        Invoke-ConnectedServiceCheck $serviceName
        if ($script:alreadyConnected -eq 0) {
            Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
            $serverFQDN = Read-Host -Prompt "Enter Exchange Server FQDN: "
            $exchangeServerSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$serverFQDN/PowerShell/ -Authentication Kerberos -Credential $script:microsoftCredential
            Import-PSSession $exchangeServerSession -DisableNameChecking  
            # Update-Prompt
            Update-ConnectedServices $serviceName
        }
    } catch {
        Write-Warning 'Unable to connect to Exchnage Service'
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
    # return $script:connectedServices
}
function Exchange { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    $moduleName = 'ExchangeOnlineManagement'
    # Invoke-ModuleCheck('ExchangeOnlineManagement')
    try {
        Invoke-ConnectedServiceCheck $serviceName
        if ($script:alreadyConnected -eq 0) {
            Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
            # Check if module is installed
            Invoke-ModuleCheck -moduleName $moduleName
            # Exchange Online V2 uses modern auth by default and supports MFA
            Connect-ExchangeOnline -UserPrincipalName $script:microsoftCredential.UserName
            # Update-Prompt
            Update-ConnectedServices $serviceName
        }
        
    } catch {
        Write-Warning 'Unable to connect to Exchange Online'
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
    # return $script:connectedServices
}
function MSOnline { 
    # Check $script:connectedServices
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
            # Update-Prompt
            # Update-ConnectedServices
            Update-ConnectedServices $serviceName
        }
    } catch {
        Write-Warning 'Unable to connect to MSOnline'
        Write-Warning $Error[0]
    }
    # return $script:connectedServices
}
function AzureAD { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    # Check if module is installe
    # Invoke-ModuleCheck('AzureAD')
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
            # Update-Prompt
            # Update-ConnectedServices
            Update-ConnectedServices $serviceName
        }
        
    } catch {
        Write-Warning 'Unable to connect to Azure AD'
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
    # return $script:connectedServices
}
function AzureADPreview {
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    # Check if module is installed
    # Invoke-ModuleCheck('AzureADPreview')
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
            # Update-Prompt
            # Update-ConnectedServices
            Update-ConnectedServices $serviceName
        }        
    } catch {
        Write-Warning 'Unable to connect to Azure AD'
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
    # return $script:connectedServices
}
function SharePoint { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    # Check if module is installed
    # Invoke-ModuleCheck('Microsoft.Online.SharePoint.PowerShell')
    $moduleName = 'Microsoft.Online.SharePoint.PowerShell'
    try {
        Invoke-ConnectedServiceCheck $serviceName
        # Check if module is installed
        if ($script:alreadyConnected -eq 0) {
            Invoke-ModuleCheck -moduleName $moduleName
     
            Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan
            Write-Host "`tEnter your SharePoint organization name below:" -ForegroundColor Yellow
            $orgName = $(Write-Color "`tExample: ", "https://", "tenantname", "-admin.sharepoint.com" -Color Yellow, $foregroundColor, Green, $foregroundColor; Read-Host)
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
            # Update-Prompt
            # Update-ConnectedServices
            Update-ConnectedServices $serviceName
        }

    } catch {
        Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
        Write-Warning 'Ensure that MFA is not required.'
        foreach ($e in $error[0..2]) {
            if ($e.Exception.Message.Contains("AADSTS50076:")) {
                Write-Warning "`tMFA error detected"
                Write-Color "`tTry ", "Add-MFA", " and re-run ", $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
            }
        }
    }
    # return $script:connectedServices
}
function Security_Compliance { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    # Check if module is installed
    # Invoke-ModuleCheck('ExchangeOnlineManagement')
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
            # Update-Prompt
            # Update-ConnectedServices
            Update-ConnectedServices $serviceName
        }
    } catch {
        Write-Warning "`tUnable to connect to $($MyInvocation.MyCommand.Name)"
        foreach ($e in $error[0..2]) {
            if ($e.Exception.Message.Contains("AADSTS50076:")) {
                Write-Warning "`tMFA error detected"
                Write-Color "`tTry ", "Add-MFA", " and re-run ", $($MyInvocation.MyCommand.Name) -Color Yellow, Green, Yellow, Green
            }
        }
    }
    # return $script:connectedServices
}
function Intune { 
    # Check $script:connectedServices
    $serviceName = $MyInvocation.MyCommand.Name
    Invoke-ConnectedServiceCheck $serviceName
    # Check if module is installed
    # Invoke-ModuleCheck('Microsoft.Graph.Intune')
    $moduleName = 'Microsoft.Graph.Intune'
    
    try {
        if ($script:alreadyConnected -eq 0) {
            # Loading MSonline before Intune can cause issues
            if ($script:connectedServices -contains 'MSOnline') {
                Write-Color "`t*************", "`t`nImporting the MSOnline cmdlets before importing this Intune module will cause errors. Please use the AzureAD module instead, as the MSOnline module is deprecated.
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
            # Update-Prompt
            Update-ConnectedServices $serviceName
        }

        # Update-ConnectedServices
    } catch {
        Write-Host "`tGraph Connection Failed" -ForegroundColor Yellow
        Write-Host "`tYou may need to connect with 'Connect-MSGraph -AdminConsent'" -ForegroundColor Yellow
        Write-Host "`tMore Info: https://github.com/Microsoft/Intune-PowerShell-SDK" -ForegroundColor Yellow
        Write-Warning 'Unable to connect to Intune'
        Write-Warning $Error[0]
        Write-Warning 'Ensure that MFA is not required.'
    }
    # return $script:connectedServices
}
#! End specific service connection functions
function disconnect {
    foreach ($service in $script:connectedServices) {
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
        $script:joinedServices = $script:connectedServices | Where-Object { $_ -NE $service }
        Write-Host "Disconnected Service: " $($service) -ForegroundColor Yellow
    }
    $script:connectedServices = @()
    $function:prompt = & { $script:userPrompt }
    # $script:joinedServices = $script:connectedServices
    # $script:joinedServices = @()
    # return $script:connectedServices
}

# Run these on startup
# Check for the -Install switch
$script:installCommand = "Import-Module $($PSCommandPath) -Force" # this wouldn't be necessary if the it's created as a module
if ($install.IsPresent) {
    # Create a profile if it doesn"t exist already
    if (!(Test-Path -Path $Profile)) {
        New-Item -ItemType File -Path $Profile -Force
    }
    if ((Get-Content $Profile | Select-String -Pattern ([regex]::Escape($script:installCommand))).Matches.Success) {
        Write-Color "`tProfile is already installed" -Color Red
        break
    } else {
        Add-Content $Profile -Value ($script:installCommand)
        Write-Color -Text "Added command ", $script:installCommand, " to $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
        exit
    }
}
if ($uninstall.IsPresent) {
    if ((Get-Content $Profile | Select-String -Pattern ([regex]::Escape($script:installCommand))).Matches.Success) {
    (Get-Content $Profile).Replace(($script:installCommand), "") | Set-Content $Profile
        Remove-Account
        Remove-MFA
        Write-Color -Text "Removed ", $script:installCommand, " from $($Profile)", "`n`tPlease reload PowerShell for changes to take effect." -Color $foregroundColor, Yellow, $foregroundColor, Green
        break
    } else {
        Write-Color "`tProfile is not installed" -Color Red
        break
    }
}

# Import profile settings
Start-Profile
#! Debug Starting
# Write-Host "Connected Services: " $script:connectedServices