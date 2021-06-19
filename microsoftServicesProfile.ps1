# Set variables
$service = ''
$serviceCount = 0

# prompt for user username and password then save that in an environment variable
# Check if credential exists
if ((Test-Path env:microsoftConnectionUser) -And (Test-Path env:microsoftConnectionPass)) {
  $encryptedUser = $env:microsoftConnectionUser
  $microsoftPassword = $env:microsoftConnectionPass

}
else {
  Write-Host "Microsoft connection credentials not found.`n"
  Write-Host "Prompting for login"
  $microsoftUser = Read-Host -Prompt "Enter Username"
  $inputPassword = Read-Host -Prompt "Enter password" -AsSecureString
  # save credentials
  Write-Host "`n`nWould you like to save them for later?" -ForegroundColor Yellow -NoNewLine
  Write-Host " (Y / N)" -ForegroundColor White -NoNewLine
  $saveCreds = Read-Host -Prompt " "
  $result = Switch ($saveCreds) {
    Y {$true }
    N {$false }
    Default {$false }
  }
  # convert username to encrypted string
  $secureUser = ConvertTo-SecureString $microsoftUser -AsPlainText -Force
  $encryptedUser = ConvertFrom-SecureString $secureUser
  # convert securestring to encrytped string
  $microsoftPassword = ConvertFrom-SecureString $inputPassword
  if ($result) {
    Write-Host "`n***Username and Password will be saved to environment variables as encrypted strings***`n`n"  -ForegroundColor Red
    # save credentials as a User scoped environment variable  
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $encryptedUser, [System.EnvironmentVariableTarget]::User)
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $microsoftPassword, [System.EnvironmentVariableTarget]::User)
    }
  }
# create microsoftCreds with user + pass
# convert encrytped string password > SecureString > PlainText
$secureUser = ConvertTo-SecureString $encryptedUser
$microsoftUser =[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUser))
# Convert encrypted string password back to secureString
$global:securePwd = ConvertTo-SecureString $microsoftPassword
$global:creds = New-Object System.Management.Automation.PSCredential -ArgumentList $microsoftUser, $securePwd
$orgName = $microsoftUser.split('@').split('.')[1] # split the domain from $microsoftUser
$domain = $microsoftUser.split('@')[1]

# display found account
Write-Host "Account " -NoNewLine
Write-Host "$microsoftUser " -ForegroundColor Green -NoNewLine
Write-Host "imported.`n" -NoNewLine
if (Test-Path  env:microsoftConnectionMFA ) {
  Write-Host "MFA status: " -ForegroundColor Yellow -NoNewLine
  Write-Host "Enabled`n" -ForegroundColor Green -NoNewLine
  $script:mfaCheck = $TRUE
} else {
  Write-Host "MFA status: " -ForegroundColor Yellow -NoNewLine
  Write-host "Disabled`n" -ForegroundColor Red -NoNewLine
}

Write-Host "`nConnect to Microsoft online services with these commands: " -ForegroundColor Green
Write-Host "Teams | Exchange | Skype | MSOnline (AAD V1) | AzureAD (AAD V2) | SharePoint | Security_Compliance | connectAll | Disconnect`n" -ForegroundColor Yellow

Write-Host "Manage Account Credentials with: " -ForegroundColor Green
Write-Host "Remove-Account | Add-MFA | Remove-MFA `n" -ForegroundColor Yellow

Write-Host "Helpful Variables: " -ForeGroundColor Green
Write-Host '$microsoftUser = ' -ForeGroundColor Yellow -NoNewLine
Write-Host $microsoftUser -ForeGroundColor White
Write-Host '$domain = ' -ForegroundColor Yellow -NoNewLine
Write-Host $domain -ForegroundColor White
Write-Host '$orgName = ' -ForegroundColor Yellow -NoNewLine
Write-Host $orgName`n`n -ForeGroundColor White



# Change prompt when connecting to services
function global:prompt() {
  # Group connected services
  if ($serviceCount -gt 1) {
    $service = "[$service]"
  } if ($serviceCount -eq 1) {
    $service = $service.replace('|', '+')
  } 

# Update the prompt
if ($serviceCount -gt 0) {
  Write-Host "$service" -ForegroundColor Yellow -NoNewline 
  Write-Host " | " -ForegroundColor  White -NoNewline 
  Write-Host ('' + $(Get-Location) + ">")  -NoNewLine 
}
else {
  Write-Host ("$service" + $(Get-Location) + ">") -NoNewLine `

}
return " "
}


# Don't add serviceName if it's already there
function checkServices($functionName) {
  $script:alreadyConnected = 1
  if ($script:service.ToLower().Contains($functionName.toLower())) {
    Write-Host "`n`n" $functionName "is already connected.`n`n"
    $global:alreadyConnected = 0
    break
  }
}

# add serviceName and increment serviceCount
function Increment($functionName) {
  if ($serviceCount -gt 0) {
    $script:service += "|"
  }
  $script:service += $functionName
  $script:serviceCount += 1
  Write-Host 'Connected to '$functionName -ForegroundColor Yellow
}

function disconnect() {
  if ($script:service.Length -eq 0 ) {
    Write-Host 'No services connected'
  }
  else {
    #Disconnect Exchange Online,Skype and Security & Compliance center session
    if (($script:service -contains 'Skype') -or ($script:service -contains 'Exchange') -or ($script:service -contains 'Security_Compliance')) {
      Get-PSSession | Remove-PSSession
    }
    #Disconnect Teams connection
    if ($script:service -contains 'Teams') {
      Disconnect-MicrosoftTeams
    }
    #Disconnect SharePoint connection
    if ($script:service -contains 'SharePoint') {
      Disconnect-SPOService
    }
    Write-Host "Disconnected from:"
    Write-Host $script:service.replace("|", "`n") -ForegroundColor Yellow
    $script:service = ''
    $script:serviceCount = 0
  }
}

function connectAll() {
  Teams
  Exchange
  Skype
  SharePoint
  Security_Compliance
  AzureAD
  MSOnline
}

function checkInstallModule($moduleName){ 
  $installModule = Switch($moduleName){
    Teams {'MicrosoftTeams'}
    Exchange {'ExchangeOnlineManagement'}
    SharePoint {'Microsoft.Online.SharePoint.PowerShell'}
    AzureAD {'AzureAD'}
    MSOnline {'MSOnline'}
    Security_Compliance {'ExchangeOnlineManagement'}
  }
  # If module is not already installed, prompt for install 
  if(!(Get-Module -ListAvailable -Name $installModule)){
    Write-Host "Module " -NoNewLine
    Write-Host "$installModule " -ForegroundColor Yellow -NoNewLine
    Write-Host "is missing, would you like to install it? (Y / N)" -NoNewLine
    $readHost = Read-Host -Prompt " "
    Switch ($readHost) {
      Y { $installAnswer = $true }
      N { $installAnswer = $false }
      Default { $installAnswer = $false }
    }
    if ($installAnswer -eq $true) {
      # Check if admin
      try{
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        # Run with -AllowClobber for AzureAD
        if($installModule -eq 'AzureAD'){
          Install-Module -Repository "PSGallery" -Name $installModule -AllowClobber -Force
        } else {
          Install-Module -Repository "PSGallery" -Name $installModule -Force
        }
      }
      else {
        Write-Host "`nAdministrator rights are required to install modules. Prompting for rights..." 
        # pass install to an elevated PowerShell window
        # $runCommand = Install-Module $installModule -Repository "PSGallery"
        if($installModule -eq 'AzureAD'){
          $runCommand = "Install-Module -Repository 'PSGallery' -Name $installModule -Force -AllowClobber"
        } else {
        $runCommand = "Install-Module -Repository 'PSGallery' -Name $installModule -Force"
        }
        start-process -filepath powershell.exe -argumentlist @('-command',$runCommand) -verb runas -wait
      }
      } catch {
        Write-Host "Error during install, please try again."
      }
   
    }
    if ($installAnswer -eq $false) {
      Write-Host "`n`t*** $installModule is not installed. Please install to use $moduleName***`n`n" -ForegroundColor Red
    } 
  }
}

## Start Online Service Functions 
# Teams
function Teams() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($script:mfaCheck) {

      Connect-MicrosoftTeams
    }
    else {
      Write-Host "Not detecting MFA"
      Connect-MicrosoftTeams -Credential $creds
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

function AzureAD() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      Connect-AzureAD -AccountId $microsoftUser
    }
    else {
      Connect-AzureAD -Credential $creds
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

# MSOnline 
function MSOnline() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      Connect-MsolService
    }
    else {
      Connect-MsolService -Credential $creds
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

# SharePoint
function SharePoint() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      Connect-SPOService -Url https://$orgName-admin.sharepoint.com
    }
    else {
      Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $creds
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

# Exchange Online
function Exchange() {
  checkServices($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      checkInstallModule($MyInvocation.MyCommand.name)
      Connect-ExchangeOnline -UserPrincipalName $microsoftUser -ShowProgress $true
    }
    else {
      $exoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
      Import-PSSession $exoSession -DisableNameChecking
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

# Skype Online management 
function Skype() {
  checkServices($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      Import-Module SkypeOnlineConnector
      $sfbSession = New-CsOnlineSession
      Import-PSSession $sfbSession
    }
    else {
      Import-Module SkypeOnlineConnector
      $sfbSession = New-CsOnlineSession -Credential $creds
      Import-PSSession $sfbSession
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

function Security_Compliance() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    if ($mfaCheck) {
      Connect-IPPSSession -UserPrincipalName $microsoftUser
    }
    else {
      Connect-IPPSSession -Credential $creds -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/
    }
    Increment($MyInvocation.MyCommand.name)
  }
}

function Remove-Account(){
  Write-Host "`n Removing saved username, password and MFA settings from environment variables"
  [Environment]::SetEnvironmentVariable("microsoftConnectionMFA",$null,"User")
  [Environment]::SetEnvironmentVariable("microsoftConnectionUser",$null,"User")
  [Environment]::SetEnvironmentVariable("microsoftConnectionPass",$null,"User")
}

function Add-MFA(){
  Write-Host "Saving MFA settings to environment variable"
  [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
  $script:mfaCheck = $mfaAnswer
}

function Remove-MFA(){
  [Environment]::SetEnvironmentVariable("microsoftConnectionMFA",$null,"User")
}