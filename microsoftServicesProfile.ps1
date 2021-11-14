# Set variables
$service = ''
$serviceCount = 0

# prompt for user username and password then save that in an environment variable
# Check if credential exists
if ((Test-Path env:microsoftConnectionUser) -And (Test-Path env:microsoftConnectionPass)) {
  $encryptedUser = $env:microsoftConnectionUser
  $microsoftPassword = $env:microsoftConnectionPass
}
if (Test-Path env:microsoftConnectionUser) {
  $microsoftUser = $env:microsoftConnectionUser
}
else {
  Write-Host "Microsoft connection credentials not found.`n"
  Write-Host "Prompting for login"
  $microsoftUser = Read-Host -Prompt "Enter Username"
  $inputPassword = Read-Host -Prompt "Enter password" -AsSecureString
  $host.ui.RawUI.WindowTitle = 'Connected Account: ' + $microsoftUser
  # save credentials
  Write-Host "`n`nWould you like to save them for later?" -ForegroundColor Yellow -NoNewline
  Write-Host " (Y / N)" -ForegroundColor White -NoNewline
  $saveCreds = Read-Host -Prompt " "
  $result = Switch ($saveCreds) {
    Y { $true }
    N { $false }
    Default { $false }
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
$microsoftUser = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureUser))
# Convert encrypted string password back to secureString
$global:securePwd = ConvertTo-SecureString $microsoftPassword
$global:creds = New-Object System.Management.Automation.PSCredential -ArgumentList $microsoftUser, $securePwd
$domain = $microsoftUser.split('@')[1]
$host.ui.RawUI.WindowTitle = 'Connected: ' + $microsoftUser

function displayCommands(){
# display found account
Write-Host "Account " -NoNewline
Write-Host "$microsoftUser " -ForegroundColor Green -NoNewline
Write-Host "imported.`n" -NoNewline
if (Test-Path  env:microsoftConnectionMFA ) {
  Write-Host "MFA status: " -ForegroundColor Yellow -NoNewline
  Write-Host "Enabled`n" -ForegroundColor Green -NoNewLin
  $script:mfaCheck = $true
}
else {
  Write-Host "MFA status: " -ForegroundColor Yellow -NoNewline
  Write-Host "Disabled`n" -ForegroundColor Red -NoNewline
}

Write-Host "`nConnect to Microsoft online services with these commands: " -ForegroundColor Green
Write-Host "Teams | ExchangeServer | Exchange | MSOnline (AAD V1) | AzureAD (AAD V2) | SharePoint | Security_Compliance | Intune | connectAll | Disconnect`n" -ForegroundColor Yellow

Write-Host "Manage Account Credentials with: " -ForegroundColor Green
Write-Host "Remove-Account | Add-MFA | Remove-MFA `n" -ForegroundColor Yellow

Write-Host "Helpful Variables: " -ForegroundColor Green
Write-Host '$microsoftUser = ' -ForegroundColor Yellow -NoNewline
Write-Host $microsoftUser -ForegroundColor White
Write-Host '$domain = ' -ForegroundColor Yellow -NoNewline
Write-Host $domain `n -ForegroundColor White
Write-Host "Re-display commands with: " -ForegroundColor Green -NoNewline
Write-Host 'displayCommands' -ForegroundColor Yellow

}

displayCommands

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
    Write-Host ('' + $(Get-Location) + ">")  -NoNewline 
  }
  else {
    Write-Host ("$service" + $(Get-Location) + ">") -NoNewline `

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
    #Disconnect Exchange Online and Security & Compliance center session
    if (($script:service -contains 'Exchange') -or ($script:service -contains 'Security_Compliance') -or ($script:service -contains 'ExchangeServer')) {
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
  SharePoint
  Security_Compliance
  AzureAD
  MSOnline
  exchangeServer
  Intune
}

function checkInstallModule($moduleName) { 
  $installModule = Switch ($moduleName) {
    Teams { 'MicrosoftTeams' }
    Exchange { 'ExchangeOnlineManagement' }
    SharePoint { 'Microsoft.Online.SharePoint.PowerShell' }
    AzureAD { 'AzureAD' }
    MSOnline { 'MSOnline' }
    Security_Compliance { 'ExchangeOnlineManagement' }
    Intune { 'Microsoft.Graph.Intune' }
  }
  # If module is not already installed, prompt for install 
  if (!(Get-Module -ListAvailable -Name $installModule)) {
    Write-Host "Module " -NoNewline
    Write-Host "$installModule " -ForegroundColor Yellow -NoNewline
    Write-Host "is missing, would you like to install it? (Y / N)" -NoNewline
    $readHost = Read-Host -Prompt " "
    Switch ($readHost) {
      Y { $installAnswer = $true }
      N { $installAnswer = $false }
      Default { $installAnswer = $false }
    }
    if ($installAnswer -eq $true) {
      # Check if admin
      try {
        if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
          # Run with -AllowClobber for AzureAD
          if ($installModule -eq 'AzureAD') {
            Install-Module -Repository "PSGallery" -Name $installModule -AllowClobber -Force
          }
          else {
            Install-Module -Repository "PSGallery" -Name $installModule -Force
          }
        }
        else {
          Write-Host "`nAdministrator rights are required to install modules. Prompting for rights..." 
          # pass install to an elevated PowerShell window
          # $runCommand = Install-Module $installModule -Repository "PSGallery"
          if ($installModule -eq 'AzureAD') {
            $runCommand = "Install-Module -Repository 'PSGallery' -Name $installModule -Force -AllowClobber"
          }
          else {
            $runCommand = "Install-Module -Repository 'PSGallery' -Name $installModule -Force"
          }
          Start-Process -FilePath powershell.exe -ArgumentList @('-command', $runCommand) -Verb runas -Wait
        }
      }
      catch {
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
    try {
      if ($script:mfaCheck) {

        Connect-MicrosoftTeams
      }
      else {
        Connect-MicrosoftTeams -Credential $creds
      }
      Increment($MyInvocation.MyCommand.name)
    }
    catch {
      Write-Warning 'Unable to connect to Teams'
      Write-Warning $Error[0]
    }
  }
}

function AzureAD() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  try {
    if ($script:alreadyConnected = 1) {
      if ($script:mfaCheck) {
        Connect-AzureAD -AccountId $microsoftUser
      }
      else {
        Connect-AzureAD -Credential $creds
      }
      Increment($MyInvocation.MyCommand.name)
    }
  }
  catch {
    Write-Warning 'Unable to connec to AzureAD'
    Write-Warning $Error[0]
  }
}

# Intune
function Intune() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    try { 
      if ($script:mfaCheck) {
        Connect-MSGraph
      }
      Connect-MSGraph -PSCredential $creds
      Increment($MyInvocation.MyCommand.name)
    }
    catch {
      Write-Host Graph Connection Failed
      Write-Host You may need to connect with /'Connect-MSGraph -Consent'/
      Write-Host More Info: https://github.com/Microsoft/Intune-PowerShell-SDK
    }

  }
}

# MSOnline 
function MSOnline() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    try {
      if ($script:mfaCheck) {
        Connect-MsolService
      }
      else {
        Connect-MsolService -Credential $creds
      }
      Increment($MyInvocation.MyCommand.name)
    }
    catch {
      Write-Warning 'Unable to connec to MSOnline'
      Write-Warning $Error[0]
    }
  }
}

# SharePoint
function SharePoint() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  Write-Host "Prompting for SharePoint organization name"
  Write-Host "Example " -ForegroundColor Yellow -NoNewline
  Write-Host "https://tenantname-admin.sharepoint.com" -ForegroundColor White
  Write-Host "`n`n"
  $orgName = Read-Host -Prompt "Organization name"
  # if $orgName contains -admin this should remove it
  if ($orgName -like '*-admin') {
    $orgName = $orgName.split('-')[0]
  }
  if ($script:alreadyConnected = 1) {
    try {
      if ($script:mfaCheck) {
        Connect-SPOService -Url https://$orgName-admin.sharepoint.com
      }
      else {
        Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $creds
        Increment($MyInvocation.MyCommand.name)
      }
    }
    catch {
      Write-Warning 'Unable to connec to SharePoint'
      Write-Warning $Error[0]
    }
  }
}

# Exchange Online
function Exchange() {
  checkServices($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    try {
      if ($script:mfaCheck) {
        checkInstallModule($MyInvocation.MyCommand.name)
        Connect-ExchangeOnline -UserPrincipalName $microsoftUser -ShowProgress $true
      }
      else {
        $exoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
        Import-PSSession $exoSession -DisableNameChecking
      }
      Increment($MyInvocation.MyCommand.name)  
    }
    catch {
      Write-Warning 'Unable to connec to Exchange'
      Write-Warning $Error[0]
    }
  }
}
# Exchange Server
function exchangeServer() {
  checkServices($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    try {
      $serverFQDN = Read-Host -Prompt "Exchange Server FQDN"
      $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$serverFQDN/PowerShell/ -Authentication Kerberos -Credential $creds
      Import-PSSession $Session -DisableNameChecking  
    }
    catch {
      Write-Warning 'Unable to connec to Exchange Server'
      Write-Warning $Error[0]
    }
  }
}
function Security_Compliance() {
  checkServices($MyInvocation.MyCommand.name)
  checkInstallModule($MyInvocation.MyCommand.name)
  if ($script:alreadyConnected = 1) {
    try {
      if ($script:mfaCheck) {
        Connect-IPPSSession -UserPrincipalName $microsoftUser
      }
      else {
        Connect-IPPSSession -Credential $creds -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/
      }
      Increment($MyInvocation.MyCommand.name)  
    }
    catch {
      Write-Warning 'Unable to connect to Security & Compliance Center'
      Write-Warning $Error[0]
    }
  }
}

function Remove-Account() {
  Write-Host "`n Removing saved username, password and MFA settings from environment variables"
  [Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
  [Environment]::SetEnvironmentVariable("microsoftConnectionUser", $null, "User")
  [Environment]::SetEnvironmentVariable("microsoftConnectionPass", $null, "User")
}

function Add-MFA() {
  Write-Host "Saving MFA settings to environment variable"
  [System.Environment]::SetEnvironmentVariable('microsoftConnectionMFA', $true, [System.EnvironmentVariableTarget]::User)
  $script:mfaCheck = $mfaAnswer
}

function Remove-MFA() {
  [Environment]::SetEnvironmentVariable("microsoftConnectionMFA", $null, "User")
}