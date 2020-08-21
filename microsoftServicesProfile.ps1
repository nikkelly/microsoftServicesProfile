# #TODO 
# [] How to launch Powershell with a different profile. 
#   Notes: Ideally we would have this profile as a new Terminal profile (~M365 admin)
# [] Have profile in a non-standard location
# [] Launch powershell with a different profile
#References: https://gist.github.com/merlos/e4dabae049dea4b92e070d11d0f7bfa7

# Set variables
$service = ''
$serviceCount = 0

# Check if modules are installed
$modules = 'MicrosoftTeams','MSOnline','Microsoft.Online.SharePoint.PowerShell'
$toInstall = $()

foreach ($module in $modules){
  if (!(Get-Module -ListAvailable -Name $module )) {
    $script:toInstall+=$module+"`n`t"
  } 
}

# List missing, ask to install, and install
if ($script:toInstall.length -gt 0){
  Write-Host("Missing modules: `n`t"+$toInstall) -ForegroundColor Red -NoNewLine
  Write-Host("`n`n Would you like to install them?`n`t ( y / n )") -ForegroundColor Yellow -NoNewLine
  $readHost = Read-Host -Prompt " "
  Switch ($readHost){
    Y {$installAnswer=$true}
    N {$installAnswer=$false}
    Default {$installAnswer=$false}
  }
  if ($installAnswer -eq $true){
    Install-Module -Repository "PSGallery" -Name $modules -Force
  } elseif ($installAnswer -eq $false) {
    Write-Host('exiting...')
  } 
}

# prompt for user username and password
# save that in an environment variable
# Check if credential exists
if ((Test-Path env:microsoftConnectionUser) -And (Test-Path env:microsoftConnectionPass)){
  $microsoftUser = $env:microsoftConnectionUser
  $microsoftPassword = $env:microsoftConnectionPass
} else {
  Write-Host("Microsoft connection credentials not found.")
  Write-Host("`n`n Would you like to save them for later?`n`t ( y / n )") -ForegroundColor Yellow -NoNewLine
  $saveCreds = Read-Host -Prompt " "
  Switch($saveCreds){
    Y {$saveAnswer=$true}
    N {$saveAnswer=$false}
    Default {$saveAnswer=$false}
  }
  Write-Host("Prompting for login:")
  $microsoftUser = Read-Host -Prompt "Enter Username"
  $microsoftPassword = Read-Host -Prompt "Enter password"
  if($saveAnswer){
    # save credentials as a User scoped environment variable 
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionUser', $microsoftUser, [System.EnvironmentVariableTarget]::User)
    [System.Environment]::SetEnvironmentVariable('microsoftConnectionPass', $microsoftPassword, [System.EnvironmentVariableTarget]::User)
  }
}
# create microsoftCreds with user + pass
$securePwd = $microsoftPassword | ConvertTo-SecureString -AsPlainText -Force
$microsoftCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $microsoftUser, $securePwd

Write-Host "Connect to Microsoft online services with these commands: " -ForegroundColor Green
Write-Host "`nTeams | Exchange | Skype | MSOnline | SharePoint`n`n" -ForegroundColor DarkYellow



# Change prompt when connecting to services
function global:prompt() {
  # Group connected services
  if ($serviceCount -gt 1) {
    $service = "[$service]"
  } if ($serviceCount -eq 1){
    $service = $service.replace('|','+')
  } 

  # Update the prompt
  if ($serviceCount -gt 0){
    Write-Host ("$service") -ForegroundColor DarkYellow -NoNewline 
    Write-Host ( " | ") -ForegroundColor  White -NoNewline 
    Write-Host (''+ $(Get-Location) +">") -ForegroundColor DarkMagenta -NoNewLine 
  }
  else{
    Write-Host ("$service" + $(Get-Location) +">") -NoNewLine `
   -ForegroundColor DarkMagenta
  }
  return " "
}

# Don't add serviceName if it's already there
function checkServices($functionName){
$script:alreadyConnected = 1
if($script:service.ToLower().Contains($functionName.toLower())){
  Write-Host "`n`n" $functionName "is already connected.`n`n"
  $global:alreadyConnected = 0
  break
}
}

# add serviceName and increment serviceCount
function Increment($functionName){
  if ($serviceCount -gt 0){
    $script:service+="|"
  }
  $script:service+=$functionName
  $script:serviceCount+=1
  Write-Host 'Connected to '$functionName -ForegroundColor DarkYellow
}

## Start Online Service Functions 
# Teams
function Teams(){
  checkServices($MyInvocation.MyCommand.name)
  if($script:alreadyConnected = 1){
  Connect-MicrosoftTeams -Credential $creds
  Increment($MyInvocation.MyCommand.name)
  } else {
    Write-Host 'done'
  }
}

# MSOnline 
function MSOnline(){
  checkServices($MyInvocation.MyCommand.name)
  if($script:alreadyConnected = 1){
  Connect-MsolService -Credential $creds
  Write-Host "Connected to Azure AD!" -ForegroundColor DarkYellow
  Increment($MyInvocation.MyCommand.name)}
}

# SharePoint
function SharePoint(){
  checkServices($MyInvocation.MyCommand.name)
  if($script:alreadyConnected = 1){
  $orgName=$username.split('@').split('.')[1] # split the domain from $username
  Connect-SPOService -Url https://$orgName-admin.sharepoint.com -Credential $creds
  Increment($MyInvocation.MyCommand.name)}
}

# Exchange Online
function Exchange(){
  checkServices($MyInvocation.MyCommand.name)
  if($script:alreadyConnected = 1){
  $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $creds -Authentication Basic -AllowRedirection
  Import-PSSession $Session -DisableNameChecking
  Write-Host "Connected to Exchange!" -ForegroundColor DarkYellow
  Increment($MyInvocation.MyCommand.name)}
}

# Skype Online management 
function Skype(){
  checkServices($MyInvocation.MyCommand.name)
  if($script:alreadyConnected = 1){
  Import-Module SkypeOnlineConnector
  $sfbSession = New-CsOnlineSession -Credential $creds
  Import-PSSession $sfbSession
  Write-Host "Connected to Skype Online!" -ForegroundColor DarkYellow
  Increment($MyInvocation.MyCommand.name)}
}

