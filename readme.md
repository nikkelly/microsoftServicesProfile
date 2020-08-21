# Microsoft Services PowerShell Profile

This PowerShell profile is colored to match Windows terminal with [Tomorrow Night Eighties] (https://github.com/mbadolato/iTerm2-Color-Schemes/blob/master/windowsterminal/Tomorrow%20Night%20Eighties.json)

## Allows for connection to these M365 Services:
- Microsoft Teams
- Skype for Business
- Microsoft Exchange Online
- Azure Active Directory
  
 ## Sample Windows Terminal Profile:
`{
    "guid": "{db7918ba-865e-456a-8adb-c3fc5a059a4a}",
    "name": "M365 Admin Console",
    "commandline": "powershell.exe -noprofile -noexit -command \"invoke-expression '. ''D:/Git Repos/microsoftServicesProfile/microsoftServicesProfile.ps1''' \"",
    "icon": "C:/Users/nikke/Pictures/m365logo.png",
    "hidden": false,
    "colorScheme": "Tomorrow Night Eighties"
}`

## Pre-Requisites: 
None

### Todo list
