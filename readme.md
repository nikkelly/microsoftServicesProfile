# Microsoft Services PowerShell Profile

## Allows for connection to these M365 Services
- Microsoft Teams
- Skype for Business
- Microsoft Exchange Online
- Azure Active Directory
- SharePoint

## Windows Terminal Profile
This was created to be used as a Windows Terminal profile and you can view my sample profile below:
```
{
  "guid": "{db7918ba-865e-456a-8adb-c3fc5a059a4a}",
  "name": "M365 Admin Console",
  "commandline": "powershell.exe -noprofile -noexit -command \"invoke-expression '. ''<path_to_file>/microsoftServicesProfile.ps1''' \"",
  "icon": "<path_to_icon>/m365logo.png",
  "hidden": false,
  "colorScheme": "Tomorrow Night Eighties"
}
```

## Links and Resources
- [M365 Profile Icon](https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/1200px-Microsoft_logo.svg.png)
- Terminal colorScheme is [Tomorrow Night Eighties](https://github.com/mbadolato/iTerm2-Color-Schemes/blob/master/windowsterminal/Tomorrow%20Night%20Eighties.json)
