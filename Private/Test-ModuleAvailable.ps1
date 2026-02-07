function Test-ModuleAvailable {
    <#
    .SYNOPSIS
        Checks if a PowerShell module is available and optionally installs it.

    .DESCRIPTION
        Verifies if a module is installed. If not, prompts the user to install it.
        Also checks for module compatibility with the current PowerShell version.

    .PARAMETER ModuleName
        The name of the module to check.

    .PARAMETER SkipInstallPrompt
        If specified, does not prompt to install missing modules.

    .OUTPUTS
        System.Boolean - Returns $true if module is available, $false otherwise.

    .EXAMPLE
        if (Test-ModuleAvailable -ModuleName 'MicrosoftTeams') { Connect-MicrosoftTeams }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName,

        [switch]$SkipInstallPrompt
    )

    # Check for deprecated modules
    $deprecatedModules = @{
        'MSOnline'              = 'MSOnline is deprecated. Consider using Microsoft.Graph module.'
        'AzureAD'               = 'AzureAD module is being retired March 2025. Microsoft.Graph is the replacement.'
        'AzureADPreview'        = 'AzureADPreview is being retired. Microsoft.Graph is the replacement.'
        'Microsoft.Graph.Intune' = 'Microsoft.Graph.Intune is deprecated. Use Microsoft.Graph module instead.'
    }

    if ($deprecatedModules.ContainsKey($ModuleName)) {
        Write-Host "`t[DEPRECATION WARNING] " -ForegroundColor Yellow -NoNewline
        Write-Host $deprecatedModules[$ModuleName] -ForegroundColor DarkYellow
    }

    # Check PS7 incompatibility
    $incompatibleInPS7 = @('AzureAD', 'AzureADPreview', 'MSOnline')
    $versionInfo = $script:MSProfileState.PSVersionInfo

    if ($versionInfo.RequiresGraph -and $incompatibleInPS7 -contains $ModuleName) {
        Write-Warning "$ModuleName is not compatible with PowerShell 7+. Use Connect-MSGraph instead."
        return $false
    }

    # Check if module is already available
    if (Get-Module -Name $ModuleName -ListAvailable) {
        return $true
    }

    # Module not found
    $foregroundColor = $script:MSProfileState.ForegroundColor
    Write-ColorOutput -Text "`tModule ", $ModuleName, " is missing." -Color $foregroundColor, Yellow, $foregroundColor

    if ($SkipInstallPrompt) {
        return $false
    }

    # Prompt to install
    $installPrompt = $(Write-ColorOutput -Text "`t`tInstall? [", "Y", "/", "N", "]" -Color Yellow, Green, Yellow, Red, Yellow; Read-Host)

    if ($installPrompt.ToUpper() -ne "Y") {
        Write-ColorOutput -Text "`tModule ", $ModuleName, " not installed." -Color $foregroundColor, Yellow, $foregroundColor
        return $false
    }

    # Check for admin rights
    $isAdmin = Test-IsAdministrator
    if (-not $isAdmin) {
        Write-Error "`tLoad PowerShell as administrator in order to install modules"
        return $false
    }

    # Install the module
    try {
        Write-Host "`tInstalling $ModuleName..." -ForegroundColor Cyan
        Install-Module $ModuleName -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
        Write-Host "`tModule $ModuleName installed successfully." -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Failed to install module ${ModuleName}: ${_}"
        return $false
    }
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current session is running with administrator privileges.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if ($script:MSProfileState.PSVersionInfo.IsWindows) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } else {
        # On Linux/macOS, check if running as root
        return (id -u) -eq 0
    }
}
