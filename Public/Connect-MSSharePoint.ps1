function Connect-MSSharePoint {
    <#
    .SYNOPSIS
        Connects to SharePoint Online.

    .DESCRIPTION
        Establishes a connection to SharePoint Online using the Microsoft.Online.SharePoint.PowerShell module.
        Supports interactive and credential-based authentication.

    .PARAMETER AuthMethod
        The authentication method to use: Interactive or Credential.

    .PARAMETER Credential
        A PSCredential object for credential-based authentication.

    .PARAMETER OrgName
        The SharePoint organization name (tenant name without -admin.sharepoint.com).

    .PARAMETER Url
        The full admin URL (e.g., https://contoso-admin.sharepoint.com).

    .EXAMPLE
        Connect-MSSharePoint -OrgName "contoso"

    .EXAMPLE
        Connect-MSSharePoint -Url "https://contoso-admin.sharepoint.com"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Interactive', 'Credential', 'ServicePrincipal')]
        [string]$AuthMethod = $script:MSProfileState.AuthMethod,

        [PSCredential]$Credential,

        [string]$OrgName,

        [string]$Url
    )

    $serviceName = 'SharePoint'
    $moduleName = 'Microsoft.Online.SharePoint.PowerShell'

    try {
        # Check if already connected
        if (Test-AlreadyConnected -ServiceName $serviceName) {
            return
        }

        # Check if module is available
        if (-not (Test-ModuleAvailable -ModuleName $moduleName)) {
            return
        }

        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan

        # Determine the admin URL
        $adminUrl = $Url
        if (-not $adminUrl) {
            if ($OrgName) {
                # Remove -admin suffix if present
                if ($OrgName -like '*-admin') {
                    $OrgName = $OrgName -replace '-admin$', ''
                }
                $adminUrl = "https://$OrgName-admin.sharepoint.com"
            } else {
                # Prompt for org name
                Write-Host "`tEnter your SharePoint organization name below:" -ForegroundColor Yellow
                $foregroundColor = $script:MSProfileState.ForegroundColor
                $inputOrgName = $(Write-ColorOutput -Text "`tExample: ", "https://", "tenantname", "-admin.sharepoint.com" -Color Yellow, $foregroundColor, Green, $foregroundColor; Read-Host)

                if ([string]::IsNullOrWhiteSpace($inputOrgName)) {
                    Write-Warning "Organization name is required"
                    return
                }

                # Remove -admin suffix if present
                if ($inputOrgName -like '*-admin') {
                    $inputOrgName = $inputOrgName -replace '-admin$', ''
                }
                $adminUrl = "https://$inputOrgName-admin.sharepoint.com"
            }
        }

        switch ($AuthMethod) {
            'ServicePrincipal' {
                Write-Warning "SharePoint Online Management Shell has limited service principal support."
                Write-Warning "Consider using PnP.PowerShell module for app-only authentication."
                # Fall through to interactive
                Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                Connect-SPOService -Url $adminUrl -ErrorAction Stop
            }
            'Credential' {
                $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
                if (-not $cred) {
                    Write-Warning "No credential available. Use Add-MSAccount to configure credentials."
                    return
                }
                Connect-SPOService -Url $adminUrl -Credential $cred -ErrorAction Stop
            }
            default {
                # Interactive
                if ($script:MSProfileState.MFAEnabled) {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    Connect-SPOService -Url $adminUrl -ErrorAction Stop
                } elseif ($script:MSProfileState.Credential) {
                    Connect-SPOService -Url $adminUrl -Credential $script:MSProfileState.Credential -ErrorAction Stop
                } else {
                    Write-Host "`tYou might see an interactive login prompt" -ForegroundColor Yellow
                    Connect-SPOService -Url $adminUrl -ErrorAction Stop
                }
            }
        }

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to SharePoint Online"

        if ($_.Exception.Message -match "AADSTS50076") {
            Write-Warning "`tMFA error detected"
            Write-ColorOutput -Text "`tTry ", "Add-MSMFA", " and re-run ", "Connect-MSSharePoint" -Color Yellow, Green, Yellow, Green
            return
        }

        Write-Warning $_.Exception.Message
    }
}
