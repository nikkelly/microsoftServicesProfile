function Disconnect-AllMSServices {
    <#
    .SYNOPSIS
        Disconnects from all Microsoft 365 services.

    .DESCRIPTION
        Closes connections to all currently connected Microsoft 365 services
        and resets the PowerShell prompt.

    .EXAMPLE
        Disconnect-AllMSServices
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Plural is intentional - disconnects from multiple services')]
    [CmdletBinding()]
    param()

    if ($script:MSProfileState.ConnectedServices.Count -eq 0) {
        Write-Host "`tNo services are currently connected." -ForegroundColor Yellow
        return
    }

    Write-Host "`n`tDisconnecting from Microsoft 365 services..." -ForegroundColor Cyan

    # Create a copy of the list to iterate over
    $servicesToDisconnect = $script:MSProfileState.ConnectedServices.Clone()

    foreach ($service in $servicesToDisconnect) {
        try {
            switch ($service) {
                'Teams' {
                    Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue
                }
                'ExchangeServer' {
                    if ($script:MSProfileState.ExchangeServerSession) {
                        Remove-PSSession $script:MSProfileState.ExchangeServerSession -ErrorAction SilentlyContinue
                        $script:MSProfileState.ExchangeServerSession = $null
                    }
                }
                'Exchange' {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                }
                'MSOnline' {
                    try {
                        [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
                    } catch {
                        # Module may not be loaded
                    }
                }
                'AzureAD' {
                    Disconnect-AzureAD -ErrorAction SilentlyContinue
                }
                'Graph' {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue
                }
                'SharePoint' {
                    Disconnect-SPOService -ErrorAction SilentlyContinue
                }
                'Security_Compliance' {
                    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
                }
                'Intune' {
                    # Legacy Intune module doesn't have a disconnect command
                    # For Graph-based Intune, disconnecting Graph handles it
                }
            }

            Write-Host "`tDisconnected: $service" -ForegroundColor Yellow

        } catch {
            Write-Warning "Error disconnecting from $service : $_"
        }
    }

    # Clear the connected services list
    $script:MSProfileState.ConnectedServices.Clear()

    # Reset prompt
    Reset-MSPrompt

    Write-Host "`n`tAll services disconnected." -ForegroundColor Green
}
