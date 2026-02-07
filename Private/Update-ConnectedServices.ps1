function Update-ConnectedServices {
    <#
    .SYNOPSIS
        Adds a service to the connected services list and updates the prompt.

    .DESCRIPTION
        Maintains a list of currently connected Microsoft 365 services and updates
        the PowerShell prompt to display connection status.

    .PARAMETER ServiceName
        The name of the service that was connected.

    .EXAMPLE
        Update-ConnectedServices -ServiceName 'Teams'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName
    )

    if ($PSCmdlet.ShouldProcess($ServiceName, 'Add to connected services list')) {
        # Add service to the list if not already present
        if ($script:MSProfileState.ConnectedServices -notcontains $ServiceName) {
            [void]$script:MSProfileState.ConnectedServices.Add($ServiceName)
        }

        # Update the prompt
        if ($script:MSProfileState.ConnectedServices.Count -eq 1) {
            # First connection - save original prompt and update
            if ($null -eq $script:MSProfileState.OriginalPrompt) {
                $script:MSProfileState.OriginalPrompt = $function:global:prompt
            }
            Update-MSPrompt
        }

        Write-Host "`tConnected to $ServiceName!" -ForegroundColor Green
    }
}

function Update-MSPrompt {
    <#
    .SYNOPSIS
        Updates the PowerShell prompt to show connected services.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('PowerShell prompt', 'Update to show connected services')) {
        $function:global:prompt = {
            # Call original prompt
            if ($null -ne $script:MSProfileState.OriginalPrompt) {
                & $script:MSProfileState.OriginalPrompt
            } else {
                "PS $($executionContext.SessionState.Path.CurrentLocation)$('>' * ($nestedPromptLevel + 1)) "
            }

            # Append connected services
            if ($script:MSProfileState.ConnectedServices.Count -gt 0) {
                $services = $script:MSProfileState.ConnectedServices -join '|'
                Write-Host " [$services]" -NoNewline -ForegroundColor Yellow
            }
        }.GetNewClosure()
    }
}

function Reset-MSPrompt {
    <#
    .SYNOPSIS
        Resets the PowerShell prompt to its original state.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('PowerShell prompt', 'Reset to original')) {
        if ($null -ne $script:MSProfileState.OriginalPrompt) {
            $function:global:prompt = $script:MSProfileState.OriginalPrompt
        }
    }
}
