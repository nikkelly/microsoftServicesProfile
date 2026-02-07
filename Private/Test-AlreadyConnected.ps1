function Test-AlreadyConnected {
    <#
    .SYNOPSIS
        Checks if a service is already connected.

    .DESCRIPTION
        Verifies if a Microsoft 365 service is already in the connected services list.
        Displays a message if already connected.

    .PARAMETER ServiceName
        The name of the service to check.

    .OUTPUTS
        System.Boolean - Returns $true if already connected, $false otherwise.

    .EXAMPLE
        if (Test-AlreadyConnected -ServiceName 'Teams') { return }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName
    )

    if ($script:MSProfileState.ConnectedServices.Count -eq 0) {
        return $false
    }

    $isConnected = $script:MSProfileState.ConnectedServices -contains $ServiceName

    if ($isConnected) {
        $foregroundColor = $script:MSProfileState.ForegroundColor
        Write-ColorOutput -Text $ServiceName, " is already connected." -Color Yellow, $foregroundColor
    }

    return $isConnected
}
