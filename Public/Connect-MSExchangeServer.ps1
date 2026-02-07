function Connect-MSExchangeServer {
    <#
    .SYNOPSIS
        Connects to an on-premises Exchange Server.

    .DESCRIPTION
        Establishes a PowerShell remote session to an on-premises Exchange Server
        using Kerberos authentication.

    .PARAMETER ServerFQDN
        The fully qualified domain name of the Exchange Server.

    .PARAMETER Credential
        A PSCredential object for authentication.

    .EXAMPLE
        Connect-MSExchangeServer -ServerFQDN "exchange.contoso.com"

    .EXAMPLE
        Connect-MSExchangeServer -ServerFQDN "exchange.contoso.com" -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ServerFQDN,

        [PSCredential]$Credential
    )

    $serviceName = 'ExchangeServer'

    try {
        # Check if already connected
        if (Test-AlreadyConnected -ServiceName $serviceName) {
            return
        }

        Write-Host "`t Connecting to $serviceName" -ForegroundColor Cyan

        # Get server FQDN if not provided
        if (-not $ServerFQDN) {
            $ServerFQDN = Read-Host -Prompt "`tEnter Exchange Server FQDN"
        }

        if ([string]::IsNullOrWhiteSpace($ServerFQDN)) {
            Write-Warning "Server FQDN is required"
            return
        }

        # Get credential
        $cred = if ($Credential) { $Credential } else { $script:MSProfileState.Credential }
        if (-not $cred) {
            Write-Warning "No credential available. Use Add-MSAccount to configure credentials or provide -Credential parameter."
            return
        }

        # Create PSSession
        $connectionUri = "http://$ServerFQDN/PowerShell/"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $connectionUri -Authentication Kerberos -Credential $cred -ErrorAction Stop

        # Import the session
        Import-PSSession $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

        # Store session for later disconnect
        $script:MSProfileState.ExchangeServerSession = $session

        Update-ConnectedServices -ServiceName $serviceName

    } catch {
        Write-Warning "`tUnable to connect to Exchange Server"
        Write-Warning $Error[0].Exception.Message
        Write-Warning "Ensure Kerberos authentication is configured and credentials are valid."
    }
}
