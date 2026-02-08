function Write-ColorOutput {
    <#
    .SYNOPSIS
        Writes colored output to the console.

    .DESCRIPTION
        Outputs text to the console with specified foreground colors for each text segment.

    .PARAMETER Text
        An array of text strings to output.

    .PARAMETER Color
        An array of ConsoleColor values corresponding to each text segment.

    .EXAMPLE
        Write-ColorOutput -Text "Hello ", "World" -Color Green, Yellow
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String[]]$Text,

        [Parameter(Mandatory)]
        [ConsoleColor[]]$Color
    )

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $foreground = if ($i -lt $Color.Length) { $Color[$i] } else { $Color[-1] }
        Write-Host $Text[$i] -ForegroundColor $foreground -NoNewline
    }
    Write-Host
}
