@{
    # PSScriptAnalyzer settings for microsoftServicesProfile module
    #
    # This module is an interactive UI-focused tool where colored console output
    # via Write-Host is intentional behavior for user feedback and status display.

    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}
