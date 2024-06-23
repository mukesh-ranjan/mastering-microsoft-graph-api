# Read parameters from the text file
$configFilePath = "config.txt"
if (-Not (Test-Path -Path $configFilePath)) {
    Write-Host "Config file not found: $configFilePath"
    exit
}

$config = Get-Content -Path $configFilePath
$clientId = $config[0]
$clientSecret = $config[1]
$tenantId = $config[2]

$scope = "https://graph.microsoft.com/.default"
$authUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$endpoint = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
$outputFile = "UserLogonActivity.csv"

# Get access token
$response = Invoke-RestMethod -Method Post -Uri $authUrl -ContentType "application/x-www-form-urlencoded" -Body @{
    client_id     = $clientId
    client_secret = $clientSecret
    scope         = $scope
    grant_type    = "client_credentials"
}

if ($null -eq $response) {
    Write-Host "Failed to get access token."
    exit
}

$accessToken = $response.access_token

# Set headers
$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Initialize an array to store logon activity
$logonActivity = @()

# Function to get sign-in logs and handle pagination
function Get-SignInLogs {
    param (
        [string]$url
    )

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    if ($null -ne $response -and $null -ne $response.value) {
        foreach ($log in $response.value) {
            $logonActivity += , ([PSCustomObject]@{
                    UserPrincipalName = $log.userPrincipalName
                    SignInTime        = $log.createdDateTime
                    Status            = $log.status.errorCode
                })
        }

        # Handle pagination
        if ($null -ne $response.'@odata.nextLink') {
            Get-SignInLogs -url $response.'@odata.nextLink'
        }
    }
    else {
        Write-Host "No response or no log data received."
    }
    return $logonActivity
}

# Get the initial batch of sign-in logs
$logonDetails = Get-SignInLogs -url $endpoint

# Export to CSV
if ($logonDetails.Count -gt 0) {
    $logonDetails | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Host "User logon activity has been exported to $outputFile"
}
else {
    Write-Host "No logon activity data to export."
}
