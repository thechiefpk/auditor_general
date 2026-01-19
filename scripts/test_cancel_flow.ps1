# Test Cancel Flow
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$baseUrl = "https://localhost:7120/api"
$random = Get-Random -Minimum 1000 -Maximum 9999
$username = "testuser_$random"
$email = "test_$random@example.com"
$password = "TestPass123!"

# 0. Register
$registerBody = @{ username = $username; email = $email; password = $password } | ConvertTo-Json
try {
    Write-Host "Registering user $username..."
    $regRes = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method Post -Body $registerBody -ContentType "application/json"
    $token = $regRes.token
    Write-Host "Registration successful. Token: $token"
} catch {
    # If registration fails (maybe user exists?), try login
    Write-Host "Registration failed or user exists ($(_)), trying login..."
    $loginBody = @{ username = $username; password = $password } | ConvertTo-Json
    try {
        $loginRes = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
        $token = $loginRes.token
        Write-Host "Login successful. Token: $token"
    } catch {
        Write-Error "Login failed: $_"
        exit
    }
}

$headers = @{ Authorization = "Bearer $token" }

# 2. Start Advanced Scan
# Use a path that will take some time (e.g. the backend folder itself)
$scanPath = "C:\Users\sover\Desktop\Auditor_General\backend"
$scanBody = @{ path = $scanPath; isAdvanced = $true } | ConvertTo-Json

try {
    $scanRes = Invoke-RestMethod -Uri "$baseUrl/scan/local" -Method Post -Body $scanBody -Headers $headers -ContentType "application/json"
    $jobId = $scanRes.jobId
    Write-Host "Scan started. Job ID: $jobId"
} catch {
    Write-Error "Scan start failed: $_"
    exit
}

# 3. Poll for Process ID
Write-Host "Waiting for process to start..."
$maxRetries = 20
$processId = $null

for ($i = 0; $i -lt $maxRetries; $i++) {
    Start-Sleep -Seconds 2
    
    # Query DB directly to check for ProcessId (since API doesn't expose it yet, or we can add it to progress endpoint)
    # We'll use sqlcmd for verification
    $query = "SELECT ProcessId FROM dbo.ScanProgress WHERE JobId='$jobId'"
    # Note: This is a bit tricky to capture in PS variable via Invoke-Sqlcmd if not installed, 
    # so we'll just check if the progress stage changes to "Deep Scan" which implies the advanced pipeline started.
    
    try {
        $progress = Invoke-RestMethod -Uri "$baseUrl/scan/progress/$jobId" -Headers $headers
        Write-Host "Status: $($progress.status), Stage: $($progress.stage)"
        
        if ($progress.status -eq "Deep Scan" -or $progress.stage -like "*Deep Scan*") {
            Write-Host "Advanced scan appears to be running (Status: $($progress.status))."
            break
        }
    } catch {
        Write-Host "Error checking progress: $_"
    }
}

# 4. Cancel Scan
Write-Host "Cancelling scan..."
try {
    $cancelRes = Invoke-RestMethod -Uri "$baseUrl/scan/$jobId/cancel" -Method Post -Headers $headers
    Write-Host "Cancel requested: $($cancelRes.cancelled)"
} catch {
    Write-Error "Cancel failed: $_"
}

# 5. Verify Cancellation
Start-Sleep -Seconds 5
try {
    $finalProgress = Invoke-RestMethod -Uri "$baseUrl/scan/progress/$jobId" -Headers $headers
    Write-Host "Final Status: $($finalProgress.status)"
    if ($finalProgress.status -eq "Cancelled") {
        Write-Host "SUCCESS: Scan was cancelled."
    } else {
        Write-Host "FAILURE: Scan status is $($finalProgress.status)"
    }
} catch {
    Write-Error "Final check failed: $_"
}
