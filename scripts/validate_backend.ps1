$baseUrl = "http://localhost:5059/api"
$username = "testvalidator"
$password = "Password123!"
$email = "test@example.com"

# 1. Try Register
$regBody = @{
    username = $username
    email = $email
    password = $password
} | ConvertTo-Json

Write-Host "Attempting Register..."
try {
    $regResponse = Invoke-RestMethod -Uri "$baseUrl/auth/register" -Method Post -Body $regBody -ContentType "application/json" -ErrorAction Stop
    $token = $regResponse.token
    Write-Host "Registration Successful. Token obtained."
} catch {
    Write-Host "Registration failed or user exists: $($_.Exception.Message)"
    # 2. Try Login
    $loginBody = @{
        username = $username
        password = $password
    } | ConvertTo-Json
    
    Write-Host "Attempting Login..."
    try {
        $loginResponse = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -ErrorAction Stop
        $token = $loginResponse.token
        Write-Host "Login Successful. Token obtained."
        Write-Host "Token: $token"
    } catch {
        Write-Host "Login failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader $_.Exception.Response.GetResponseStream()
            $responseBody = $reader.ReadToEnd()
            Write-Host "Login Error Body: $responseBody"
        }
        exit
    }
}

if (-not $token) {
    Write-Host "No token obtained. Exiting."
    exit
}

# 3. Trigger Scan
$scanBody = @{
    path = "C:\Users\sover\Desktop\netcores\run-aspnetcore-microservices"
    isAdvanced = $true
} | ConvertTo-Json

$headers = @{
    Authorization = "Bearer $token"
}

Write-Host "Triggering Advanced Scan..."
try {
    $scanResponse = Invoke-RestMethod -Uri "$baseUrl/scan/local" -Method Post -Body $scanBody -ContentType "application/json" -Headers $headers -ErrorAction Stop
    Write-Host "Scan Triggered Successfully!"
    Write-Host "Job ID: $($scanResponse.jobId)"
    
    $jobId = $scanResponse.jobId
    
    # Poll progress
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 5
        try {
            $progress = Invoke-RestMethod -Uri "$baseUrl/scan/progress/$jobId" -Method Get -Headers $headers -ErrorAction Stop
            Write-Host "Progress: Status=$($progress.status), Stage=$($progress.stage), Files=$($progress.processedFiles)/$($progress.totalFiles), %=$($progress.percentage)"
            
            if ($progress.status -eq "Completed" -or $progress.status -eq "Failed") {
                break
            }
        }
        catch {
            Write-Host "Error polling progress: $_"
        }
    }
} catch {
    Write-Host "Scan Trigger Failed: $($_.Exception.Message)"
    # Print detailed error if available
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader $_.Exception.Response.GetResponseStream()
        $responseBody = $reader.ReadToEnd()
        Write-Host "Error Body: $responseBody"
    }
}