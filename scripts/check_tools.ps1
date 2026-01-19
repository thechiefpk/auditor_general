
# Script to check for Microsoft Presidio and Semgrep installation

Write-Host "Checking for Security Tools..." -ForegroundColor Cyan
Write-Host "--------------------------------"

# 1. Check Semgrep
Write-Host "1. Checking Semgrep..." -ForegroundColor Yellow
$semgrepFound = $false

# Check in PATH
if (Get-Command semgrep -ErrorAction SilentlyContinue) {
    Write-Host "   [OK] Semgrep found in PATH." -ForegroundColor Green
    semgrep --version
    $semgrepFound = $true
} else {
    Write-Host "   [INFO] Semgrep not found in global PATH. Checking fallback locations..."
    
    # Check specific Python Script paths
    $appData = [Environment]::GetFolderPath("ApplicationData") # Roaming
    $localAppData = [Environment]::GetFolderPath("LocalApplicationData") # Local
    
    $possiblePaths = @(
        "$appData\Python\Python314\Scripts\semgrep.exe",
        "$appData\Python\Python312\Scripts\semgrep.exe",
        "$localAppData\Programs\Python\Python314\Scripts\semgrep.exe",
        "$localAppData\Programs\Python\Python312\Scripts\semgrep.exe",
        "$appData\Python\Scripts\semgrep.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            Write-Host "   [OK] Semgrep found at: $path" -ForegroundColor Green
            
            # Temporarily add to PATH to ensure dependencies like pysemgrep are found
            $scriptDir = Split-Path -Parent $path
            $env:PATH = "$scriptDir;$env:PATH"
            
            & $path --version
            $semgrepFound = $true
            break
        }
    }
}

if (-not $semgrepFound) {
    Write-Host "   [FAIL] Semgrep is NOT installed." -ForegroundColor Red
    Write-Host "   To install: pip install semgrep"
}

Write-Host ""

# 2. Check Microsoft Presidio
Write-Host "2. Checking Microsoft Presidio..." -ForegroundColor Yellow

# Try checking with Python 3.12 (via py launcher) first, as it's the stable/supported version
$py312Available = $false
try {
    $ver = py -3.12 --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   [OK] Python 3.12 detected ($ver)" -ForegroundColor Green
        $py312Available = $true
    }
} catch {}

if ($py312Available) {
    Write-Host "   Checking Presidio in Python 3.12 environment..."
    try {
        py -3.12 -c "import presidio_analyzer; print('   [OK] Presidio import successful in Python 3.12')" 2>&1 | ForEach-Object {
            if ($_ -match "Error") {
                Write-Host "   [FAIL] Import failed: $_" -ForegroundColor Red
            } else {
                Write-Host $_
            }
        }
    } catch {
        Write-Host "   [FAIL] Python 3.12 execution failed." -ForegroundColor Red
    }
} else {
    Write-Host "   [INFO] Python 3.12 not found via 'py' launcher. Falling back to default 'python'..."
    
    # Fallback to default python check
    $pipCheck = pip show presidio-analyzer 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   [OK] presidio-analyzer package is installed (default python)." -ForegroundColor Green
        $pipCheck | Select-Object -First 2 | Write-Host
        
        # Try to import it to verify it works
        Write-Host "   Verifying import..."
        try {
            python -c "import presidio_analyzer; print('   [OK] Presidio import successful.')" 2>&1 | ForEach-Object {
                if ($_ -match "Error") {
                    Write-Host "   [WARNING] Presidio is installed but failed to import:" -ForegroundColor Magenta
                    Write-Host $_
                } else {
                    Write-Host $_
                }
            }
        } catch {
            Write-Host "   [FAIL] Python execution failed." -ForegroundColor Red
        }
    } else {
        Write-Host "   [FAIL] presidio-analyzer is NOT installed." -ForegroundColor Red
        Write-Host "   To install (recommended): winget install Python.Python.3.12; py -3.12 -m pip install presidio-analyzer presidio-anonymizer spacy pydantic; py -3.12 -m spacy download en_core_web_lg"
    }
}

Write-Host "--------------------------------"
Write-Host "Check Complete."
