[CmdletBinding()]
param(
    [string]$PythonVersion = "3.12",
    [string]$VenvPath = ".venv",
    [switch]$Recreate
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvTarget = Join-Path $projectRoot $VenvPath
$pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
$basePython = $null
$basePythonArgs = @()

if ($pythonLauncher) {
    $available = & py -0p 2>&1
    if ($LASTEXITCODE -eq 0 -and $available -match [regex]::Escape($PythonVersion)) {
        $basePython = $pythonLauncher.Source
        $basePythonArgs = @("-$PythonVersion")
    }
}

if (-not $basePython) {
    $versionFolder = "Python" + $PythonVersion.Replace(".", "")
    $directPython = Join-Path $env:LOCALAPPDATA "Programs\Python\$versionFolder\python.exe"
    if (Test-Path -LiteralPath $directPython) {
        $basePython = $directPython
    }
}

if (-not $basePython) {
    throw "Python $PythonVersion is not installed. Install it from python.org, then rerun this script."
}

if ((Test-Path -LiteralPath $venvTarget) -and $Recreate) {
    $resolvedProject = (Resolve-Path -LiteralPath $projectRoot).Path
    $resolvedVenv = (Resolve-Path -LiteralPath $venvTarget).Path
    if (-not $resolvedVenv.StartsWith($resolvedProject + [IO.Path]::DirectorySeparatorChar)) {
        throw "Refusing to remove a virtual environment outside the project directory: $resolvedVenv"
    }
    Remove-Item -LiteralPath $resolvedVenv -Recurse -Force
}

if (-not (Test-Path -LiteralPath $venvTarget)) {
    & $basePython @basePythonArgs -m venv $venvTarget
}

$venvPython = Join-Path $venvTarget "Scripts\python.exe"
$testTemp = Join-Path $projectRoot ".test-tmp-$PID"
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
& $venvPython -m pip install -e "${projectRoot}[dev]"
if ($LASTEXITCODE -ne 0) { throw "dependency installation failed" }
try {
    & $venvPython -m pytest -p no:cacheprovider --basetemp=$testTemp --cov=nettrace --cov-report=term
    if ($LASTEXITCODE -ne 0) { throw "test suite failed" }
}
finally {
    # pytest leaves --basetemp behind on purpose (it retains recent runs), so
    # without this every setup run drops another .test-tmp-<PID> in the project
    # root. .gitignore hides them, which is exactly why they accumulate unnoticed.
    if (Test-Path -LiteralPath $testTemp) {
        Remove-Item -LiteralPath $testTemp -Recurse -Force
    }
}

Write-Host "Development environment ready: $venvTarget"
