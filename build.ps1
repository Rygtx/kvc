[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$SourceRoot = Join-Path $ProjectRoot "kvc"
$Projects = @(
    "implementer.vcxproj",
    "kvc.vcxproj",
    "kvc_crypt.vcxproj",
    "kvc_pass.vcxproj",
    "KvcXor.vcxproj"
)

function Write-Info([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Step([string]$Message) {
    Write-Host $Message -ForegroundColor DarkGray
}

function Write-Success([string]$Message) {
    Write-Host $Message -ForegroundColor Green
}

function Write-Failure([string]$Message) {
    Write-Host $Message -ForegroundColor Red
}

function Get-LatestVsPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installationPath = & $vswhere -products * -requires Microsoft.Component.MSBuild -property installationPath -latest
        if ($installationPath) {
            return $installationPath.Trim()
        }
        
        $installationPath = & $vswhere -products * -requires Microsoft.Component.MSBuild -property installationPath -latest -prerelease
        if ($installationPath) {
            return $installationPath.Trim()
        }
    }

    $vsVersions = @("18", "17", "16")
    foreach ($ver in $vsVersions) {
        $path = Join-Path ${env:ProgramFiles} "Microsoft Visual Studio\$ver"
        if (Test-Path $path) {
            $edition = Get-ChildItem $path -Directory | Select-Object -First 1
            if ($edition) {
                return $edition.FullName
            }
        }
    }

    throw "Visual Studio with MSBuild was not found."
}

try {
    Write-Info "Starting KVC Framework Build."

    # 1. Clean previous build artifacts (keep 'bin' and 'kvc')
    Write-Info "Cleaning output directories..."
    $ExcludedDirs = @("bin", "kvc")
    Get-ChildItem -Path $ProjectRoot -Directory |
        Where-Object { $_.Name -notin $ExcludedDirs } |
        ForEach-Object {
            Write-Step "Removing $($_.FullName)"
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }

    Write-Info "Locating the newest Visual Studio instance."
    $vsPath = Get-LatestVsPath
    Write-Step "Using Visual Studio at $vsPath"

    $msbuild = Get-ChildItem -Path $vsPath -Filter "MSBuild.exe" -Recurse | 
               Where-Object { $_.FullName -match "amd64" } | 
               Select-Object -ExpandProperty FullName -First 1

    if (-not $msbuild) {
        $msbuild = Get-ChildItem -Path $vsPath -Filter "MSBuild.exe" -Recurse | 
                   Select-Object -ExpandProperty FullName -First 1
    }

    if (-not $msbuild -or -not (Test-Path -LiteralPath $msbuild)) {
        throw "MSBuild.exe was not found under: $vsPath"
    }

    Write-Step "Using MSBuild at $msbuild"

    foreach ($project in $Projects) {
        $projectPath = Join-Path $SourceRoot $project
        if (-not (Test-Path -LiteralPath $projectPath)) {
            Write-Failure "Project file not found: $projectPath"
            continue
        }

        Write-Info "Building $project..."
        # Pass SolutionDir explicitly so vcxproj uses the root bin/ folder like slnx does
        & $msbuild $projectPath /p:Configuration=$Configuration /p:Platform=$Platform /p:SolutionDir="$ProjectRoot\" /m /nologo /v:m
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Successfully built $project"
        } else {
            throw "Failed to build $project with exit code $LASTEXITCODE"
        }
    }

    Write-Success "KVC Framework build completed successfully."
}
catch {
    Write-Failure $_.Exception.Message
    exit 1
}

