<#
.SYNOPSIS
    Copy reference documentation files from source directories to the project ReferenceDocs folder.

.DESCRIPTION
    This script reads the list of required documentation files from used-docs.txt and copies them
    from the configurable source directories (SQLServerDocs and WindowsServerDocs) to the project's
    ReferenceDocs folder, preserving the directory structure.

.PARAMETER SQLServerDocsSource
    Path to the source SQLServerDocs directory

.PARAMETER WindowsServerDocsSource
    Path to the source WindowsServerDocs directory

.PARAMETER ProjectRoot
    Path to the project root directory (defaults to script location)
 

.EXAMPLE
    .\Update-ReferenceDocs.ps1 -SQLServerDocsSource "C:\docs\sql-docs" -WindowsServerDocsSource "C:\docs\windowsserverdocs"

.EXAMPLE
    .\Update-ReferenceDocs.ps1 -SQLServerDocsSource "C:\docs\sql-docs" -WindowsServerDocsSource "C:\docs\windowsserverdocs" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the source SQLServerDocs directory")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$SQLServerDocsSource,

    [Parameter(Mandatory = $true, HelpMessage = "Path to the source WindowsServerDocs directory")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$WindowsServerDocsSource,

    [Parameter(Mandatory = $false)]
    [string]$ProjectRoot = $PSScriptRoot 
)

# Read the list of required documentation files
$usedDocsFile = Join-Path $ProjectRoot "used-docs.txt"
if (-not (Test-Path $usedDocsFile)) {
    Write-Error "Could not find used-docs.txt at: $usedDocsFile"
    exit 1
}

Write-Host "Reading required documentation files from: $usedDocsFile" -ForegroundColor Cyan
$content = Get-Content $usedDocsFile

# Parse the file paths (skip comments and empty lines)
$filePaths = $content | Where-Object { 
    $_ -match '^\./ReferenceDocs/' 
} | ForEach-Object { 
    $_.Trim() 
}

Write-Host "Found $($filePaths.Count) documentation files to copy" -ForegroundColor Green
Write-Host ""

# Statistics
$stats = @{
    Copied  = 0
    Skipped = 0
    Missing = 0
    Errors  = 0
}

foreach ($relativePath in $filePaths) {
    # Remove the .\ReferenceDocs\ prefix
    $pathWithoutPrefix = $relativePath -replace '^\./ReferenceDocs/', ''
    
    # Determine source directory
    if ($pathWithoutPrefix -like 'SQLServerDocs/*') {
        $sourceBase = $SQLServerDocsSource
        $relativeToBase = $pathWithoutPrefix -replace '^SQLServerDocs/', ''
    }
    elseif ($pathWithoutPrefix -like 'WindowsServerDocs/*') {
        $sourceBase = $WindowsServerDocsSource
        $relativeToBase = $pathWithoutPrefix -replace '^WindowsServerDocs/', ''
    }
    else {
        Write-Warning "Unknown documentation path: $pathWithoutPrefix"
        $stats.Errors++
        continue
    }

    # Build source and destination paths
    $sourcePath = Join-Path $sourceBase $relativeToBase
    $destinationPath = Join-Path $ProjectRoot (Join-Path "ReferenceDocs" $pathWithoutPrefix)

    # Check if source file exists
    if (-not (Test-Path $sourcePath -PathType Leaf)) {
        Write-Warning "Source file not found: $sourcePath"
        $stats.Missing++
        continue
    }

    # Check if destination file already exists and is up to date
    if (Test-Path $destinationPath -PathType Leaf) {
        $sourceHash = Get-FileHash $sourcePath -Algorithm MD5
        $destHash = Get-FileHash $destinationPath -Algorithm MD5
        
        if ($sourceHash.Hash -eq $destHash.Hash) {
            Write-Host "[SKIP] $pathWithoutPrefix (already up to date)" -ForegroundColor DarkGray
            $stats.Skipped++
            continue
        }
    }

    # Create destination directory if it doesn't exist
    $destinationDir = Split-Path $destinationPath -Parent
    if (-not (Test-Path $destinationDir)) {
        if ($WhatIf) {
            Write-Host "[WHATIF] Would create directory: $destinationDir" -ForegroundColor Yellow
        }
        else {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
        }
    }

    # Copy the file
    if ($WhatIf) {
        Write-Host "[WHATIF] Would copy: $pathWithoutPrefix" -ForegroundColor Yellow
        $stats.Copied++
    }
    else {
        try {
            Copy-Item -Path $sourcePath -Destination $destinationPath -Force
            Write-Host "[COPY] $pathWithoutPrefix" -ForegroundColor Green
            $stats.Copied++
        }
        catch {
            Write-Error "Failed to copy $pathWithoutPrefix : $_"
            $stats.Errors++
        }
    }
}

# Summary
Write-Host ""
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  Copied:  $($stats.Copied)" -ForegroundColor Green
Write-Host "  Skipped: $($stats.Skipped) (already up to date)" -ForegroundColor DarkGray
Write-Host "  Missing: $($stats.Missing)" -ForegroundColor Yellow
Write-Host "  Errors:  $($stats.Errors)" -ForegroundColor Red
Write-Host "===============================================" -ForegroundColor Cyan

if ($stats.Missing -gt 0) {
    Write-Warning "Some source files were not found. Please verify your source directory paths."
}

if ($stats.Errors -gt 0) {
    Write-Error "Some files failed to copy. Please review the errors above."
    exit 1
}

Write-Host ""
if ($WhatIf) {
    Write-Host "WhatIf mode - no files were actually copied" -ForegroundColor Yellow
}
else {
    Write-Host "Documentation update complete!" -ForegroundColor Green
}
