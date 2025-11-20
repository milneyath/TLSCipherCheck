# AuditUtils.psm1
# Utility functions for the Crypto Audit Script

# Global state for logging
$Script:LogFile = $null

function Initialize-AuditLog {
    param (
        [string]$Path
    )
    $Script:LogFile = $Path
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    "Timestamp,Level,Message" | Out-File -FilePath $Script:LogFile -Encoding utf8
}

function Write-AuditLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp,$Level,$Message"
    
    # Write to console with color
    $color = switch ($Level) {
        "INFO" { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color

    # Write to file if initialized
    if ($Script:LogFile) {
        $logLine | Out-File -FilePath $Script:LogFile -Append -Encoding utf8
    }
}

function New-AuditReportStructure {
    param (
        [string]$BasePath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportRoot = Join-Path $BasePath "AuditRun_$timestamp"
    
    try {
        New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
        Write-AuditLog -Message "Created report directory: $reportRoot" -Level "SUCCESS"
        return $reportRoot
    }
    catch {
        Write-AuditLog -Message "Failed to create report directory: $_" -Level "ERROR"
        throw
    }
}

function Invoke-RemoteCheck {
    param (
        [string]$ComputerName,
        [PSCredential]$Credential,
        [string]$CheckScriptPath,
        [hashtable]$Arguments = @{}
    )

    Write-AuditLog -Message "Starting check on $ComputerName : $(Split-Path $CheckScriptPath -Leaf)"
    
    try {
        # Read the script content to pass as a scriptblock
        # We use this approach to ensure local modules/functions aren't a dependency on the remote side
        # unless we explicitly copy them. For simple checks, sending the scriptblock is easier.
        $scriptContent = Get-Content $CheckScriptPath -Raw
        $scriptBlock = [ScriptBlock]::Create($scriptContent)

        $params = @{
            ScriptBlock  = $scriptBlock
            ArgumentList = $Arguments
            ErrorAction  = "Stop"
        }
        
        $isLocal = ($ComputerName -eq "localhost") -or ($ComputerName -eq "127.0.0.1") -or ($ComputerName -eq ".") -or ($ComputerName -eq $env:COMPUTERNAME)
        
        if (-not $isLocal) {
            $params["ComputerName"] = $ComputerName
            if ($Credential) {
                $params["Credential"] = $Credential
            }
        }
        # If local, we ignore Credential usually as we are already running as the user
        
        $result = Invoke-Command @params
        
        return $result
    }
    catch {
        Write-AuditLog -Message "Failed to execute check on $ComputerName : $_" -Level "ERROR"
        return [PSCustomObject]@{
            CheckName = (Split-Path $CheckScriptPath -Leaf)
            Value     = "ERROR"
            Details   = "Execution failed: $($_.Exception.Message)"
            RawData   = $_
        }
    }
}

function Export-AuditZip {
    param (
        [string]$SourceDirectory,
        [string]$ZipPath
    )
    
    try {
        Compress-Archive -Path "$SourceDirectory\*" -DestinationPath $ZipPath -Force
        Write-AuditLog -Message "Successfully created ZIP archive: $ZipPath" -Level "SUCCESS"
    }
    catch {
        Write-AuditLog -Message "Failed to create ZIP archive: $_" -Level "ERROR"
    }
}

Export-ModuleMember -Function Initialize-AuditLog, Write-AuditLog, New-AuditReportStructure, Invoke-RemoteCheck, Export-AuditZip
