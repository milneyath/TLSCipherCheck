# TLSCipherCheck.psm1
# Main module for TLS Cipher Check Audit

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

function Invoke-TLSCipherAudit {
    param (
        [string]$ServerList = "servers.txt",
        [string]$OutputPath = ".\Output",
        [PSCredential]$Credential
    )

    # Initialize
    Initialize-AuditLog -Path (Join-Path $OutputPath "Audit_Log_$(Get-Date -Format 'yyyyMMdd-HHmmss').log")
    Write-AuditLog -Message "Starting Crypto Audit" -Level "INFO"

    # Create Report Structure
    $reportDir = New-AuditReportStructure -BasePath $OutputPath
    $csvPath = Join-Path $reportDir "Audit_Summary.csv"

    # Load Servers
    if (-not (Test-Path $ServerList)) {
        Write-AuditLog -Message "Server list file not found: $ServerList" -Level "ERROR"
        return
    }
    $servers = Get-Content $ServerList
    Write-AuditLog -Message "Loaded $( $servers.Count ) servers from list" -Level "INFO"

    # Load Checks
    # Checks are now located in the module directory under 'Checks'
    $checksPath = Join-Path $PSScriptRoot "Checks"
    if (-not (Test-Path $checksPath)) {
        Write-AuditLog -Message "Checks directory not found at $checksPath" -Level "ERROR"
        return
    }

    $checkFiles = Get-ChildItem $checksPath -Filter "Check-*.ps1"
    Write-AuditLog -Message "Loaded $( $checkFiles.Count ) check modules" -Level "INFO"

    $allResults = @()

    foreach ($server in $servers) {
        if ([string]::IsNullOrWhiteSpace($server)) { continue }
        
        Write-AuditLog -Message "Processing Server: $server" -Level "INFO"
        
        # Create server folder for detailed logs
        $serverDir = Join-Path $reportDir $server
        New-Item -ItemType Directory -Path $serverDir -Force | Out-Null
        
        $serverSummary = [ordered]@{
            ServerName = $server
            Timestamp  = Get-Date
        }
        
        foreach ($checkFile in $checkFiles) {
            $checkName = $checkFile.BaseName
            
            Write-AuditLog -Message "Running Check: $checkName" -Level "INFO"
            
            $checkResults = Invoke-RemoteCheck -ComputerName $server -Credential $Credential -CheckScriptPath $checkFile.FullName
            
            # Save detailed output to TXT
            $detailFile = Join-Path $serverDir "$($checkName).txt"
            $checkResults | Format-List | Out-File -FilePath $detailFile -Encoding utf8
            
            # Aggregate for CSV
            # We flatten the results: CheckName -> Value
            foreach ($res in $checkResults) {
                if ($res -is [PSCustomObject] -and $res.CheckName) {
                    # Add to summary object (handle duplicates if any by appending)
                    $key = $res.CheckName
                    $val = $res.Value
                    
                    if ($serverSummary.Contains($key)) {
                        $serverSummary[$key] = "$($serverSummary[$key]); $val"
                    }
                    else {
                        $serverSummary[$key] = $val
                    }
                }
            }
        }
        
        $allResults += [PSCustomObject]$serverSummary
    }

    # Export Summary CSV
    if ($allResults) {
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
        Write-AuditLog -Message "Exported summary CSV to $csvPath" -Level "SUCCESS"
    }
    else {
        Write-AuditLog -Message "No results to export" -Level "WARNING"
    }

    # Zip Report
    $zipPath = Join-Path $OutputPath "Audit_Report_$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
    Export-AuditZip -SourceDirectory $reportDir -ZipPath $zipPath

    Write-AuditLog -Message "Audit Complete. Results saved to $zipPath" -Level "SUCCESS"
}

Export-ModuleMember -Function Initialize-AuditLog, Write-AuditLog, New-AuditReportStructure, Invoke-RemoteCheck, Export-AuditZip, Invoke-TLSCipherAudit
