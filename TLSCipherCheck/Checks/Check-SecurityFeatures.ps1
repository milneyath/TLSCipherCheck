# Check-SecurityFeatures.ps1

$results = @()

# 1. TPM Status
try {
    $tpm = Get-Tpm
    $tpmStatus = "Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady), Enabled: $($tpm.TpmEnabled)"
    $results += [PSCustomObject]@{
        CheckName = "Security - TPM"
        Value     = if ($tpm.TpmReady) { "Ready" } else { "Not Ready" }
        Details   = $tpmStatus
        RawData   = $tpm
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "Security - TPM"
        Value     = "Error"
        Details   = "Failed to query TPM: $_"
        RawData   = $_
    }
}

# 2. Credential Guard
try {
    $devGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($devGuard) {
        # SecurityServicesRunning is an array of integers. 1 = Credential Guard.
        $credGuardRunning = $devGuard.SecurityServicesRunning -contains 1
        $vbsStatus = $devGuard.VirtualizationBasedSecurityStatus
        
        $results += [PSCustomObject]@{
            CheckName = "Security - Credential Guard"
            Value     = if ($credGuardRunning) { "Running" } else { "Not Running" }
            Details   = "VBS Status: $vbsStatus; Services: $($devGuard.SecurityServicesRunning -join ',')"
            RawData   = $devGuard
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = "Security - Credential Guard"
            Value     = "Unknown"
            Details   = "Win32_DeviceGuard class not found (OS might be too old)"
            RawData   = $null
        }
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "Security - Credential Guard"
        Value     = "Error"
        Details   = "Failed to query Device Guard: $_"
        RawData   = $_
    }
}

# 3. LSA Protection (RunAsPPL)
try {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $runAsPPL = (Get-ItemProperty -Path $lsaKey -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    
    $val = if ($runAsPPL -eq 1) { "Enabled" } else { "Disabled" }
    $det = if ($runAsPPL) { "RunAsPPL = $runAsPPL" } else { "RunAsPPL registry value missing or 0" }

    $results += [PSCustomObject]@{
        CheckName = "Security - LSA Protection"
        Value     = $val
        Details   = $det
        RawData   = @{ RunAsPPL = $runAsPPL }
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "Security - LSA Protection"
        Value     = "Error"
        Details   = "Failed to query LSA registry: $_"
        RawData   = $_
    }
}

# 4. Memory Integrity (Hypervisor Enforced Code Integrity)
try {
    $hvciKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $hvci = (Get-ItemProperty -Path $hvciKey -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
    
    $val = if ($hvci -eq 1) { "Enabled" } else { "Disabled" }
    $det = if ($hvci) { "HVCI Enabled = $hvci" } else { "HVCI registry value missing or 0" }

    $results += [PSCustomObject]@{
        CheckName = "Security - Memory Integrity"
        Value     = $val
        Details   = $det
        RawData   = @{ HVCI = $hvci }
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "Security - Memory Integrity"
        Value     = "Error"
        Details   = "Failed to query HVCI registry: $_"
        RawData   = $_
    }
}

return $results
