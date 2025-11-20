# Check-SMB.ps1

$results = @()

# Check if Get-SmbServerConfiguration exists (Server 2012+)
if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    try {
        $smbConfig = Get-SmbServerConfiguration
        
        # Protocol Versions
        $results += [PSCustomObject]@{
            CheckName = "SMB - v1 Protocol"
            Value     = "Enabled: $($smbConfig.EnableSMB1Protocol)"
            Details   = "Should be False"
            RawData   = $smbConfig.EnableSMB1Protocol
        }
        
        $results += [PSCustomObject]@{
            CheckName = "SMB - v2/v3 Protocol"
            Value     = "Enabled: $($smbConfig.EnableSMB2Protocol)"
            Details   = "Should be True"
            RawData   = $smbConfig.EnableSMB2Protocol
        }
        
        # Security
        $results += [PSCustomObject]@{
            CheckName = "SMB - Require Security Signature"
            Value     = "$($smbConfig.RequireSecuritySignature)"
            Details   = "Signing Required"
            RawData   = $smbConfig.RequireSecuritySignature
        }
        
        $results += [PSCustomObject]@{
            CheckName = "SMB - Encrypt Data"
            Value     = "$($smbConfig.EncryptData)"
            Details   = "Encryption Required (SMB3)"
            RawData   = $smbConfig.EncryptData
        }
    }
    catch {
        $results += [PSCustomObject]@{
            CheckName = "SMB Configuration"
            Value     = "Error"
            Details   = "Failed to get SMB configuration: $_"
            RawData   = $_
        }
    }
}
else {
    # Fallback for older OS (Registry)
    $smb1Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    if (Test-Path $smb1Path) {
        $smb1 = Get-ItemProperty -Path $smb1Path -Name "SMB1" -ErrorAction SilentlyContinue
        $smb1Val = if ($smb1) { $smb1.SMB1 } else { "Default (Enabled on old OS)" }
        
        $results += [PSCustomObject]@{
            CheckName = "SMB - v1 Protocol (Registry)"
            Value     = "SMB1: $smb1Val"
            Details   = "Checked via Registry"
            RawData   = $smb1Val
        }
    }
}

return $results
