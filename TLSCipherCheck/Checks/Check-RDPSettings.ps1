# Check-RDPSettings.ps1

$results = @()

$rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

if (Test-Path $rdpPath) {
    # Security Layer
    $secLayer = Get-ItemProperty -Path $rdpPath -Name "SecurityLayer" -ErrorAction SilentlyContinue
    $secLayerVal = if ($secLayer) { $secLayer.SecurityLayer } else { "Not Set" }
    $secLayerLabel = switch ($secLayerVal) {
        0 { "RDP Security" }
        1 { "Negotiate" }
        2 { "SSL (TLS)" }
        Default { "Unknown ($secLayerVal)" }
    }
    
    $results += [PSCustomObject]@{
        CheckName = "RDP - SecurityLayer"
        Value     = "$secLayerVal ($secLayerLabel)"
        Details   = "Security Layer configuration"
        RawData   = $secLayerVal
    }
    
    # Encryption Level
    $encLevel = Get-ItemProperty -Path $rdpPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
    $encLevelVal = if ($encLevel) { $encLevel.MinEncryptionLevel } else { "Not Set" }
    $encLevelLabel = switch ($encLevelVal) {
        1 { "Low" }
        2 { "Client Compatible" }
        3 { "High" }
        4 { "FIPS" }
        Default { "Unknown ($encLevelVal)" }
    }
    
    $results += [PSCustomObject]@{
        CheckName = "RDP - MinEncryptionLevel"
        Value     = "$encLevelVal ($encLevelLabel)"
        Details   = "Encryption Level configuration"
        RawData   = $encLevelVal
    }
    
    # NLA
    $nla = Get-ItemProperty -Path $rdpPath -Name "UserAuthentication" -ErrorAction SilentlyContinue
    $nlaVal = if ($nla) { $nla.UserAuthentication } else { "Not Set" }
    $nlaLabel = if ($nlaVal -eq 1) { "Enabled" } elseif ($nlaVal -eq 0) { "Disabled" } else { "Unknown" }
    
    $results += [PSCustomObject]@{
        CheckName = "RDP - NLA (UserAuthentication)"
        Value     = "$nlaVal ($nlaLabel)"
        Details   = "Network Level Authentication"
        RawData   = $nlaVal
    }
    
    # Certificate
    $certHash = Get-ItemProperty -Path $rdpPath -Name "SSLCertificateSHA1Hash" -ErrorAction SilentlyContinue
    $certHashVal = if ($certHash) { 
        # Convert byte array to hex string
        ($certHash.SSLCertificateSHA1Hash | ForEach-Object { $_.ToString("X2") }) -join ""
    }
    else { 
        "Not Set" 
    }
    
    $results += [PSCustomObject]@{
        CheckName = "RDP - Certificate Thumbprint"
        Value     = $certHashVal
        Details   = "RDP Listener Certificate"
        RawData   = $certHashVal
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "RDP Settings"
        Value     = "Not Found"
        Details   = "RDP registry path not found"
        RawData   = $null
    }
}

return $results
