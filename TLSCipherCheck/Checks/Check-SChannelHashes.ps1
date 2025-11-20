# Check-SChannelHashes.ps1

$hashes = @("MD5", "SHA", "SHA256", "SHA384", "SHA512")
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes"

$results = @()

foreach ($hash in $hashes) {
    $path = "$basePath\$hash"
    $checkName = "Hash - $hash"
    
    if (Test-Path $path) {
        $enabled = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
        $enabledVal = if ($enabled) { $enabled.Enabled } else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = $checkName
            Value     = "Enabled: $enabledVal"
            Details   = "Registry key present"
            RawData   = @{ Enabled = $enabledVal }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = $checkName
            Value     = "Not Configured (System Default)"
            Details   = "Registry key not found. OS defaults apply."
            RawData   = $null
        }
    }
}

return $results
