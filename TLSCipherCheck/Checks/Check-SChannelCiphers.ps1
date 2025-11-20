# Check-SChannelCiphers.ps1

$ciphers = @("NULL", "DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128", "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "Triple DES 168", "AES 128/128", "AES 256/256")
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

$results = @()

foreach ($cipher in $ciphers) {
    $path = "$basePath\$cipher"
    $checkName = "Cipher - $cipher"
    
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
