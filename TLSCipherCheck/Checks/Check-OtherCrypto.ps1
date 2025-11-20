# Check-OtherCrypto.ps1

$results = @()

# 1. Key Exchange Algorithms
$keyExchanges = @("Diffie-Hellman", "PKCS", "ECDH")
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms"

foreach ($alg in $keyExchanges) {
    $path = "$basePath\$alg"
    $checkName = "KeyExchange - $alg"
    
    if (Test-Path $path) {
        $enabled = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
        $enabledVal = if ($enabled) { $enabled.Enabled } else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = $checkName
            Value     = "Enabled: $enabledVal"
            Details   = "Registry key present"
            RawData   = @{ Enabled = $enabledVal }
        }
        
        # Check key bit lengths
        if ($alg -eq "Diffie-Hellman") {
            $serverMin = Get-ItemProperty -Path $path -Name "ServerMinKeyBitLength" -ErrorAction SilentlyContinue
            $clientMin = Get-ItemProperty -Path $path -Name "ClientMinKeyBitLength" -ErrorAction SilentlyContinue
            
            $results += [PSCustomObject]@{
                CheckName = "KeyExchange - $alg - ServerMinKeyBitLength"
                Value     = if ($serverMin) { $serverMin.ServerMinKeyBitLength } else { "Missing" }
                Details   = "Minimum server key bit length (Recommended: 2048)"
                RawData   = @{ ServerMinKeyBitLength = if ($serverMin) { $serverMin.ServerMinKeyBitLength } else { "Missing" } }
            }
            
            $results += [PSCustomObject]@{
                CheckName = "KeyExchange - $alg - ClientMinKeyBitLength"
                Value     = if ($clientMin) { $clientMin.ClientMinKeyBitLength } else { "Missing" }
                Details   = "Minimum client key bit length (Recommended: 2048)"
                RawData   = @{ ClientMinKeyBitLength = if ($clientMin) { $clientMin.ClientMinKeyBitLength } else { "Missing" } }
            }
        }
        elseif ($alg -eq "PKCS") {
            $clientMin = Get-ItemProperty -Path $path -Name "ClientMinKeyBitLength" -ErrorAction SilentlyContinue
            
            $results += [PSCustomObject]@{
                CheckName = "KeyExchange - $alg - ClientMinKeyBitLength"
                Value     = if ($clientMin) { $clientMin.ClientMinKeyBitLength } else { "Missing" }
                Details   = "Minimum client key bit length (Recommended: 2048)"
                RawData   = @{ ClientMinKeyBitLength = if ($clientMin) { $clientMin.ClientMinKeyBitLength } else { "Missing" } }
            }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = $checkName
            Value     = "Key Missing"
            Details   = "Registry key not found (System Default)"
            RawData   = $null
        }
    }
}

# 2. FIPS Mode
$fipsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
if (Test-Path $fipsPath) {
    $fips = Get-ItemProperty -Path $fipsPath -Name "Enabled" -ErrorAction SilentlyContinue
    $fipsVal = if ($fips) { $fips.Enabled } else { "Missing" }
    
    $results += [PSCustomObject]@{
        CheckName = "FIPS Mode"
        Value     = "Enabled: $fipsVal"
        Details   = "FipsAlgorithmPolicy"
        RawData   = @{ Enabled = $fipsVal }
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "FIPS Mode"
        Value     = "Key Missing"
        Details   = "FipsAlgorithmPolicy key not found"
        RawData   = $null
    }
}

# 3. Cipher Suite Order
$cipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
if (Test-Path $cipherOrderPath) {
    $functions = Get-ItemProperty -Path $cipherOrderPath -Name "Functions" -ErrorAction SilentlyContinue
    $functionsVal = if ($functions) { $functions.Functions } else { "Not Configured" }
    
    # If it's a multi-string, join it
    if ($functionsVal -is [array]) {
        $functionsVal = $functionsVal -join ", "
    }

    $results += [PSCustomObject]@{
        CheckName = "Cipher Suite Order"
        Value     = "Configured"
        Details   = "GPO Enforced Order present"
        RawData   = $functionsVal
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "Cipher Suite Order"
        Value     = "Default"
        Details   = "No GPO enforcement found"
        RawData   = $null
    }
}

# 4. WinHTTP Default Secure Protocols
$winHttpPaths = @(
    @{ Name = "WinHTTP (64-bit)"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" },
    @{ Name = "WinHTTP (32-bit)"; Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" }
)

foreach ($item in $winHttpPaths) {
    if (Test-Path $item.Path) {
        $defaultSecProto = Get-ItemProperty -Path $item.Path -Name "DefaultSecureProtocols" -ErrorAction SilentlyContinue
        $protoVal = if ($defaultSecProto) { 
            "0x{0:X} ({1})" -f $defaultSecProto.DefaultSecureProtocols, $defaultSecProto.DefaultSecureProtocols
        }
        else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = "$($item.Name) - DefaultSecureProtocols"
            Value     = $protoVal
            Details   = "WinHTTP secure protocols (2048=TLS1.2, 2560=TLS1.2+1.1)"
            RawData   = @{ DefaultSecureProtocols = if ($defaultSecProto) { $defaultSecProto.DefaultSecureProtocols } else { "Missing" } }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = "$($item.Name) - DefaultSecureProtocols"
            Value     = "Key Missing"
            Details   = "Registry key not found"
            RawData   = $null
        }
    }
}

# 5. Internet Explorer Secure Protocols
$iePaths = @(
    @{ Name = "IE (HKLM)"; Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" },
    @{ Name = "IE (HKCU)"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
)

foreach ($item in $iePaths) {
    if (Test-Path $item.Path) {
        $secProto = Get-ItemProperty -Path $item.Path -Name "SecureProtocols" -ErrorAction SilentlyContinue
        $protoVal = if ($secProto) { 
            "0x{0:X} ({1})" -f $secProto.SecureProtocols, $secProto.SecureProtocols
        }
        else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = "$($item.Name) - SecureProtocols"
            Value     = $protoVal
            Details   = "Internet Explorer secure protocols (2048=TLS1.2)"
            RawData   = @{ SecureProtocols = if ($secProto) { $secProto.SecureProtocols } else { "Missing" } }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = "$($item.Name) - SecureProtocols"
            Value     = "Key Missing"
            Details   = "Registry key not found"
            RawData   = $null
        }
    }
}

return $results
