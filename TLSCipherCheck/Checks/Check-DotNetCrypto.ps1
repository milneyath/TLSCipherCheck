# Check-DotNetCrypto.ps1

$results = @()

$paths = @(
    @{ Name = ".NET v4 (64-bit)"; Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" },
    @{ Name = ".NET v4 (32-bit)"; Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" },
    @{ Name = ".NET v2 (64-bit)"; Path = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" },
    @{ Name = ".NET v2 (32-bit)"; Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" }
)

foreach ($item in $paths) {
    $checkNameBase = "DotNet - $($item.Name)"
    
    if (Test-Path $item.Path) {
        # SchUseStrongCrypto
        $strongCrypto = Get-ItemProperty -Path $item.Path -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        $strongVal = if ($strongCrypto) { $strongCrypto.SchUseStrongCrypto } else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = "$checkNameBase - SchUseStrongCrypto"
            Value     = $strongVal
            Details   = "Registry key value"
            RawData   = @{ SchUseStrongCrypto = $strongVal }
        }

        # SystemDefaultTlsVersions
        $sysDef = Get-ItemProperty -Path $item.Path -Name "SystemDefaultTlsVersions" -ErrorAction SilentlyContinue
        $sysDefVal = if ($sysDef) { $sysDef.SystemDefaultTlsVersions } else { "Missing" }
        
        $results += [PSCustomObject]@{
            CheckName = "$checkNameBase - SystemDefaultTlsVersions"
            Value     = $sysDefVal
            Details   = "Registry key value"
            RawData   = @{ SystemDefaultTlsVersions = $sysDefVal }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = $checkNameBase
            Value     = "Key Missing"
            Details   = "Parent registry key not found"
            RawData   = $null
        }
    }
}

return $results
