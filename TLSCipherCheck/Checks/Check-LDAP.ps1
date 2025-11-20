# Check-LDAP.ps1

$results = @()

# 1. Client Signing
$path = "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
$checkName = "LDAP - Client Signing"

if (Test-Path $path) {
    $val = Get-ItemProperty -Path $path -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
    $valData = if ($val) { $val.LDAPClientIntegrity } else { "Missing" }
    
    $results += [PSCustomObject]@{
        CheckName = $checkName
        Value     = "LDAPClientIntegrity: $valData"
        Details   = "Registry key present"
        RawData   = @{ LDAPClientIntegrity = $valData }
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = $checkName
        Value     = "Key Missing"
        Details   = "Registry key not found"
        RawData   = $null
    }
}

return $results
