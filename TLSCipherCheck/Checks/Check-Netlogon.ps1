# Check-Netlogon.ps1

$results = @()
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"

# List of values to check
$valuesToCheck = @(
    "RequireSignOrSeal",
    "SealSecureChannel",
    "SignSecureChannel",
    "RequireStrongKey",
    "RefusePasswordChange",
    "MaximumPasswordAge",
    "DisablePasswordChange"
)

if (Test-Path $basePath) {
    $props = Get-ItemProperty -Path $basePath -ErrorAction SilentlyContinue

    foreach ($valName in $valuesToCheck) {
        $checkName = "Netlogon - $valName"
        
        if ($props.PSObject.Properties.Match($valName).Count -gt 0) {
            $valData = $props.$valName
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "$($valName): $valData"
                Details   = "Registry value present"
                RawData   = @{ $valName = $valData }
            }
        }
        else {
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "Value Missing"
                Details   = "Registry value not found"
                RawData   = $null
            }
        }
    }
}
else {
    foreach ($valName in $valuesToCheck) {
        $results += [PSCustomObject]@{
            CheckName = "Netlogon - $valName"
            Value     = "Key Missing"
            Details   = "Netlogon Parameters key not found"
            RawData   = $null
        }
    }
}

return $results
