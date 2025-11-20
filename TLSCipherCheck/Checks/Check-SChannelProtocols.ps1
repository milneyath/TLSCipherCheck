# Check-SChannelProtocols.ps1

$protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
$roles = @("Client", "Server")
$basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

$results = @()

foreach ($protocol in $protocols) {
    foreach ($role in $roles) {
        $path = "$basePath\$protocol\$role"
        $checkName = "Protocol - $protocol $role"
        
        if (Test-Path $path) {
            $enabled = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
            $disabledByDefault = Get-ItemProperty -Path $path -Name "DisabledByDefault" -ErrorAction SilentlyContinue
            
            $enabledVal = if ($enabled) { $enabled.Enabled } else { "Missing" }
            $disabledVal = if ($disabledByDefault) { $disabledByDefault.DisabledByDefault } else { "Missing" }
            
            $value = "Enabled: $enabledVal"
            $details = "DisabledByDefault: $disabledVal"
            
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = $value
                Details   = $details
                RawData   = @{ Enabled = $enabledVal; DisabledByDefault = $disabledVal }
            }
        }
        else {
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "Not Configured (System Default)"
                Details   = "Registry key not found. OS defaults apply. See: https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-"
                RawData   = $null
            }
        }
    }
}

return $results
