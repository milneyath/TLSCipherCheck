# Check-WinRM.ps1

$results = @()

# Ensure WSMan drive is available
if (-not (Get-PSDrive -Name WSMan -ErrorAction SilentlyContinue)) {
    try {
        New-PSDrive -Name WSMan -PSProvider WSMan -Root "Localhost" -ErrorAction Stop | Out-Null
    }
    catch {
        return [PSCustomObject]@{
            CheckName = "WinRM Check"
            Value     = "Error"
            Details   = "Failed to map WSMan drive: $_"
            RawData   = $_
        }
    }
}

try {
    # 1. Service Configuration
    $servicePath = "WSMan:\localhost\Service"
    if (Test-Path $servicePath) {
        # AllowUnencrypted
        $allowUnencrypted = Get-ItemProperty -Path $servicePath -Name "AllowUnencrypted" -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            CheckName = "WinRM Service - AllowUnencrypted"
            Value     = "$($allowUnencrypted.Value)"
            Details   = "Service Configuration"
            RawData   = $allowUnencrypted.Value
        }

        # Auth
        $authPath = "$servicePath\Auth"
        $authProps = Get-Item $authPath
        $authMethods = @("Basic", "Kerberos", "Negotiate", "CredSSP", "Certificate", "CbtHardeningLevel")
        
        foreach ($method in $authMethods) {
            # Some properties might be missing on older OS, handle gracefully
            try {
                $val = $authProps.Property($method).Value
                $results += [PSCustomObject]@{
                    CheckName = "WinRM Auth - $method"
                    Value     = "$val"
                    Details   = "Authentication Method"
                    RawData   = $val
                }
            }
            catch {
                # Property might not exist
            }
        }
    }

    # 2. Listeners
    $listenerPath = "WSMan:\localhost\Listener"
    if (Test-Path $listenerPath) {
        $listeners = Get-ChildItem -Path $listenerPath
        
        if ($listeners) {
            foreach ($listener in $listeners) {
                # Listener names are like "Listener_123456..."
                # We need to dig into keys to find Transport
                # Usually keys are "Transport=HTTP,Address=*"

                
                # Get properties
                $transport = Get-ItemProperty -Path $listener.PSPath -Name "Transport" -ErrorAction SilentlyContinue
                $port = Get-ItemProperty -Path $listener.PSPath -Name "Port" -ErrorAction SilentlyContinue
                $thumbprint = Get-ItemProperty -Path $listener.PSPath -Name "CertificateThumbprint" -ErrorAction SilentlyContinue
                
                $details = "Port: $($port.Value)"
                if ($thumbprint.Value) {
                    $details += "; Cert: $($thumbprint.Value)"
                }

                $results += [PSCustomObject]@{
                    CheckName = "WinRM Listener - $($listener.Name)"
                    Value     = "Transport: $($transport.Value)"
                    Details   = $details
                    RawData   = @{ Transport = $transport.Value; Port = $port.Value; Thumbprint = $thumbprint.Value }
                }
            }
        }
        else {
            $results += [PSCustomObject]@{
                CheckName = "WinRM Listeners"
                Value     = "None"
                Details   = "No listeners found"
                RawData   = $null
            }
        }
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "WinRM Check"
        Value     = "Error"
        Details   = "Failed to query WSMan: $_"
        RawData   = $_
    }
}

return $results
