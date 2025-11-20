# Check-SQLServer.ps1

$results = @()

# Helper function to get SQL Instance Certificate Info (User Provided)
function Get-SqlInstanceCertificateInfo {
    param(
        [Parameter(Mandatory)]
        [string]$InstanceId
    )

    $netlibKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\MSSQLServer\SuperSocketNetLib"
    if (-not (Test-Path $netlibKey)) { return $null }

    $props = Get-ItemProperty $netlibKey
    $thumb = $props.Certificate
    $force = $props.ForceEncryption

    if (-not $thumb) {
        return [pscustomobject]@{
            Thumbprint      = $null
            ForceEncryption = $force
            Certificate     = $null
        }
    }

    $thumb = $thumb -replace ' ', ''

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $cert = $store.Certificates | Where-Object { ($_.Thumbprint -replace ' ') -eq $thumb }
    $store.Close()

    [pscustomobject]@{
        Thumbprint      = $thumb
        ForceEncryption = $force
        Certificate     = $cert
    }
}

# Protocols to test
$protocols = @(
    "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2"
)

$protocolMap = @{
    "SSL 2.0" = [System.Security.Authentication.SslProtocols]::Ssl2
    "SSL 3.0" = [System.Security.Authentication.SslProtocols]::Ssl3
    "TLS 1.0" = [System.Security.Authentication.SslProtocols]::Tls
    "TLS 1.1" = [System.Security.Authentication.SslProtocols]::Tls11
    "TLS 1.2" = [System.Security.Authentication.SslProtocols]::Tls12
}

# Try to add TLS 1.3 if present
try {
    if ([Enum]::IsDefined([System.Security.Authentication.SslProtocols], "Tls13")) {
        $protocolMap["TLS 1.3"] = [System.Security.Authentication.SslProtocols]::Tls13
        $protocols += "TLS 1.3"
    }
    elseif ([Enum]::IsDefined([System.Security.Authentication.SslProtocols], 12288)) {
        $protocolMap["TLS 1.3"] = 12288
        $protocols += "TLS 1.3"
    }
}
catch {
    # TLS 1.3 not available in enum
}

# Discovery
$instancesKeyPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
$sqlInstances = @()

if (Test-Path $instancesKeyPath) {
    $instanceProps = Get-ItemProperty -Path $instancesKeyPath
    # Filter out PSPath, PSParentPath, etc.
    $propNames = $instanceProps.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name
    
    foreach ($name in $propNames) {
        $sqlInstances += [PSCustomObject]@{
            Name = $name
            ID   = $instanceProps.$name
        }
    }
}

if ($sqlInstances.Count -gt 0) {
    foreach ($inst in $sqlInstances) {
        $instanceName = $inst.Name
        $instanceId = $inst.ID
        
        # Version Check
        $setupKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\Setup"
        $version = "Unknown"
        $supportsTds8 = $false
        if (Test-Path $setupKey) {
            $verStr = (Get-ItemProperty $setupKey).Version
            $version = $verStr
            if ($verStr) {
                $major = [version]$verStr | Select-Object -ExpandProperty Major
                if ($major -ge 16) { $supportsTds8 = $true }
            }
        }

        # Cert & Encryption
        $certInfo = Get-SqlInstanceCertificateInfo -InstanceId $instanceId
        
        # Port Discovery
        $tcpKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        $port = 1433 # Default
        if (Test-Path $tcpKey) {
            $tcpProps = Get-ItemProperty $tcpKey
            $static = $tcpProps.TcpPort
            $dynamic = $tcpProps.TcpDynamicPorts

            if ($static -and $static -match '^\d+$') {
                $port = [int]$static
            }
            elseif ($dynamic -and $dynamic -match '^\d+$') {
                $port = [int]$dynamic
            }
        }

        # Testing
        foreach ($protoName in $protocols) {
            $checkName = "SQLServer - $instanceName ($port) - $protoName"
            
            if (-not $protocolMap.ContainsKey($protoName)) { continue }
            $protoEnum = $protocolMap[$protoName]

            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $sslStream = $null
            try {
                $tcpClient.Connect("localhost", $port)
                $stream = $tcpClient.GetStream()
                $sslStream = New-Object System.Net.Security.SslStream($stream, $false, { $true })

                try {
                    $sslStream.AuthenticateAsClient("localhost", $null, $protoEnum, $false)
                    
                    $remoteCert = $null
                    if ($sslStream.RemoteCertificate) {
                        $remoteCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
                    }

                    $details = "ForceEncryption: $($certInfo.ForceEncryption); Version: $version"
                    if ($remoteCert) { $details += "; WireCert: $($remoteCert.Thumbprint)" }
                    if ($certInfo.Thumbprint) { $details += "; RegCert: $($certInfo.Thumbprint)" }
                    if ($supportsTds8) { $details += "; TDS 8.0 Supported" }

                    $results += [PSCustomObject]@{
                        CheckName = $checkName
                        Value     = "Supported"
                        Details   = $details
                        RawData   = @{ CertInfo = $certInfo; RemoteCert = $remoteCert; Version = $version }
                    }
                }
                catch {
                    $errDetails = "Handshake failed"
                    if (-not $supportsTds8 -and $certInfo.ForceEncryption -ne 1) {
                        $errDetails += ". Likely due to SQL expecting TDS pre-login (ForceEncryption=Off, Pre-SQL 2022)"
                    }
                    else {
                        $errDetails += ". Error: $_"
                    }
                    
                    $results += [PSCustomObject]@{
                        CheckName = $checkName
                        Value     = "Not Supported"
                        Details   = $errDetails
                        RawData   = $_
                    }
                }
                finally { 
                    if ($sslStream) { $sslStream.Dispose() }
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    CheckName = $checkName
                    Value     = "Error"
                    Details   = "Connection failed: $_"
                    RawData   = $_
                }
            }
            finally { 
                if ($tcpClient) { $tcpClient.Dispose() }
            }
        }
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "SQLServer"
        Value     = "Not Found"
        Details   = "No SQL Server instances found in registry"
        RawData   = $null
    }
}

return $results
