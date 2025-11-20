# Check-LocalWebsites.ps1

$results = @()

# Protocols to test
$protocols = @(
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1",
    "TLS 1.2",
    "TLS 1.3"
)

# Map friendly names to SslProtocols enum values
# Note: Some older/newer protocols might require specific .NET versions or registry settings to be available in the enum
$protocolMap = @{
    "SSL 2.0" = [System.Security.Authentication.SslProtocols]::Ssl2
    "SSL 3.0" = [System.Security.Authentication.SslProtocols]::Ssl3
    "TLS 1.0" = [System.Security.Authentication.SslProtocols]::Tls
    "TLS 1.1" = [System.Security.Authentication.SslProtocols]::Tls11
    "TLS 1.2" = [System.Security.Authentication.SslProtocols]::Tls12
    "TLS 1.3" = 12288 # [System.Security.Authentication.SslProtocols]::Tls13 (Available in .NET 4.8+ / Core)
}

# Targets to test
$targets = @()

# 1. Try to get bindings from IIS
if (Get-Module -ListAvailable -Name WebAdministration) {
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $bindings = Get-WebBinding | Where-Object { $_.protocol -eq "https" }
        foreach ($binding in $bindings) {
            $hostName = if ($binding.bindingInformation.Split(":")[2]) { $binding.bindingInformation.Split(":")[2] } else { "localhost" }
            $port = $binding.bindingInformation.Split(":")[1]
            $targets += [PSCustomObject]@{ Host = $hostName; Port = $port; Source = "IIS" }
        }
    }
    catch {
        Write-Warning "Failed to query IIS bindings: $_"
    }
}

# 2. Fallback/Default to localhost:443 if no targets found
if ($targets.Count -eq 0) {
    $targets += [PSCustomObject]@{ Host = "localhost"; Port = 443; Source = "Default" }
}

# Remove duplicates
$targets = $targets | Select-Object -Unique Host, Port, Source

# Function to test a protocol
function Test-Protocol {
    param (
        [string]$TargetHost,
        [int]$TargetPort,
        [string]$ProtocolName,
        [int]$ProtocolEnum
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $stream = $tcpClient.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($stream, $false, { $true }) # Trust all certs for testing

        try {
            # Attempt authentication
            $sslStream.AuthenticateAsClient($TargetHost, $null, $ProtocolEnum, $false)
            
            $certInfo = $null
            if ($sslStream.RemoteCertificate) {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
                $certInfo = @{
                    Subject    = $cert.Subject
                    Issuer     = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotAfter   = $cert.NotAfter
                }
            }
            
            return @{ Supported = $true; Cert = $certInfo }
        }
        catch {
            return @{ Supported = $false; Cert = $null }
        }
        finally {
            $sslStream.Dispose()
        }
    }
    catch {
        return @{ Supported = $false; Cert = $null } # Connection failed or other error
    }
    finally {
        $tcpClient.Dispose()
    }
}

# Run tests
foreach ($target in $targets) {
    foreach ($protoName in $protocols) {
        $checkName = "LocalSite - $($target.Host):$($target.Port) - $protoName"
        
        # Check if protocol enum is valid in this environment
        if (-not $protocolMap.ContainsKey($protoName)) {
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "Skipped"
                Details   = "Protocol definition not found in script map"
                RawData   = $null
            }
            continue
        }

        $protoEnum = $protocolMap[$protoName]
        
        # Handle TLS 1.3 availability check safely
        if ($protoName -eq "TLS 1.3" -and -not [Enum]::IsDefined([System.Security.Authentication.SslProtocols], 12288)) {
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "Skipped"
                Details   = "TLS 1.3 not supported by current .NET runtime"
                RawData   = $null
            }
            continue
        }

        try {
            $testResult = Test-Protocol -TargetHost $target.Host -TargetPort $target.Port -ProtocolName $protoName -ProtocolEnum $protoEnum
            $isSupported = $testResult.Supported
             
            $value = if ($isSupported) { "Supported" } else { "Not Supported" }
            $details = "Tested against $($target.Host):$($target.Port)"
             
            if ($testResult.Cert) {
                $details += "; Cert: $($testResult.Cert.Subject) (Exp: $($testResult.Cert.NotAfter))"
            }

            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = $value
                Details   = $details
                RawData   = @{ 
                    Host        = $target.Host
                    Port        = $target.Port
                    Protocol    = $protoName
                    Supported   = $isSupported
                    Certificate = $testResult.Cert
                }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = $checkName
                Value     = "Error"
                Details   = "Test failed: $_"
                RawData   = $_
            }
        }
    }
}

return $results
