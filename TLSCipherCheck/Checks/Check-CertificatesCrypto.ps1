# Check-CertificatesCrypto.ps1

$results = @()

$stores = @("My", "WebHosting", "Remote Desktop", "Root", "CA")

foreach ($storeName in $stores) {
    $storePath = "Cert:\LocalMachine\$storeName"
    
    if (Test-Path $storePath) {
        try {
            $certs = Get-ChildItem -Path $storePath -ErrorAction Stop
            
            foreach ($cert in $certs) {
                try {
                    # Extract crypto details
                    $sigAlgo = $cert.SignatureAlgorithm.FriendlyName
                    $pubKeyAlgo = $cert.PublicKey.Oid.FriendlyName
                    $keyLength = $cert.PublicKey.Key.KeySize
                    $hasPrivateKey = $cert.HasPrivateKey
                    
                    # Try to get key provider info if private key exists
                    $keyProvider = "N/A"
                    if ($hasPrivateKey) {
                        try {
                            # This may not always be accessible
                            $keyProvider = if ($cert.PrivateKey) { $cert.PrivateKey.CspKeyContainerInfo.ProviderName } else { "CNG or inaccessible" }
                        }
                        catch {
                            $keyProvider = "Unable to retrieve"
                        }
                    }
                    
                    $results += [PSCustomObject]@{
                        CheckName = "Certificate - $storeName - $($cert.Thumbprint)"
                        Value     = "Subject: $($cert.Subject)"
                        Details   = "Issuer: $($cert.Issuer); SigAlg: $sigAlgo; PubKeyAlg: $pubKeyAlgo; KeyLen: $keyLength; HasPrivKey: $hasPrivateKey"
                        RawData   = @{
                            StoreName          = $storeName
                            Subject            = $cert.Subject
                            Issuer             = $cert.Issuer
                            SerialNumber       = $cert.SerialNumber
                            Thumbprint         = $cert.Thumbprint
                            SignatureAlgorithm = $sigAlgo
                            PublicKeyAlgorithm = $pubKeyAlgo
                            KeyLength          = $keyLength
                            HasPrivateKey      = $hasPrivateKey
                            KeyProvider        = $keyProvider
                        }
                    }
                }
                catch {
                    $results += [PSCustomObject]@{
                        CheckName = "Certificate - $storeName - Error"
                        Value     = "Failed to parse cert"
                        Details   = "Error: $($_)"
                        RawData   = $_
                    }
                }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = "Certificates - $storeName"
                Value     = "Error"
                Details   = "Failed to enumerate store: $($_)"
                RawData   = $_
            }
        }
    }
}

return $results
