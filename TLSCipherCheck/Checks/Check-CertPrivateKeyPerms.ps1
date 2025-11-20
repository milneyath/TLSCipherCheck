# Check-CertPrivateKeyPerms.ps1

$results = @()

$stores = @("My", "WebHosting", "Remote Desktop")

foreach ($storeName in $stores) {
    $storePath = "Cert:\LocalMachine\$storeName"
    
    if (Test-Path $storePath) {
        try {
            $certs = Get-ChildItem -Path $storePath -ErrorAction Stop | Where-Object { $_.HasPrivateKey }
            
            foreach ($cert in $certs) {
                try {
                    # Try to find the private key file
                    $keyPath = $null
                    $keyContainer = $null
                    
                    if ($cert.PrivateKey) {
                        # CAPI keys
                        if ($cert.PrivateKey.CspKeyContainerInfo) {
                            $keyContainer = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                            # Common paths
                            $possiblePaths = @(
                                "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyContainer",
                                "$env:ProgramData\Microsoft\Crypto\DSS\MachineKeys\$keyContainer"
                            )
                            foreach ($path in $possiblePaths) {
                                if (Test-Path $path) {
                                    $keyPath = $path
                                    break
                                }
                            }
                        }
                    }
                    else {
                        # CNG keys - try to find via thumbprint
                        # CNG keys are typically in %ProgramData%\Microsoft\Crypto\Keys
                        # This is a simplified approach; real resolution may require more work
                        $cngPath = "$env:ProgramData\Microsoft\Crypto\Keys"
                        if (Test-Path $cngPath) {
                            # We can't easily map thumbprint to key file without deeper inspection
                            # For now, just note it's CNG
                            $keyContainer = "CNG Key (path resolution requires additional logic)"
                        }
                    }
                    
                    if ($keyPath -and (Test-Path $keyPath)) {
                        $acl = Get-Acl -Path $keyPath
                        $owner = $acl.Owner
                        $access = ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
                        
                        $results += [PSCustomObject]@{
                            CheckName = "PrivateKeyPerms - $storeName - $($cert.Thumbprint)"
                            Value     = "Found: $keyPath"
                            Details   = "Owner: $owner; Access: $access"
                            RawData   = @{
                                StoreName          = $storeName
                                Thumbprint         = $cert.Thumbprint
                                KeyContainerOrPath = $keyPath
                                Owner              = $owner
                                Access             = $access
                                SDDL               = $acl.Sddl
                            }
                        }
                    }
                    else {
                        $results += [PSCustomObject]@{
                            CheckName = "PrivateKeyPerms - $storeName - $($cert.Thumbprint)"
                            Value     = "Key not found on disk"
                            Details   = "Container: $keyContainer"
                            RawData   = @{
                                StoreName          = $storeName
                                Thumbprint         = $cert.Thumbprint
                                KeyContainerOrPath = $keyContainer
                            }
                        }
                    }
                }
                catch {
                    $results += [PSCustomObject]@{
                        CheckName = "PrivateKeyPerms - $storeName - Error"
                        Value     = "Failed"
                        Details   = "Error: $($_)"
                        RawData   = $_
                    }
                }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = "PrivateKeyPerms - $storeName"
                Value     = "Error"
                Details   = "Failed to enumerate store: $($_)"
                RawData   = $_
            }
        }
    }
}

return $results
