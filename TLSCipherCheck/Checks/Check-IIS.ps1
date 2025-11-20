# Check-IIS.ps1

$results = @()

if (Get-Module -ListAvailable -Name WebAdministration) {
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    
    # 1. Check Sites for HSTS and SSL Flags
    $sites = Get-ChildItem -Path IIS:\Sites
    
    foreach ($site in $sites) {
        $siteName = $site.Name
        
        # HSTS (Requires IIS 10+ usually, checked via config)
        try {
            $hsts = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/hsts" -Name * -PSPath "IIS:\" -ErrorAction SilentlyContinue
            # Also check specific site
            $siteHsts = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/site[@name='$siteName']/hsts" -Name * -PSPath "IIS:\" -ErrorAction SilentlyContinue
            
            $hstsEnabled = if ($siteHsts.enabled) { $siteHsts.enabled } elseif ($hsts.enabled) { "$($hsts.enabled) (Inherited)" } else { "False" }
            
            $results += [PSCustomObject]@{
                CheckName = "IIS Site - $siteName - HSTS"
                Value     = "Enabled: $hstsEnabled"
                Details   = "Max-Age: $(if($siteHsts.maxAge){$siteHsts.maxAge}else{$hsts.maxAge})"
                RawData   = @{ Enabled = $hstsEnabled; MaxAge = $siteHsts.maxAge }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = "IIS Site - $siteName - HSTS"
                Value     = "Error"
                Details   = "Failed to query HSTS: $_"
                RawData   = $_
            }
        }

        # SSL Flags
        try {
            $sslFlags = Get-WebConfigurationProperty -Filter "system.webServer/security/access" -Name "sslFlags" -PSPath "IIS:\Sites\$siteName" -ErrorAction SilentlyContinue
            
            $results += [PSCustomObject]@{
                CheckName = "IIS Site - $siteName - SSL Flags"
                Value     = "$($sslFlags.Value)"
                Details   = "Ssl, SslRequireCert, etc."
                RawData   = $sslFlags.Value
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = "IIS Site - $siteName - SSL Flags"
                Value     = "Error"
                Details   = "Failed to query SSL Flags: $_"
                RawData   = $_
            }
        }
        
        # Bindings
        foreach ($binding in $site.Bindings) {
            if ($binding.protocol -eq "https") {
                $results += [PSCustomObject]@{
                    CheckName = "IIS Binding - $siteName - $($binding.bindingInformation)"
                    Value     = "HTTPS"
                    Details   = "Cert Hash: $($binding.certificateHash) Store: $($binding.certificateStoreName)"
                    RawData   = $binding
                }
            }
        }
    }
}
else {
    $results += [PSCustomObject]@{
        CheckName = "IIS Check"
        Value     = "Skipped"
        Details   = "WebAdministration module not found (IIS likely not installed)"
        RawData   = $null
    }
}

return $results
