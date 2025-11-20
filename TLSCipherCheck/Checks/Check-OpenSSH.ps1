# Check-OpenSSH.ps1

$results = @()
$sshBasePath = "$env:ProgramData\ssh"
$configFile = Join-Path $sshBasePath "sshd_config"

if (Test-Path $configFile) {
    # 1. Parse Configuration
    try {
        $configContent = Get-Content $configFile -ErrorAction Stop
        
        # Helper to find config value (ignores comments)
        function Get-SshConfigValue {
            param($Content, $Key)
            $match = $Content | Where-Object { $_ -match "^\s*$Key\s+(.+)" } | Select-Object -First 1
            if ($match) {
                return ($match -replace "^\s*$Key\s+", "").Trim()
            }
            return "Default/Missing"
        }

        $keysToCheck = @("Ciphers", "MACs", "KexAlgorithms", "PasswordAuthentication", "PubkeyAuthentication", "PermitRootLogin", "SyslogFacility", "LogLevel")
        
        foreach ($key in $keysToCheck) {
            $val = Get-SshConfigValue -Content $configContent -Key $key
            
            $results += [PSCustomObject]@{
                CheckName = "OpenSSH Config - $key"
                Value     = $val
                Details   = "From sshd_config"
                RawData   = $val
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            CheckName = "OpenSSH Config"
            Value     = "Error"
            Details   = "Failed to read sshd_config: $_"
            RawData   = $_
        }
    }

    # 2. File Permissions (Host Keys)
    $hostKeys = Get-ChildItem -Path $sshBasePath -Filter "ssh_host_*_key"
    foreach ($keyFile in $hostKeys) {
        try {
            $acl = Get-Acl -Path $keyFile.FullName
            $owner = $acl.Owner
            $access = ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
            
            $results += [PSCustomObject]@{
                CheckName = "OpenSSH File Perms - $($keyFile.Name)"
                Value     = "Owner: $owner"
                Details   = "Access: $access"
                RawData   = @{ Owner = $owner; Access = $access; SDDL = $acl.Sddl }
            }
        }
        catch {
            $results += [PSCustomObject]@{
                CheckName = "OpenSSH File Perms - $($keyFile.Name)"
                Value     = "Error"
                Details   = "Failed to get ACL: $_"
                RawData   = $_
            }
        }
    }

    # 3. Authorized Keys
    # Default is .ssh/authorized_keys in user profile if not specified
    $authKeysConfig = Get-SshConfigValue -Content $configContent -Key "AuthorizedKeysFile"
    if ($authKeysConfig -eq "Default/Missing") {
        $authKeysConfig = ".ssh/authorized_keys"
    }

    # Split multiple paths if present
    $authKeyPaths = $authKeysConfig -split "\s+"

    # Get all users to check (simplistic approach: check C:\Users)
    $users = Get-ChildItem -Path "C:\Users" -Directory
    
    foreach ($userDir in $users) {
        $username = $userDir.Name
        
        foreach ($pathPattern in $authKeyPaths) {
            # Replace tokens
            # %h = user home directory
            # %u = username
            # %% = literal %
            
            $resolvedPath = $pathPattern -replace "%h", $userDir.FullName
            $resolvedPath = $resolvedPath -replace "%u", $username
            $resolvedPath = $resolvedPath -replace "%%", "%"
            
            # Handle relative paths (relative to user home)
            if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
                $resolvedPath = Join-Path $userDir.FullName $resolvedPath
            }

            if (Test-Path $resolvedPath -PathType Leaf) {
                try {
                    $acl = Get-Acl -Path $resolvedPath
                    $owner = $acl.Owner
                    $access = ($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join "; "
                    
                    $results += [PSCustomObject]@{
                        CheckName = "OpenSSH AuthKeys - $username"
                        Value     = "Found: $resolvedPath"
                        Details   = "Owner: $owner; Access: $access"
                        RawData   = @{ Path = $resolvedPath; Owner = $owner; Access = $access; SDDL = $acl.Sddl }
                    }
                }
                catch {
                    $results += [PSCustomObject]@{
                        CheckName = "OpenSSH AuthKeys - $username"
                        Value     = "Error"
                        Details   = "Failed to get ACL for $($resolvedPath): $($_)"
                        RawData   = $_
                    }
                }
            }
        }
    }

}
else {
    $results += [PSCustomObject]@{
        CheckName = "OpenSSH"
        Value     = "Not Found"
        Details   = "sshd_config not found at $configFile"
        RawData   = $null
    }
}

return $results
