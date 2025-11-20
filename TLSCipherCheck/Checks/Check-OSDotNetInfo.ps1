# Check-OSDotNetInfo.ps1

$results = @()

# 1. OS Info via WMI
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    
    $results += [PSCustomObject]@{
        CheckName = "OS - Version"
        Value     = $os.Version
        Details   = "Operating System Version"
        RawData   = $os.Version
    }
    
    $results += [PSCustomObject]@{
        CheckName = "OS - BuildNumber"
        Value     = $os.BuildNumber
        Details   = "Operating System Build Number"
        RawData   = $os.BuildNumber
    }
    
    $results += [PSCustomObject]@{
        CheckName = "OS - Caption"
        Value     = $os.Caption
        Details   = "Operating System Edition"
        RawData   = $os.Caption
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "OS Info"
        Value     = "Error"
        Details   = "Failed to query WMI: $($_)"
        RawData   = $_
    }
}

# 2. .NET Framework Versions
$dotNetVersions = @()

# .NET 4.x (via Release key)
$net4Path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
if (Test-Path $net4Path) {
    $release = Get-ItemProperty -Path $net4Path -Name "Release" -ErrorAction SilentlyContinue
    if ($release) {
        $releaseNum = $release.Release
        # Map release number to version
        $versionString = switch ($releaseNum) {
            { $_ -ge 533320 } { "4.8.1" }
            { $_ -ge 528040 } { "4.8" }
            { $_ -ge 461808 } { "4.7.2" }
            { $_ -ge 461308 } { "4.7.1" }
            { $_ -ge 460798 } { "4.7" }
            { $_ -ge 394802 } { "4.6.2" }
            { $_ -ge 394254 } { "4.6.1" }
            { $_ -ge 393295 } { "4.6" }
            { $_ -ge 379893 } { "4.5.2" }
            { $_ -ge 378675 } { "4.5.1" }
            { $_ -ge 378389 } { "4.5" }
            Default { "4.x (Release: $releaseNum)" }
        }
        $dotNetVersions += $versionString
    }
}

# .NET 3.5
$net35Path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5"
if (Test-Path $net35Path) {
    $installed = Get-ItemProperty -Path $net35Path -Name "Install" -ErrorAction SilentlyContinue
    if ($installed -and $installed.Install -eq 1) {
        $dotNetVersions += "3.5"
    }
}

# .NET 3.0
$net30Path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0\Setup"
if (Test-Path $net30Path) {
    $installed = Get-ItemProperty -Path $net30Path -Name "InstallSuccess" -ErrorAction SilentlyContinue
    if ($installed -and $installed.InstallSuccess -eq 1) {
        $dotNetVersions += "3.0"
    }
}

# .NET 2.0
$net20Path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727"
if (Test-Path $net20Path) {
    $installed = Get-ItemProperty -Path $net20Path -Name "Install" -ErrorAction SilentlyContinue
    if ($installed -and $installed.Install -eq 1) {
        $dotNetVersions += "2.0"
    }
}

$dotNetVersionsStr = if ($dotNetVersions.Count -gt 0) { $dotNetVersions -join ";" } else { "None detected" }

$results += [PSCustomObject]@{
    CheckName = ".NET - Installed Versions"
    Value     = $dotNetVersionsStr
    Details   = "Detected .NET Framework versions"
    RawData   = $dotNetVersions
}

return $results
