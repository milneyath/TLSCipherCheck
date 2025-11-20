# Check-EventLog.ps1

$results = @()

# Use auditpol /get /category:* /r to get CSV output
# /r outputs: "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting"
# Inclusion Setting: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure

try {
    $csvOutput = auditpol.exe /get /category:* /r
    
    if ($csvOutput) {
        # Skip the first blank line if present and header
        $data = $csvOutput | Select-Object -Skip 2 | ConvertFrom-Csv -Header "MachineName", "PolicyTarget", "Subcategory", "SubcategoryGUID", "InclusionSetting", "ExclusionSetting"
        
        $relevantCategories = @(
            "Security State Change",
            "Security System Extension",
            "System Integrity",
            "Logon",
            "Logoff",
            "Special Logon",
            "File System",
            "Registry",
            "Sensitive Privilege Use"
        )

        foreach ($row in $data) {
            if ($row.Subcategory -in $relevantCategories) {
                $setting = switch ($row.InclusionSetting) {
                    "0" { "No Auditing" }
                    "No Auditing" { "No Auditing" }
                    "1" { "Success" }
                    "Success" { "Success" }
                    "2" { "Failure" }
                    "Failure" { "Failure" }
                    "3" { "Success and Failure" }
                    "Success and Failure" { "Success and Failure" }
                    Default { "Unknown ($($row.InclusionSetting))" }
                }

                $results += [PSCustomObject]@{
                    CheckName = "Audit Policy - $($row.Subcategory)"
                    Value     = $setting
                    Details   = "Inclusion: $($row.InclusionSetting)"
                    RawData   = $row
                }
            }
        }
    }
    else {
        $results += [PSCustomObject]@{
            CheckName = "Audit Policy"
            Value     = "Error"
            Details   = "auditpol.exe returned no output"
            RawData   = $null
        }
    }
}
catch {
    $results += [PSCustomObject]@{
        CheckName = "Audit Policy"
        Value     = "Error"
        Details   = "Failed to run auditpol.exe: $_"
        RawData   = $_
    }
}

return $results
