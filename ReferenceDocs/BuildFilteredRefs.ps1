<#
.SYNOPSIS
  Pre-filter Group Policy reference sheets and ADMX files to only the registry
  keys listed in UsedKeys.txt.

.DESCRIPTION
  - Reads UsedKeys.txt containing lines of "Hive:\Path,ValueName"
  - Normalises each entry to a canonical ID: HIVE\KeyPath\ValueName (uppercase)
  - For each *.xlsx/*.xls in the current folder, filters rows where (Registry Key + Value Name)
    matches one of the IDs, and writes <BaseName>.Result.xlsx
  - Parses .\Policies\*.admx (+ en-US .adml) for registry mappings, filters to used IDs,
    and writes UsedKeys.AdmxResult.xml

.NOTES
  Requires ImportExcel module for Excel I/O.
#>

param(
    [string]$BasePath = "."
)

# ---------------------------
# 1. Load & normalise UsedKeys
# ---------------------------

$usedKeysPath = Join-Path $BasePath "UsedKeys.txt"
if (-not (Test-Path $usedKeysPath)) {
    throw "UsedKeys.txt not found at '$usedKeysPath'"
}

Write-Host "Loading used keys from $usedKeysPath"

# We'll store canonical IDs in a HashSet for fast lookups
$usedKeyIds = New-Object 'System.Collections.Generic.HashSet[string]'

Get-Content $usedKeysPath | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) { return }

    # Expect: HKLM:\SOFTWARE\Foo\Bar,ValueName
    $parts = $line.Split(',', 2)
    if ($parts.Count -lt 2) { return }

    $fullPath = $parts[0].Trim()
    $valueName = $parts[1].Trim()

    # Normalise hive + key
    # Remove trailing ':' and optional backslash after hive
    if ($fullPath -match '^(HKLM|HKEY_LOCAL_MACHINE):?\\?(.*)$') {
        $hive = 'HKLM'
        $keyPath = $Matches[2]
    }
    elseif ($fullPath -match '^(HKCU|HKEY_CURRENT_USER):?\\?(.*)$') {
        $hive = 'HKCU'
        $keyPath = $Matches[2]
    }
    elseif ($fullPath -match '^(HKU|HKEY_USERS):?\\?(.*)$') {
        $hive = 'HKU'
        $keyPath = $Matches[2]
    }
    elseif ($fullPath -match '^(HKCR|HKEY_CLASSES_ROOT):?\\?(.*)$') {
        $hive = 'HKCR'
        $keyPath = $Matches[2]
    }
    else {
        Write-Warning "Unrecognised hive in UsedKeys line: '$line'"
        return
    }

    $keyPath = $keyPath.TrimStart('\')

    $id = ("{0}\{1}\{2}" -f $hive, $keyPath, $valueName).ToUpperInvariant()
    [void]$usedKeyIds.Add($id)
}

Write-Host "Loaded $($usedKeyIds.Count) unique registry key/value IDs from UsedKeys.txt"

# -----------------------------------------
# Helper: build canonical ID from sheet row
# -----------------------------------------

function Get-CanonicalIdFromSheetRow {
    param(
        [string]$RegistryKey,
        [string]$ValueName
    )

    if (-not $RegistryKey -or -not $ValueName) { return $null }

    $rk = $RegistryKey.Trim()

    if ($rk -match '^(HKEY_LOCAL_MACHINE|HKLM)\\(.*)$') {
        $hive = 'HKLM'
        $keyPath = $Matches[2]
    }
    elseif ($rk -match '^(HKEY_CURRENT_USER|HKCU)\\(.*)$') {
        $hive = 'HKCU'
        $keyPath = $Matches[2]
    }
    elseif ($rk -match '^(HKEY_USERS|HKU)\\(.*)$') {
        $hive = 'HKU'
        $keyPath = $Matches[2]
    }
    elseif ($rk -match '^(HKEY_CLASSES_ROOT|HKCR)\\(.*)$') {
        $hive = 'HKCR'
        $keyPath = $Matches[2]
    }
    else {
        # Unknown or missing hive; skip
        return $null
    }

    $keyPath = $keyPath.TrimStart('\')
    $valueName = $ValueName.Trim()

    if (-not $valueName) { return $null }

    return ("{0}\{1}\{2}" -f $hive, $keyPath, $valueName).ToUpperInvariant()
}

# -----------------------------------------
# 2. Filter each GP reference Excel workbook
# -----------------------------------------

# NOTE: ImportExcel works best with .xlsx. If your files are .xls, consider
# resaving them as .xlsx first, or use COM to convert.

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Warning "ImportExcel module not found. Install it with: Install-Module ImportExcel"
}

$excelFiles = Get-ChildItem -Path $BasePath -File -Include *.xlsx, *.xls

foreach ($file in $excelFiles) {
    # Skip previously generated result files
    if ($file.Name -like '*.Result.*') { continue }

    Write-Host "Processing Excel reference file: $($file.Name)"

    # Try to import; assume the data is on the first sheet
    try {
        $rows = Import-Excel -Path $file.FullName
    }
    catch {
        Write-Warning "Failed to import '$($file.FullName)' via Import-Excel. $_"
        continue
    }

    if (-not $rows) {
        Write-Warning "No rows found in '$($file.FullName)'"
        continue
    }

    # Detect column names (they sometimes vary slightly)
    $colNames = $rows[0].psobject.Properties.Name
    $regKeyCol =
    $colNames | Where-Object { $_ -match 'Registry Key' } | Select-Object -First 1
    $valueNameCol =
    $colNames | Where-Object { $_ -match 'Value Name' } | Select-Object -First 1

    if (-not $regKeyCol -or -not $valueNameCol) {
        Write-Warning "Could not find 'Registry Key'/'Value Name' columns in '$($file.Name)'"
        continue
    }

    $filtered = @()

    foreach ($row in $rows) {
        $rk = $row.$regKeyCol
        $vn = $row.$valueNameCol
        $id = Get-CanonicalIdFromSheetRow -RegistryKey $rk -ValueName $vn
        if (-not $id) { continue }

        if ($usedKeyIds.Contains($id)) {
            $filtered += $row
        }
    }

    Write-Host "  Found $($filtered.Count) matching rows in $($file.Name)"

    $outName = "{0}.Result.xlsx" -f [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $outPath = Join-Path $BasePath $outName

    if ($filtered.Count -gt 0) {
        $filtered | Export-Excel -Path $outPath -WorksheetName 'Filtered' -AutoSize -Force
        Write-Host "  Wrote filtered workbook: $outPath"
    }
    else {
        Write-Host "  No matching rows; skipping output workbook."
    }
}

# -------------------------------------------------------
# 3. Parse ADMX/ADML and emit only mappings for used keys
# -------------------------------------------------------

$policiesPath = Join-Path $BasePath "Policies"
if (-not (Test-Path $policiesPath)) {
    Write-Warning "Policies folder '$policiesPath' not found. Skipping ADMX parsing."
    return
}

$admxFiles = Get-ChildItem -Path $policiesPath -Filter *.admx -File
if (-not $admxFiles) {
    Write-Warning "No .admx files found under '$policiesPath'. Skipping ADMX parsing."
    return
}

function Get-AdmlStrings {
    param(
        [string]$AdmlPath
    )

    $dict = @{}

    [xml]$adml = Get-Content -Path $AdmlPath -ErrorAction Stop

    $strings = $adml.policyDefinitionResources.resources.stringTable.string
    foreach ($s in $strings) {
        $id = $s.id
        $text = $s.InnerText
        if ($id) { $dict[$id] = $text }
    }

    return $dict
}

$policyMappings = @()

foreach ($admx in $admxFiles) {
    $admxPath = $admx.FullName
    $admxName = $admx.Name

    # Assume en-US ADML; adjust locale if needed
    $admlPath = Join-Path $policiesPath ("en-US\" + [System.IO.Path]::GetFileNameWithoutExtension($admxName) + ".adml")

    if (-not (Test-Path $admlPath)) {
        Write-Warning "ADML not found for $admxName at $admlPath; skipping explain/display texts."
        $strings = @{}
    }
    else {
        $strings = Get-AdmlStrings -AdmlPath $admlPath
    }

    Write-Host "Parsing ADMX: $admxName"

    try {
        [xml]$xml = Get-Content -Path $admxPath -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to parse $admxName as XML: $_"
        continue
    }

    $policies = $xml.policyDefinitions.policies.policy
    if (-not $policies) { continue }

    foreach ($p in $policies) {
        # class="Machine"/"User"
        $class = $p.class
        $hive =
        if ($class -eq 'User') { 'HKCU' }
        else { 'HKLM' }  # default to HKLM for Machine or missing

        $displayNameId = $p.displayName
        $explainId = $p.explainText
        $policyName = if ($displayNameId -and $strings.ContainsKey($displayNameId)) { $strings[$displayNameId] } else { $displayNameId }
        $explainText = if ($explainId -and $strings.ContainsKey($explainId)) { $strings[$explainId] }   else { $explainId }

        $baseKey = $p.key
        $baseValue = $p.valueName

        # Pattern 1: key + valueName directly on <policy>
        if ($baseKey -and $baseValue) {
            $id = ("{0}\{1}\{2}" -f $hive, $baseKey.TrimStart('\'), $baseValue).ToUpperInvariant()
            if ($usedKeyIds.Contains($id)) {
                $policyMappings += [pscustomobject]@{
                    Id          = $id
                    Hive        = $hive
                    KeyPath     = $baseKey
                    ValueName   = $baseValue
                    PolicyName  = $policyName
                    Class       = $class
                    AdmxFile    = $admxName
                    ExplainText = $explainText
                }
            }
        }

        # Pattern 2: registrySettings/registrySetting elements
        $regSettings = $p.registrySettings.registrySetting
        if ($regSettings) {
            foreach ($rs in $regSettings) {
                $rKey = if ($rs.key) { $rs.key } elseif ($baseKey) { $baseKey } else { $null }
                $rValue = $rs.valueName

                if (-not $rKey -or -not $rValue) { continue }

                $id = ("{0}\{1}\{2}" -f $hive, $rKey.TrimStart('\'), $rValue).ToUpperInvariant()
                if ($usedKeyIds.Contains($id)) {
                    $policyMappings += [pscustomobject]@{
                        Id          = $id
                        Hive        = $hive
                        KeyPath     = $rKey
                        ValueName   = $rValue
                        PolicyName  = $policyName
                        Class       = $class
                        AdmxFile    = $admxName
                        ExplainText = $explainText
                    }
                }
            }
        }

        # NOTE: If you need deeper coverage, you can also parse <elements>/<boolean>/<decimal>
        # and their registryValue children, but the above two patterns catch a lot of policies.
    }
}

Write-Host "Found $($policyMappings.Count) ADMX policy mappings for used keys."

# Write out as XML for easy review
if ($policyMappings.Count -gt 0) {
    $xmlDoc = New-Object System.Xml.XmlDocument
    $root = $xmlDoc.CreateElement("UsedKeyPolicies")
    $xmlDoc.AppendChild($root) | Out-Null

    foreach ($m in $policyMappings | Sort-Object Id, AdmxFile, PolicyName -Unique) {
        $node = $xmlDoc.CreateElement("PolicyMapping")

        $node.SetAttribute("Id", $m.Id)
        $node.SetAttribute("Hive", $m.Hive)
        $node.SetAttribute("KeyPath", $m.KeyPath)
        $node.SetAttribute("ValueName", $m.ValueName)
        $node.SetAttribute("PolicyName", $m.PolicyName)
        $node.SetAttribute("Class", $m.Class)
        $node.SetAttribute("AdmxFile", $m.AdmxFile)

        if ($m.ExplainText) {
            $explainNode = $xmlDoc.CreateElement("Explain")
            $explainNode.InnerText = $m.ExplainText
            [void]$node.AppendChild($explainNode)
        }

        [void]$root.AppendChild($node)
    }

    $admxOutPath = Join-Path $BasePath "UsedKeys.AdmxResult.xml"
    $xmlDoc.Save($admxOutPath)
    Write-Host "Wrote ADMX mapping file: $admxOutPath"
}
else {
    Write-Host "No ADMX mappings matched the used keys."
}
