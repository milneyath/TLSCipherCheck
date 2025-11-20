# Audit-Crypto.ps1
# Wrapper script to run the TLSCipherCheck module
param (
    [string]$ServerList = "servers.txt",
    [string]$OutputPath = ".\Output",
    [PSCredential]$Credential
)

# Import the module from the local directory
$modulePath = Join-Path $PSScriptRoot "TLSCipherCheck"
if (Test-Path $modulePath) {
    Import-Module $modulePath -Force
}
else {
    Write-Error "Module not found at $modulePath"
    exit 1
}

# Run the audit
Invoke-TLSCipherAudit -ServerList $ServerList -OutputPath $OutputPath -Credential $Credential
