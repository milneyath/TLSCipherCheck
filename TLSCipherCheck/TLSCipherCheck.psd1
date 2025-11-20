@{
    RootModule        = 'TLSCipherCheck.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'
    Author            = 'Antigravity'
    CompanyName       = 'Google Deepmind'
    Copyright         = '(c) 2025 Google Deepmind. All rights reserved.'
    Description       = 'A module to audit Windows servers for cryptographic compliance (TLS, Ciphers, etc.).'
    FunctionsToExport = @(
        'Invoke-TLSCipherAudit',
        'Initialize-AuditLog',
        'Write-AuditLog',
        'New-AuditReportStructure',
        'Invoke-RemoteCheck',
        'Export-AuditZip'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
