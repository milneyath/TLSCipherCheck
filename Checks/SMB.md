# Check Specification: SMB Settings

## Objective
Audit SMB protocol versions and security settings (Signing/Encryption).

## Target Settings
Use `Get-SmbServerConfiguration` (or registry fallback for older OS).

## Items to Check
1. **Protocol Versions**:
    - `EnableSMB1Protocol`: True/False.
    - `EnableSMB2Protocol`: True/False (Covers SMB2/3).
2. **Security**:
    - `RequireSecuritySignature`: True/False.
    - `EncryptData`: True/False (SMB3 feature).
    - `EnableSecuritySignature`: True/False.

## Output Details
- Record status of SMB1 and SMB2/3.
- Record Signing and Encryption requirements.

## Baseline Recommended Settings
- **SMB v1**:
    - Server: `HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters` -> `SMB1` = `0` (Disabled).
    - Client: `HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10` -> `Start` = `4` (Disabled).
- **SMB Signing**:
    - Server: `HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters` -> `RequireSecuritySignature` = `1`.
    - Client: `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` -> `RequireSecuritySignature` = `1`.
- **Encryption**:
    - `SendUnencryptedPasswordToThirdPartySMBServers` = `0`.
- **Minimum Version**:
    - Client/Server: `MinSmb2Dialect` = `768` (0x300, SMB 3.0).

## Related Windows Server Documentation
- **[Detect, Enable, and Disable SMBv1, SMBv2, and SMBv3](./ReferenceDocs/WindowsServerDocs/storage/file-server/Troubleshoot/detect-enable-and-disable-smbv1-v2-v3.md)**: Complete guide on detecting and managing SMB protocol versions using PowerShell, Registry, and Group Policy
- **[SMB Security Enhancements](./ReferenceDocs/WindowsServerDocs/storage/file-server/smb-security.md)**: Covers SMB Encryption (EncryptData), AES-256-GCM/CCM cipher suites, and SMB Direct encryption
- **[SMB Signing](./ReferenceDocs/WindowsServerDocs/storage/file-server/smb-signing.md)**: How to control SMB signing behavior (RequireSecuritySignature) via Group Policy, PowerShell, and Windows Admin Center
- **[SMB Signing Overview](./ReferenceDocs/WindowsServerDocs/storage/file-server/smb-signing-overview.md)**: Details on SMB signing algorithms including AES-128-GMAC and AES-128-CMAC
