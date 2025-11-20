# Check Specification: NTLM Settings

## Objective
Audit NTLM restriction policies and authentication levels.

## Target Registry Path
`HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`

## Items to Check
1. **Authentication Level**:
    - `NtlmMinClientSec` (DWORD).
    - `NtlmMinServerSec` (DWORD).
    - Values: `0x0` (No security) to `0x80000` (Ntlmv2 only).
2. **Restriction**:
    - `RestrictSendingNTLMTraffic` (DWORD): `0` (Allow all), `1` (Audit), `2` (Deny).
    - `RestrictReceivingNTLMTraffic` (DWORD).

## Output Details
- Record raw values for Client/Server security levels.
- Record raw values for NTLM traffic restrictions.

## Baseline Recommended Settings
- **LAN Manager Authentication Level**:
    - Path: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
    - Value: `LmCompatibilityLevel` = `5` (Send NTLMv2 response only. Refuse LM & NTLM).
- **Minimum Session Security**:
    - Path: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`
    - Value: `NTLMMinClientSec` = `537395200` (0x20080000 - Require NTLMv2, Require 128-bit encryption).
    - Value: `NTLMMinServerSec` = `537395200` (0x20080000 - Require NTLMv2, Require 128-bit encryption).

## Related Windows Server Documentation
- **[NTLM Overview](./ReferenceDocs/WindowsServerDocs/security/kerberos/ntlm-overview.md)**: Overview of NTLM authentication protocols (LM, NTLMv1, NTLMv2), when NTLM is used, and links to auditing/restricting NTLM usage
- **[SMB NTLM Blocking](./ReferenceDocs/WindowsServerDocs/storage/file-server/smb-ntlm-blocking.md)**: How to block NTLM authentication over SMB and require Kerberos
- **[Windows Authentication Concepts](./ReferenceDocs/WindowsServerDocs/security/windows-authentication/windows-authentication-concepts.md)**: Background on NTLM vs Kerberos authentication in Windows environments
