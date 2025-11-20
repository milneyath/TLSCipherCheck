# Check Specification: RDP Settings

## Objective
Audit RDP cryptographic and security configuration.

## Target Settings
Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`

## Items to Check
1. **Security Layer** (`SecurityLayer`):
    - 0=RDP, 1=Negotiate, 2=SSL(TLS).
2. **Encryption Level** (`MinEncryptionLevel`):
    - 1=Low, 2=Client Compatible, 3=High, 4=FIPS.
3. **NLA** (`UserAuthentication`):
    - 0=Off, 1=On.
4. **Certificate**:
    - `SSLCertificateSHA1Hash` (Thumbprint).
    - If present, map to actual certificate details if possible.

## Output Details
- Record raw values and friendly labels for Security Layer and Encryption Level.
- Record NLA status.
- Record Listener Certificate Thumbprint.

## Baseline Recommended Settings
- **Encryption Level**: `MinEncryptionLevel` = `3` (High).
- **Security**:
    - `UserAuthentication` (NLA) = `1` (Required).
    - `fPromptForPassword` = `1` (Always prompt).
    - `fEncryptRPCTraffic` = `1` (Require secure RPC).

## Related Windows Server Documentation
- **[Remote Desktop Services Certificates](./ReferenceDocs/WindowsServerDocs/remote/remote-desktop-services/remote-desktop-services-certificates.md)**: How to create, configure, and use SSL/TLS certificates for Remote Desktop Services to secure RDP connections
