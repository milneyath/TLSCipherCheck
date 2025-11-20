# Check Specification: SChannel Protocols

## Objective
Verify which SSL/TLS protocols are enabled or disabled on the server.

## Target Registry Path
`HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`

## Items to Check
For each protocol (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3):
1. **Client Subkey**:
    - `Enabled` (DWORD): Should be `0` for legacy, `1` (or missing/default) for modern.
    - `DisabledByDefault` (DWORD).
2. **Server Subkey**:
    - `Enabled` (DWORD).
    - `DisabledByDefault` (DWORD).

## Output Details
- Record the raw `Enabled` and `DisabledByDefault` values for both Client and Server subkeys.
- Note if the key is missing (implies default behavior).
 
## Baseline Recommended Settings
- **TLS 1.2 and 1.3**: Should be enabled.
- **TLS 1.0 and 1.1**: Should be disabled.
- **SSL 2.0 and 3.0**: Should be disabled.
- **Registry Overrides** (Modern Configuration):
    - `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`:
        - `OverrideMinimumEnabledTLSVersionClient`: `1.2`
        - `OverrideMinimumEnabledTLSVersionServer`: `1.2`
        - `OverrideMinimumEnabledDTLSVersionClient`: `1.2`
        - `OverrideMinimumEnabledDTLSVersionServer`: `1.2`

### TLS Version Support by Operating System
- **TLS 1.3**: Supported on Windows 11 and Windows Server 2022+ (enabled by default)
- **TLS 1.2**: Supported on Windows Server 2012+ (enabled by default on Server 2012 R2+)
- **TLS 1.1**: Supported on Windows Server 2008 R2+ (deprecated, should be disabled)
- **TLS 1.0**: Supported on Windows Server 2003+ (deprecated, should be disabled)
- **SSL 3.0 / SSL 2.0**: Legacy protocols (deprecated, should be disabled)

### Related Features and Settings
- **SCHANNEL Ciphers**: Determines which cipher suites are available for TLS connections (see Ciphers check)
- **SCHANNEL Hashes**: Determines which hash algorithms are available (see OtherCrypto check)
- **SCHANNEL Key Exchange Algorithms**: Affects TLS handshake (see OtherCrypto check)
- **.NET Strong Cryptography**: Required for .NET applications to use TLS 1.2+ (see DotNet and OSDotNet checks)
- **WinHTTP DefaultSecureProtocols**: Affects Windows HTTP client TLS version selection (see OtherCrypto check)

## Related Windows Server Documentation
- **[TLS Registry Settings](./ReferenceDocs/WindowsServerDocs/security/tls/tls-registry-settings.md)**: Comprehensive guide to TLS/SSL registry settings including protocol version configuration (Enabled/DisabledByDefault values)
- **[Manage TLS](./ReferenceDocs/WindowsServerDocs/security/tls/manage-tls.md)**: How to configure TLS cipher suite order and ECC curve order
- **[Manage SSL Protocols in AD FS](./ReferenceDocs/WindowsServerDocs/identity/ad-fs/operations/Manage-SSL-Protocols-in-AD-FS.md)**: Examples of enabling/disabling SSL 3.0, TLS 1.0, TLS 1.1, and TLS 1.2 via registry and PowerShell

