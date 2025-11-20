# Check Specification: .NET Framework Crypto

## Objective
Verify .NET Framework is configured to use strong cryptography and inherit system TLS settings.

## Target Registry Paths
1. `HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319`
2. `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319`
3. `HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727`
4. `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727`

## Items to Check
- **SchUseStrongCrypto** (DWORD):
    - Enables TLS 1.2 support for .NET 4.x apps.
    - MUST be `1`.
- **SystemDefaultTlsVersions** (DWORD):
    - Tells .NET to use the OS-configured TLS versions instead of hardcoded defaults.
    - MUST be `1`.

## Output Details
- Report values for both 64-bit and 32-bit (Wow6432Node) registry keys.
- Record raw values (e.g., 1, 0, or Missing).

## Related Windows Server Documentation
- **[Manage SSL Protocols in AD FS](./ReferenceDocs/WindowsServerDocs/identity/ad-fs/operations/Manage-SSL-Protocols-in-AD-FS.md)**: Section on "Enable strong authentication for .NET applications" - covers SchUseStrongCrypto and SystemDefaultTlsVersions registry keys for .NET Framework 3.5, 4.0, and 4.5.x

