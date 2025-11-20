# Check Specification: Other Crypto Settings

## Objective
Verify miscellaneous cryptographic settings including Key Exchanges and FIPS compliance.

## Target Registry Paths
1. **Key Exchanges**: `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms`
    - Check `Diffie-Hellman`, `PKCS`, `ECDH` enabled status.
    - **Key Lengths**:
        - `Diffie-Hellman`: Check `ServerMinKeyBitLength` and `ClientMinKeyBitLength` (Recommended: 2048).
        - `PKCS`: Check `ClientMinKeyBitLength` (Recommended: 2048).
2. **FIPS Mode**: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`
    - `Enabled` (DWORD).
    - Generally SHOULD be `0` unless specifically required by compliance (FIPS often breaks apps).
3. **WinHTTP**:
    - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`
    - `HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp`
    - Check `DefaultSecureProtocols` (DWORD).
4. **Internet Explorer / System**:
    - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`
    - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
    - Check `SecureProtocols` (DWORD).
5. **Cipher Suite Order** (Optional/Advanced):
    - `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`
    - `Functions` (String/MultiString).
    - Check if a specific order is enforced via GPO.

## Output Details
- List status of Key Exchange algorithms and their minimum key bit lengths.
- Report FIPS mode status (Enabled/Disabled).
- Report WinHTTP `DefaultSecureProtocols` values (Hex/Decimal).
- Report IE `SecureProtocols` values.
- Dump Cipher Suite order if configured.

## Baseline Recommended Settings
- **Cipher Suite Order** (`HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` -> `Functions`):
    - `TLS_AES_128_GCM_SHA256`
    - `TLS_AES_256_GCM_SHA384`
    - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
    - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
    - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
    - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
    - `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`
    - `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`
    - `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
    - `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`
- **ECC Curves** (`HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` -> `EccCurves`):
    - `NistP256`
    - `NistP384`
- **Key Protection**:
    - `ForceKeyProtection` = `2`.

## Related Windows Server Documentation
- **[TLS Registry Settings](./ReferenceDocs/WindowsServerDocs/security/tls/tls-registry-settings.md)**: Section on "KeyExchangeAlgorithm key sizes" - covers Diffie-Hellman and RSA/PKCS minimum key bit lengths
- **[Manage TLS](./ReferenceDocs/WindowsServerDocs/security/tls/manage-tls.md)**: Complete guide on configuring cipher suite order via Group Policy, MDM, or PowerShell; also covers ECC curve order configuration
- **[What's New in TLS/SSL](./ReferenceDocs/WindowsServerDocs/security/tls/what-s-new-in-tls-ssl-schannel-ssp-overview.md)**: Information about FIPS compliance and cryptographic algorithm updates

