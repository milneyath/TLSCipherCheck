# Check Specification: SChannel Ciphers

## Objective
Verify which Cipher algorithms are enabled/disabled.

## Target Registry Path
`HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers`

## Items to Check
Iterate through the following specific cipher suites:
    - `DES 56/56`
    - `NULL`
    - `RC2 128/128`, `RC2 40/128`, `RC2 56/128`
    - `RC4 40/128`, `RC4 56/128`, `RC4 64/128`, `RC4 128/128`
    - `Triple DES 168`
    - `AES 128/128`
    - `AES 256/256`

For each, check the `Enabled` (DWORD) value.

## Output Details
- Record the raw `Enabled` value for each cipher.
- Note if the key is missing.

## Baseline Recommended Settings
- The Microsoft Security Baseline enforces cipher usage primarily through the **Cipher Suite Order** (see `OtherCrypto.md`).
- Individual SCHANNEL cipher keys (`RC4`, `DES`, `NULL`) should generally be disabled or not present.
- **Recommended Cipher Suites** include `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and GCM-based ECDHE suites.
- Weak ciphers (RC4, DES, 3DES, NULL) are excluded from the recommended suite order.

## Related Windows Server Documentation
- **[TLS Registry Settings](./ReferenceDocs/WindowsServerDocs/security/tls/tls-registry-settings.md)**: Section on Ciphers and CipherSuites configuration
- **[Manage TLS](./ReferenceDocs/WindowsServerDocs/security/tls/manage-tls.md)**: How to configure TLS cipher suite order using Group Policy, MDM, or PowerShell

