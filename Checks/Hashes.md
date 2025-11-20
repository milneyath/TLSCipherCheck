# Check Specification: SChannel Hashes

## Objective
Verify which Hashing algorithms are enabled/disabled.

## Target Registry Path
`HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes`

## Items to Check
Iterate through known hashes (MD5, SHA, SHA256, SHA384, SHA512):
- Check `Enabled` (DWORD) value.

## Output Details
- Record the raw `Enabled` value for each hash.
- Note if the key is missing.

## Baseline Recommended Settings
- The Microsoft Security Baseline enforces hash usage primarily through the **Cipher Suite Order** (see `OtherCrypto.md`).
- Weak hashes (MD5, SHA1) are generally deprecated for signature purposes in modern suites, though SHA1 may still appear in some legacy compatibility suites (e.g., `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`).
- The recommended baseline suite order prioritizes SHA256 and SHA384.

## Related Windows Server Documentation
- **[TLS Registry Settings](./ReferenceDocs/WindowsServerDocs/security/tls/tls-registry-settings.md)**: Section on Hashes - explains that hash algorithms should be controlled via cipher suite order
- **[Manage TLS](./ReferenceDocs/WindowsServerDocs/security/tls/manage-tls.md)**: How to configure TLS cipher suite order which controls hash algorithms

