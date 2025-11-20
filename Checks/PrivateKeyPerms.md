# Check Specification: Certificate Private Key Permissions

## Objective
Audit ACLs for certificate private keys.

## Scope
For each certificate in LocalMachine stores (My, WebHosting, etc.) where `HasPrivateKey` is True.

## Logic
1. Resolve the backing key container/file.
    - For CAPI: `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` (usually).
    - For CNG: `%ProgramData%\Microsoft\Crypto\Keys`.
    - Use .NET `System.Security.Cryptography.X509Certificates` extensions to find the unique container name.
2. Get ACLs for the key file.

## Items to Capture
- StoreName, Thumbprint
- KeyContainerOrPath
- **ACL**:
    - Identity (Account/SID)
    - Rights (FullControl, Read, etc.)
    - Inheritance

## Output Details
- List ACLs for each private key found.

## Related Windows Server Documentation
- **[Export Certificate Private Key](./ReferenceDocs/WindowsServerDocs/identity/ad-cs/export-certificate-private-key.md)**: Guide to exporting certificates with private keys, including security considerations for protecting private key files
- **[icacls Command](./ReferenceDocs/WindowsServerDocs/administration/windows-commands/icacls.md)**: Reference for the icacls command used to display and modify discretionary access control lists (DACLs) on files, including certificate private key containers
