# Check Specification: Certificates Crypto Details

## Objective
Enumerate certificates on the target server and capture only cryptographic attributes.

## Target Stores
- `Cert:\LocalMachine\My`
- `Cert:\LocalMachine\WebHosting`
- `Cert:\LocalMachine\Remote Desktop`
- `Cert:\LocalMachine\Root` (Trusted Root CA)
- `Cert:\LocalMachine\CA` (Intermediate CA)

## Items to Capture
For each certificate:
- StoreName
- Subject, Issuer
- SerialNumber, Thumbprint
- **Crypto Details**:
    - SignatureAlgorithm (e.g., sha256RSA)
    - PublicKeyAlgorithm (e.g., RSA, ECDSA)
    - KeyLength (e.g., 2048, 4096)
    - KeyAlgorithmParameters (if available)
    - HasPrivateKey (True/False)
    - KeyProvider / KeyStorageProvider

## Output Details
- List all certificates with the above fields.
