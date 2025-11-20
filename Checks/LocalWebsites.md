# Check Specification: Local Websites TLS Support

## Objective
Actively test local websites to determine which TLS protocols are *actually* accepted by the running service. This complements the registry-based checks by verifying the effective configuration of the listening service (e.g., IIS).

## Target
- **Primary**: Local IIS Bindings (enumerated via `WebAdministration` module).
- **Fallback**: `localhost:443` if no IIS bindings are found.

## Items to Check
The script attempts to establish a client connection using each of the following protocols:
1.  **SSL 2.0**
2.  **SSL 3.0**
3.  **TLS 1.0**
4.  **TLS 1.1**
5.  **TLS 1.2**
6.  **TLS 1.3**

## Output Details
For each identified target (Host:Port) and Protocol:
- **Supported**: The server accepted the connection with this protocol.
- **Not Supported**: The handshake failed or was rejected.
- **Skipped**: The protocol is not supported by the client (the script runner) or environment.

## Baseline Recommended Settings
- **SSL 2.0**: Not Supported
- **SSL 3.0**: Not Supported
- **TLS 1.0**: Not Supported
- **TLS 1.1**: Not Supported
- **TLS 1.2**: Supported
- **TLS 1.3**: Supported (Windows Server 2022 / Windows 11+)

## Related Windows Server Documentation
- **[Protocols in TLS/SSL (Schannel SSP)](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)**: Overview of supported protocols in the Windows Schannel Security Support Provider.
