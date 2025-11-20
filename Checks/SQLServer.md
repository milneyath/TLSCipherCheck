# Check Specification: SQL Server TLS Support

## Objective
Audit the TLS configuration of local SQL Server instances. This check determines if the SQL Server instance supports secure TLS protocols and identifies the certificate being used for encryption.

## Target
- **Registry**: `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL` (Discovery)
- **Registry**: `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\[InstanceID]\MSSQLServer\SuperSocketNetLib` (Configuration)
- **Network**: Localhost connection to the SQL Server TCP port (default 1433).

## Items to Check
1.  **Instance Discovery**: Identifies running SQL Server instances and their TCP ports.
2.  **Protocol Support**: Actively tests connection using:
    -   SSL 2.0, SSL 3.0
    -   TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
3.  **Certificate Usage**:
    -   Retrieves the certificate configured in the Registry (`SuperSocketNetLib\Certificate`).
    -   Captures the certificate presented during the TLS handshake.
4.  **Configuration**: Checks `ForceEncryption` status and SQL Server version (TDS 8.0 support).

## Output Details
- **Supported**: The SQL Server accepted the TLS handshake with this protocol.
- **Not Supported**: The handshake failed.
    -   *Note*: For SQL Server versions prior to 2022 (TDS 7.x), a handshake failure is expected if `ForceEncryption` is Off, as the server expects a cleartext TDS pre-login packet first.
- **Details**: Includes `ForceEncryption` status, SQL Version, and Certificate Thumbprints (Registry vs. Wire).

## Baseline Recommended Settings
- **SSL 2.0 / 3.0**: Not Supported
- **TLS 1.0 / 1.1**: Not Supported
- **TLS 1.2**: Supported
- **TLS 1.3**: Supported (SQL Server 2022+)
- **ForceEncryption**: On (Recommended for security)

## Related SQL Server Documentation
- **[TLS 1.3 Support](./ReferenceDocs/SQLServerDocs/relational-databases/security/networking/tls-1-3.md)**: TLS 1.3 support in SQL Server 2022+, including differences from TLS 1.2, driver support, OS requirements, and certificate requirements for TDS 8.0
- **[TDS 8.0](./ReferenceDocs/SQLServerDocs/relational-databases/security/networking/tds-8.md)**: Tabular Data Stream protocol version 8.0 with mandatory encryption, compatibility matrix for TDS/TLS/OS versions, and connection string encryption options
- **[Connect with TLS 1.3](./ReferenceDocs/SQLServerDocs/relational-databases/security/networking/connect-with-tls-1-3.md)**: Step-by-step guide to configure SQL Server and clients to use TLS 1.3, including connection string examples and troubleshooting
- **[Connect with Strict Encryption](./ReferenceDocs/SQLServerDocs/relational-databases/security/networking/connect-with-strict-encryption.md)**: How to configure and test strict encryption connections, including ODBC/OLE DB setup and SQL Server Configuration Manager settings
- **[Certificate Overview](./ReferenceDocs/SQLServerDocs/database-engine/configure-windows/certificate-overview.md)**: Overview of certificate management in SQL Server, including requirements, installation, and configuration for encrypted connections
- **[SQL Server Certificates and Asymmetric Keys](./ReferenceDocs/SQLServerDocs/relational-databases/security/sql-server-certificates-and-asymmetric-keys.md)**: Overview of certificate usage in SQL Server for securing connections, database mirroring, and encryption
- **[SQL Server Encryption](./ReferenceDocs/SQLServerDocs/relational-databases/security/encryption/sql-server-encryption.md)**: Comprehensive guide to encryption in SQL Server including TLS 1.2 and TLS 1.3 support
- **[What's New in SQL Server 2022](./ReferenceDocs/SQLServerDocs/sql-server/what-s-new-in-sql-server-2022.md)**: Security features including TDS 8.0 protocol support and TLS 1.3 compatibility (SQL Server 2022+)

