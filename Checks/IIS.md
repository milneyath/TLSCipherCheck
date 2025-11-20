# Check Specification: IIS Crypto Settings

## Objective
Audit IIS configuration for cryptographic settings, including HSTS and SSL Flags.

## Target Settings
1. **HSTS (HTTP Strict Transport Security)**:
    - Check `applicationHost.config` or site-level `web.config`.
    - Look for `<hsts>` element or custom headers (`Strict-Transport-Security`).
2. **SSL Flags**:
    - Check `system.webServer/security/access`.
    - `sslFlags`: `Ssl`, `SslRequireCert`, `SslNegotiateCert`, `Ssl128`.
3. **Bindings**:
    - List all HTTPS bindings.
    - Record associated Certificate Hash (Thumbprint) and Store.
    - Check for legacy bindings (IP:Port vs Hostname).

## Output Details
- List HSTS status per site (Enabled/Disabled/Max-Age).
- List SSL Flags per site/application.
- Dump HTTPS binding details.

## Related Windows Server Documentation
- **[TLS Registry Settings](./ReferenceDocs/WindowsServerDocs/security/tls/tls-registry-settings.md)**: Section on "EnableOcspStaplingForSni" - covers OCSP stapling for IIS websites with SNI and Centralized Certificate Store bindings
- **[Manage SSL Protocols in AD FS](./ReferenceDocs/WindowsServerDocs/identity/ad-fs/operations/Manage-SSL-Protocols-in-AD-FS.md)**: Examples of managing SSL/TLS protocols and cipher suites for web services over http.sys (applicable to IIS)
