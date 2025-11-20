# Check Specification: WinRM Settings

## Objective
Audit Windows Remote Management (WinRM) security configuration.

## Target Settings
Use `WSMan:` drive provider.

## Items to Check
1. **Service Configuration** (`WSMan:\localhost\Service`):
    - `AllowUnencrypted`: Record value.
    - `Auth`:
        - `Basic`: Record value.
        - `Kerberos`: Record value.
        - `Negotiate`: Record value.
        - `CredSSP`: Record value.
2. **Listeners** (`WSMan:\localhost\Listener`):
    - Enumerate listeners.
    - Check `Transport` (HTTP vs HTTPS).
    - If HTTPS, check Certificate Thumbprint.

## Output Details
- Record `AllowUnencrypted` status.
- List enabled Authentication methods.
- List active Listeners and their transport security.

## Baseline Recommended Settings
- **Service**:
    - `AllowBasic`: `0` (Disabled).
    - `AllowUnencryptedTraffic`: `0` (Disabled).
    - `DisableRunAs`: `1` (Disallow storing RunAs credentials).
- **Client**:
    - `AllowBasic`: `0` (Disabled).
    - `AllowUnencryptedTraffic`: `0` (Disabled).
    - `AllowDigest`: `0` (Disabled).

## Related Windows Server Documentation
- **[Configure Remote Management in Server Manager](./ReferenceDocs/WindowsServerDocs/administration/server-manager/configure-remote-management-in-server-manager.md)**: Comprehensive guide to enabling and configuring Windows Remote Management (WinRM) for remote server administration, including firewall configuration and authentication settings
