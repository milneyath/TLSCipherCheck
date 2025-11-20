# Check Specification: OpenSSH Settings

## Objective
Audit OpenSSH for Windows configuration (`sshd_config`) and file permissions.

## Target Settings
1. **Configuration File**: `C:\ProgramData\ssh\sshd_config` (or default install path).
    - **Crypto**: `Ciphers`, `MACs`, `KexAlgorithms`.
    - **Auth**: `PasswordAuthentication`, `PubkeyAuthentication`, `PermitRootLogin`.
    - **Logging**: `SyslogFacility`, `LogLevel`.

2. **File Permissions (ACLs)**:
    - **Host Keys**: `ssh_host_*_key` in ProgramData.
    - **Authorized Keys**:
        - Parse `AuthorizedKeysFile` directive from config.
        - Handle tokens like `%h` (User Home) and `%u` (Username).
        - For `%h`, iterate through `C:\Users` to find actual files.
        - Check ACLs: Should be restricted to Owner, SYSTEM, Administrators.


## Output Details
- Dump relevant `sshd_config` lines.
- Report ACL SDDL or simplified owner/access list for critical files.

## Related Windows Server Documentation
- **[OpenSSH for Windows Overview](./ReferenceDocs/WindowsServerDocs/administration/OpenSSH/openssh-overview.md)**: Introduction to OpenSSH components and tools for secure remote system administration on Windows
- **[OpenSSH Server Configuration](./ReferenceDocs/WindowsServerDocs/administration/OpenSSH/openssh-server-configuration.md)**: Detailed guide to Windows-specific OpenSSH server configuration options including sshd_config settings, authentication methods, and authorized keys file locations
- **[OpenSSH Key Management](./ReferenceDocs/WindowsServerDocs/administration/OpenSSH/OpenSSH_KeyManagement.md)**: Key-based authentication setup, including ACL requirements for authorized_keys files and administrators_authorized_keys with proper permissions (SYSTEM and Administrators only)
