# Crypto Audit Script Project Plan

## Overview
This project aims to create a robust PowerShell-based auditing tool to verify cryptographic settings on Windows Servers. The tool will assess compliance with security best practices regarding SChannel protocols, ciphers, hashes, and .NET framework configurations.

## Objectives
1. **Automated Auditing**: Eliminate manual checks of registry keys.
2. **Comprehensive Reporting**: Generate detailed evidence (TXT) and high-level summaries (CSV).
3. **Scalability**: Support processing lists of servers remotely.
4. **Modularity**: Easy to add new checks in the future.

## Architecture

### 1. Main Controller (`Audit-Crypto.ps1`)
- **Role**: Entry point.
- **Inputs**: Text file with server names.
- **Process**:
    - Reads server list.
    - Establishes remote connectivity (WinRM).
    - Iterates through defined checks.
    - Aggregates results.
    - Zips final output.

### 2. Utility Module (`Modules\AuditUtils.psm1`)
- **Logging**: Centralized logging function to write to console and log file.
- **Reporting**: Functions to create the output directory structure and generate the final ZIP.
- **Connectivity**: Helper functions for robust `Invoke-Command` usage with error trapping.

### 3. Check Modules (`Modules\Checks\*.ps1`)
Each check will be a standalone script or function that returns a standard object:
- `CheckName`: Name of the check (e.g., "TLS 1.2").
- `Value`: The actual configured value (e.g., "1", "0", "Enabled", "Missing").
- `Details`: Human-readable explanation or raw output.
- `RawData`: The actual registry value or system setting found.

## Planned Checks
See the `checks` folder for detailed specifications of each check type.
- **Protocols**: SSL/TLS version status (Enabled/Disabled).
- **Ciphers**: Encryption algorithms (AES, RC4, etc.) status.
- **Hashes**: Hashing algorithms (MD5, SHA, etc.) status.
- **.NET**: Strong crypto and default TLS settings for .NET apps.
- **Other**: Key Exchange algorithms, FIPS mode, Cipher Suite Order.
- **IIS**: HSTS, SSL Flags, and Binding info.
- **SMB**: SMBv1/v2/v3 status and signing/encryption requirements.
- **NTLM**: NTLM restriction and security settings.
- **OpenSSH**: `sshd_config` crypto settings and dynamic `authorized_keys` ACL checks.
- **EventLog**: Audit Policy settings for System, Logon, and Object Access categories.
- **WinRM**: Service authentication settings, unencrypted traffic policy, and listener security.
- **Certificates**: Crypto details (Key Length, Algo) for LocalMachine stores.
- **Private Keys**: ACL permissions for certificate private keys.
- **RDP**: Security Layer, Encryption Level, NLA, and Certificate.
- **OS & .NET**: OS Version/Build and installed .NET Framework versions.




## Output Structure
A single ZIP file containing:
- `Audit_Summary_Timestamp.csv`: One row per server with columns for key findings (Values only).
- `Audit_Log_Timestamp.log`: Execution log.
- `ServerName/`: Folder per server (or just prefixed files).
    - `ServerName_Protocols.txt`: Detailed dump of protocol settings.
    - `ServerName_DotNet.txt`: Detailed dump of .NET settings.
    - ...etc.
