# Registry Keys and Policy Settings Reference

This document lists all registry keys and policy settings read by the checks in `Modules/Checks`.

## Table of Contents
- [SCHANNEL Settings](#schannel-settings)
  - [Protocols](#protocols)
  - [Ciphers](#ciphers)
  - [Hashes](#hashes)
  - [Key Exchange Algorithms](#key-exchange-algorithms)
- [Cryptography Settings](#cryptography-settings)
  - [FIPS Mode](#fips-mode)
  - [Cipher Suite Order](#cipher-suite-order)
  - [WinHTTP Settings](#winhttp-settings)
  - [Internet Explorer Settings](#internet-explorer-settings)
- [.NET Framework Settings](#net-framework-settings)
- [IIS Settings](#iis-settings)
- [SMB Settings](#smb-settings)
- [NTLM Settings](#ntlm-settings)
- [LDAP Settings](#ldap-settings)
- [Netlogon Settings](#netlogon-settings)
- [WinRM Settings](#winrm-settings)
- [RDP Settings](#rdp-settings)
- [OpenSSH Settings](#openssh-settings)
- [SQL Server Settings](#sql-server-settings)
- [Security Features](#security-features)
- [OS and .NET Version Information](#os-and-net-version-information)

---

## SCHANNEL Settings

### Protocols
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`

For each protocol (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3) and role (Client, Server):

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<Protocol>\<Role>` | `Enabled` | Whether the protocol is enabled (DWORD: 0 or 1) | Check-SChannelProtocols.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\<Protocol>\<Role>` | `DisabledByDefault` | Whether the protocol is disabled by default (DWORD: 0 or 1) | Check-SChannelProtocols.ps1 |

**Example Paths:**
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client`
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server`

### Ciphers
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers`

For each cipher (NULL, DES 56/56, RC2 40/128, RC2 56/128, RC2 128/128, RC4 40/128, RC4 56/128, RC4 64/128, RC4 128/128, Triple DES 168, AES 128/128, AES 256/256):

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\<Cipher>` | `Enabled` | Whether the cipher is enabled (DWORD: 0xFFFFFFFF for enabled, 0x0 for disabled) | Check-SChannelCiphers.ps1 |

**Example Path:**
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256`

### Hashes
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes`

For each hash (MD5, SHA, SHA256, SHA384, SHA512):

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\<Hash>` | `Enabled` | Whether the hash algorithm is enabled (DWORD: 0xFFFFFFFF for enabled, 0x0 for disabled) | Check-SChannelHashes.ps1 |

**Example Path:**
- `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256`

### Key Exchange Algorithms
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms`

For each algorithm (Diffie-Hellman, PKCS, ECDH):

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\<Algorithm>` | `Enabled` | Whether the key exchange algorithm is enabled (DWORD: 0xFFFFFFFF for enabled, 0x0 for disabled) | Check-OtherCrypto.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman` | `ServerMinKeyBitLength` | Minimum server key bit length (DWORD, recommended: 2048) | Check-OtherCrypto.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman` | `ClientMinKeyBitLength` | Minimum client key bit length (DWORD, recommended: 2048) | Check-OtherCrypto.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS` | `ClientMinKeyBitLength` | Minimum client key bit length (DWORD, recommended: 2048) | Check-OtherCrypto.ps1 |

---

## Cryptography Settings

### FIPS Mode
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` | `Enabled` | FIPS 140-2 compliant cryptography mode (DWORD: 0 or 1) | Check-OtherCrypto.ps1 |

### Cipher Suite Order
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002` | `Functions` | GPO-enforced cipher suite order (Multi-String or String) | Check-OtherCrypto.ps1 |

### WinHTTP Settings
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` | `DefaultSecureProtocols` | WinHTTP default secure protocols (DWORD: 2048=TLS1.2, 2560=TLS1.2+1.1) | Check-OtherCrypto.ps1 |
| `HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp` | `DefaultSecureProtocols` | WinHTTP default secure protocols (32-bit) | Check-OtherCrypto.ps1 |

### Internet Explorer Settings
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings` | `SecureProtocols` | Internet Explorer secure protocols (DWORD: 2048=TLS1.2) | Check-OtherCrypto.ps1 |
| `HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings` | `SecureProtocols` | Internet Explorer secure protocols (User) | Check-OtherCrypto.ps1 |

---

## .NET Framework Settings

For each .NET version and architecture (.NET v4 64-bit, .NET v4 32-bit, .NET v2 64-bit, .NET v2 32-bit):

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319` | `SchUseStrongCrypto` | Enable strong cryptography (DWORD: 1=enabled) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319` | `SchUseStrongCrypto` | Enable strong cryptography (32-bit) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727` | `SchUseStrongCrypto` | Enable strong cryptography (.NET 2.0) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727` | `SchUseStrongCrypto` | Enable strong cryptography (.NET 2.0 32-bit) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319` | `SystemDefaultTlsVersions` | Use OS default TLS versions (DWORD: 1=enabled) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319` | `SystemDefaultTlsVersions` | Use OS default TLS versions (32-bit) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727` | `SystemDefaultTlsVersions` | Use OS default TLS versions (.NET 2.0) | Check-DotNetCrypto.ps1 |
| `HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727` | `SystemDefaultTlsVersions` | Use OS default TLS versions (.NET 2.0 32-bit) | Check-DotNetCrypto.ps1 |

---

## IIS Settings

IIS settings are primarily accessed via the WebAdministration module and configuration files, not directly from registry. The module queries:

- Site HSTS (HTTP Strict Transport Security) configuration via `system.applicationHost/sites/site[@name='<sitename>']/hsts`
- SSL Flags via `system.webServer/security/access`
- HTTPS bindings including certificate information

**Module:** Check-IIS.ps1

---

## SMB Settings

SMB settings are primarily queried via `Get-SmbServerConfiguration` cmdlet, with registry fallback:

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `SMB1` | SMB 1.0 protocol status (DWORD: 0=disabled, 1=enabled) | Check-SMB.ps1 |

**Cmdlet-based values checked:**
- `EnableSMB1Protocol`
- `EnableSMB2Protocol` (covers SMB 2.x and 3.x)
- `RequireSecuritySignature`
- `EncryptData`

**Module:** Check-SMB.ps1

---

## NTLM Settings
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0`

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `NtlmMinClientSec` | Minimum client security (DWORD: 0x0=None, 0x80000=NTLMv2) | Check-NTLM.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `NtlmMinServerSec` | Minimum server security (DWORD: 0x0=None, 0x80000=NTLMv2) | Check-NTLM.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `RestrictSendingNTLMTraffic` | Restrict outgoing NTLM traffic (DWORD: 0=Allow, 1=Audit, 2=Deny) | Check-NTLM.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0` | `RestrictReceivingNTLMTraffic` | Restrict incoming NTLM traffic (DWORD: 0=Allow, 1=Audit, 2=Deny) | Check-NTLM.ps1 |

---

## LDAP Settings
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP` | `LDAPClientIntegrity` | LDAP client signing requirements (DWORD: 0=None, 1=Negotiate, 2=Require) | Check-LDAP.ps1 |

---

## Netlogon Settings
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `RequireSignOrSeal` | Require signing or sealing (DWORD: 0 or 1) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `SealSecureChannel` | Seal secure channel (DWORD: 0 or 1) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `SignSecureChannel` | Sign secure channel (DWORD: 0 or 1) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `RequireStrongKey` | Require strong key (DWORD: 0 or 1) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `RefusePasswordChange` | Refuse password change (DWORD: 0 or 1) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `MaximumPasswordAge` | Maximum password age (DWORD: days) | Check-Netlogon.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` | `DisablePasswordChange` | Disable password change (DWORD: 0 or 1) | Check-Netlogon.ps1 |

---

## WinRM Settings

WinRM settings are accessed via the WSMan provider, not directly from registry:

**Base Path:** `WSMan:\localhost\Service`

| WSMan Path | Value Name | Description | Module |
|-----------|------------|-------------|---------|
| `WSMan:\localhost\Service` | `AllowUnencrypted` | Allow unencrypted WinRM traffic (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `Basic` | Basic authentication (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `Kerberos` | Kerberos authentication (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `Negotiate` | Negotiate authentication (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `CredSSP` | CredSSP authentication (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `Certificate` | Certificate authentication (true/false) | Check-WinRM.ps1 |
| `WSMan:\localhost\Service\Auth` | `CbtHardeningLevel` | Channel Binding Token hardening level | Check-WinRM.ps1 |
| `WSMan:\localhost\Listener\<ListenerName>` | `Transport` | Transport protocol (HTTP/HTTPS) | Check-WinRM.ps1 |
| `WSMan:\localhost\Listener\<ListenerName>` | `Port` | Listener port | Check-WinRM.ps1 |
| `WSMan:\localhost\Listener\<ListenerName>` | `CertificateThumbprint` | Certificate thumbprint for HTTPS listeners | Check-WinRM.ps1 |

---

## RDP Settings
**Base Path:** `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | `SecurityLayer` | Security layer (DWORD: 0=RDP, 1=Negotiate, 2=SSL/TLS) | Check-RDPSettings.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | `MinEncryptionLevel` | Minimum encryption level (DWORD: 1=Low, 2=Client Compatible, 3=High, 4=FIPS) | Check-RDPSettings.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | `UserAuthentication` | Network Level Authentication (DWORD: 0=Disabled, 1=Enabled) | Check-RDPSettings.ps1 |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | `SSLCertificateSHA1Hash` | RDP listener certificate thumbprint (Binary/Byte Array) | Check-RDPSettings.ps1 |

---

## OpenSSH Settings

OpenSSH settings are read from configuration files and file system permissions, not registry:

**Configuration File:** `%ProgramData%\ssh\sshd_config`

**Configuration Values Checked:**
- `Ciphers` - Allowed cipher algorithms
- `MACs` - Message authentication code algorithms
- `KexAlgorithms` - Key exchange algorithms
- `PasswordAuthentication` - Allow password authentication
- `PubkeyAuthentication` - Allow public key authentication
- `PermitRootLogin` - Allow root login
- `SyslogFacility` - Syslog facility for logging
- `LogLevel` - Logging level
- `AuthorizedKeysFile` - Path to authorized keys file (default: `.ssh/authorized_keys`)

**File Permissions Checked:**
- Host key files: `%ProgramData%\ssh\ssh_host_*_key`
- Authorized keys files (per user)

**Module:** Check-OpenSSH.ps1

---

## SQL Server Settings

SQL Server settings are read from registry for each discovered instance:

**Discovery Path:** `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL`

| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\Setup` | `Version` | SQL Server version string | Check-SQLServer.ps1 |
| `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\SuperSocketNetLib` | `Certificate` | Certificate thumbprint for TLS encryption | Check-SQLServer.ps1 |
| `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\SuperSocketNetLib` | `ForceEncryption` | Force encryption flag (DWORD: 0 or 1) | Check-SQLServer.ps1 |
| `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\SuperSocketNetLib\Tcp\IPAll` | `TcpPort` | Static TCP port | Check-SQLServer.ps1 |
| `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\<InstanceID>\MSSQLServer\SuperSocketNetLib\Tcp\IPAll` | `TcpDynamicPorts` | Dynamic TCP port | Check-SQLServer.ps1 |

**Additional Checks:**
- Active TLS protocol testing against SQL Server instances (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3)
- Certificate details from TLS handshake
- TDS 8.0 support detection (SQL Server 2022+, version 16+)

---

## Security Features

### LSA Protection
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | LSA Protection (DWORD: 1=Enabled) | Check-SecurityFeatures.ps1 |

### Memory Integrity (HVCI)
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | `Enabled` | Hypervisor-Enforced Code Integrity (DWORD: 1=Enabled) | Check-SecurityFeatures.ps1 |

### TPM Status
Queried via `Get-Tpm` cmdlet (not registry)

**Module:** Check-SecurityFeatures.ps1

### Credential Guard
Queried via `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`

**Values checked:**
- `SecurityServicesRunning` (Array: 1=Credential Guard)
- `VirtualizationBasedSecurityStatus`

**Module:** Check-SecurityFeatures.ps1

---

## OS and .NET Version Information

### Operating System Information
Queried via WMI `Win32_OperatingSystem` class:
- `Version`
- `BuildNumber`
- `Caption`

**Module:** Check-OSDotNetInfo.ps1

### .NET Framework Versions
| Registry Path | Value Name | Description | Module |
|--------------|------------|-------------|---------|
| `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` | `Release` | .NET 4.x release number (maps to specific version) | Check-OSDotNetInfo.ps1 |
| `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5` | `Install` | .NET 3.5 installation status (DWORD: 1=installed) | Check-OSDotNetInfo.ps1 |
| `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.0\Setup` | `InstallSuccess` | .NET 3.0 installation status (DWORD: 1=installed) | Check-OSDotNetInfo.ps1 |
| `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v2.0.50727` | `Install` | .NET 2.0 installation status (DWORD: 1=installed) | Check-OSDotNetInfo.ps1 |

**.NET 4.x Release Number Mapping:**
- 533320+ = .NET 4.8.1
- 528040+ = .NET 4.8
- 461808+ = .NET 4.7.2
- 461308+ = .NET 4.7.1
- 460798+ = .NET 4.7
- 394802+ = .NET 4.6.2
- 394254+ = .NET 4.6.1
- 393295+ = .NET 4.6
- 379893+ = .NET 4.5.2
- 378675+ = .NET 4.5.1
- 378389+ = .NET 4.5

---

## Certificate Stores

The following certificate stores are examined for cryptographic details and private key permissions:

**Stores Checked:**
- `Cert:\LocalMachine\My`
- `Cert:\LocalMachine\WebHosting`
- `Cert:\LocalMachine\Remote Desktop`
- `Cert:\LocalMachine\Root`
- `Cert:\LocalMachine\CA`

**Certificate Information Extracted:**
- Subject
- Issuer
- Serial Number
- Thumbprint
- Signature Algorithm
- Public Key Algorithm
- Key Length
- Has Private Key
- Key Provider (CSP or CNG)

**Private Key File Locations:**
- CAPI Keys: `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys\<ContainerName>`
- DSS Keys: `%ProgramData%\Microsoft\Crypto\DSS\MachineKeys\<ContainerName>`
- CNG Keys: `%ProgramData%\Microsoft\Crypto\Keys\<ContainerName>`

**Modules:**
- Check-CertificatesCrypto.ps1
- Check-CertPrivateKeyPerms.ps1

---

## Audit Policy Settings

Audit policies are queried via `auditpol.exe /get /category:* /r` (not registry).

**Relevant Subcategories Checked:**
- Security State Change
- Security System Extension
- System Integrity
- Logon
- Logoff
- Special Logon
- File System
- Registry
- Sensitive Privilege Use

**Module:** Check-EventLog.ps1

---

## Local Website TLS Testing

**Module:** Check-LocalWebsites.ps1

This module performs active TLS protocol testing against local HTTPS endpoints discovered via IIS bindings or defaults to localhost:443.

**Protocols Tested:**
- SSL 2.0
- SSL 3.0
- TLS 1.0
- TLS 1.1
- TLS 1.2
- TLS 1.3

**Information Captured:**
- Protocol support status
- Certificate details from TLS handshake
- Certificate subject, issuer, thumbprint, and expiration

---

## Notes

1. **Missing Keys:** If a registry key or value is not present, the checks report "Missing", "Not Configured", or "System Default" as appropriate. This indicates the setting is using OS defaults.

2. **Policy Precedence:** Group Policy settings typically take precedence over local registry settings. The checks capture what is configured in the registry, which may be enforced via GPO.

3. **Dynamic Values:** Some settings (like SQL Server ports, IIS bindings, and OpenSSH authorized keys) are dynamically discovered based on the system configuration.

4. **Architecture:** For settings that differ between 32-bit and 64-bit, both registry paths are checked (e.g., `SOFTWARE` vs `SOFTWARE\Wow6432Node`).

5. **Cmdlet-based Checks:** Some checks (SMB, WinRM, TPM, Credential Guard, IIS, Audit Policy) use PowerShell cmdlets or WMI/CIM queries rather than direct registry access.

6. **File-based Checks:** OpenSSH configuration and certificate private key permissions are checked via file system access.

---

**Generated:** 2025-11-20  
**Tool Version:** TLSCipherCheck  
**Total Modules Analyzed:** 20
