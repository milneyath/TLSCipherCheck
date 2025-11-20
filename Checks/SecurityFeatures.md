# Check Specification: Windows Security Features

## Objective
Audit the status of critical Windows security features that rely on hardware security (TPM) and virtualization-based security (VBS).

## Target
- **TPM**: `Get-Tpm` cmdlet.
- **Credential Guard**: WMI `Win32_DeviceGuard` class.
- **LSA Protection**: Registry `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`.
- **Memory Integrity**: Registry `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled`.

## Items to Check
1.  **TPM (Trusted Platform Module)**:
    -   **Ready**: TPM is initialized and ready for use.
    -   **Enabled**: TPM is enabled in BIOS/UEFI.
2.  **Credential Guard**:
    -   Verifies if the Credential Guard service is running (protects NTLM/Kerberos secrets).
3.  **LSA Protection (RunAsPPL)**:
    -   Verifies if LSASS runs as a Protected Process Light (prevents code injection into LSASS).
4.  **Memory Integrity (HVCI)**:
    -   Verifies if Hypervisor-Enforced Code Integrity is enabled (prevents unsigned kernel drivers).

## Output Details
- **Value**: `Enabled`, `Disabled`, `Ready`, `Not Ready`, or `Running`.
- **Details**: Provides specific status codes, registry values, or error messages (e.g., "VBS Status: 2").

## Baseline Recommended Settings
- **TPM**: Ready
- **Credential Guard**: Running
- **LSA Protection**: Enabled (`RunAsPPL = 1` or `2`)
- **Memory Integrity**: Enabled

## Related Windows Server Documentation
- **[Configure Additional LSA Protection](./ReferenceDocs/WindowsServerDocs/security/credentials-protection-and-management/configuring-additional-lsa-protection.md)**: Complete guide to configuring LSA (LSASS) to run as a protected process (RunAsPPL), including audit mode, UEFI lock, and Group Policy configuration
- **[Credential Guard Protected Machine Accounts](./ReferenceDocs/WindowsServerDocs/identity/ad-ds/manage/delegated-managed-service-accounts/credential-guard-protected-machine-accounts.md)**: Machine identity isolation configuration for virtualization-based protection of AD machine accounts
- **[Secured-core Server Overview](./ReferenceDocs/WindowsServerDocs/security/secured-core-server.md)**: Overview of Secured-core server capabilities including hardware-backed root of trust, firmware attack defense, and HVCI (Memory Integrity)
- **[Configure Secured-core Server](./ReferenceDocs/WindowsServerDocs/security/configure-secured-core-server.md)**: Step-by-step configuration guide for Secured-core server features including VBS, HVCI, and System Guard Secure Launch
- **[Kernel Mode Hardware Stack Protection](./ReferenceDocs/WindowsServerDocs/security/kernel-mode-hardware-stack-protection.md)**: Information about kernel-mode hardware-enforced stack protection and virtualization-based security features
- **[Credentials Protection and Management](./ReferenceDocs/WindowsServerDocs/security/credentials-protection-and-management/credentials-protection-and-management.md)**: Overview of credential protection strategies including LSA protection and Credential Guard
- **[TPM Key Attestation](./ReferenceDocs/WindowsServerDocs/identity/ad-ds/manage/component-updates/TPM-Key-Attestation.md)**: Using TPM for key attestation in Active Directory environments

