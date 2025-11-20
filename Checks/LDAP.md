# Check Specification: LDAP Settings

## Objective
Audit LDAP signing and channel binding requirements to prevent NTLM relay attacks and ensure traffic integrity.

## Target Registry Paths
1. **Client Settings**: `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP`

## Items to Check
1. **Client Signing**:
    - `LDAPClientIntegrity` (DWORD).
    - Baseline Value: `1` (Require Signing).

## Output Details
- Record `LDAPClientIntegrity` value.

## Baseline Recommended Settings
- **Client**: `LDAPClientIntegrity` = `1`.

