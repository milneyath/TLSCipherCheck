# Check Specification: Netlogon Settings

## Objective
Audit Netlogon secure channel signatures and encryption for **Domain Members** to ensure traffic to the Domain Controller is secure.

## Target Registry Path
`HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`

## Items to Check
1. **Secure Channel Security**:
    - `RequireSignOrSeal`: `1` (Always encrypt or sign).
    - `SealSecureChannel`: `1` (Encrypt when possible).
    - `SignSecureChannel`: `1` (Sign when possible).
    - `RequireStrongKey`: `1` (Require strong session key).
2. **Password Management**:
    - `RefusePasswordChange`: `0` (Allow machine password changes).
    - `MaximumPasswordAge`: `30` (Days).
    - `DisablePasswordChange`: `0`.

## Output Details
- Record values for all Secure Channel security settings.
- Record Machine Account Password settings.

## Baseline Recommended Settings
- **Security**:
    - `RequireSignOrSeal` = `1`
    - `SealSecureChannel` = `1`
    - `SignSecureChannel` = `1`
    - `RequireStrongKey` = `1`
- **Passwords**:
    - `RefusePasswordChange` = `0`
    - `MaximumPasswordAge` = `30`
    - `DisablePasswordChange` = `0`
 