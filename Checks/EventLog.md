# Check Specification: EventLog Audit Policy

## Objective
Audit Windows Advanced Audit Policy settings relevant to security and cryptography.

## Target Settings
Use `auditpol.exe /get /category:*` to retrieve effective policy.

## Items to Check
1. **System**:
    - `Security State Change`
    - `Security System Extension`
    - `System Integrity`
2. **Logon/Logoff**:
    - `Logon`
    - `Logoff`
    - `Special Logon`
3. **Object Access**:
    - `Audit File System` (if relevant for key files)
    - `Audit Registry` (if relevant for crypto keys)
4. **Privilege Use**:
    - `Sensitive Privilege Use`

## Output Details
- Record the status (Success, Failure, No Auditing) for each subcategory.

## Baseline Recommended Settings
- **System**:
    - `Security State Change`: Success (1) or Success+Failure (3).
    - `Security System Extension`: Success (1) or Success+Failure (3).
    - `System Integrity`: Success and Failure (3).
- **Logon/Logoff**:
    - `Logon`: Success and Failure (3).
    - `Logoff`: Success (1) or Success+Failure (3).
    - `Special Logon`: Success (1) or Success+Failure (3).
- **Privilege Use**:
    - `Sensitive Privilege Use`: Success and Failure (3).
- **Other**:
    - `Audit Policy Change`: Success (1).
    - `Audit Authentication Policy Change`: Success (1).
    - `Audit Authorization Policy Change`: Success (1).
