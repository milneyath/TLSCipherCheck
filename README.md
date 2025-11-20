# TLSCipherCheck

TLSCipherCheck is a PowerShell module designed to audit Windows servers for cryptographic compliance. It checks for various settings related to TLS protocols, ciphers, hashes, key exchanges, and other security configurations.

## Features

- **Modular Design**: Checks are implemented as individual PowerShell scripts, making it easy to add or modify checks.
- **Remote Auditing**: Uses PowerShell Remoting to audit multiple servers from a single location.
- **Comprehensive Reporting**: Generates a detailed report including:
    - A CSV summary of all checks for all servers.
    - Detailed text files for each check on each server.
    - A ZIP archive containing the full report.
- **Extensible**: Easily add new checks by placing a `.ps1` file in the `Checks` directory.

## Installation

1. Clone or download this repository.
2. Ensure you have PowerShell 5.1 or later.
3. (Optional) Place the module in your `PSModulePath` for easier access, or just run from the source directory.

## Usage

### Running the Main Script

The easiest way to run the audit is using the provided wrapper script `Audit-Crypto.ps1`.

1. Create a `servers.txt` file in the root directory with a list of server names (one per line).
2. Run the script:

```powershell
.\Audit-Crypto.ps1 -ServerList "servers.txt" -OutputPath ".\Output"
```

If you need to provide credentials:

```powershell
$cred = Get-Credential
.\Audit-Crypto.ps1 -Credential $cred
```

### Using the Module Directly

You can also import the module and use the `Invoke-TLSCipherAudit` function directly.

```powershell
Import-Module .\TLSCipherCheck
Invoke-TLSCipherAudit -ServerList "servers.txt" -OutputPath ".\Output"
```

## Module Structure

- **TLSCipherCheck/**: Contains the PowerShell module files.
    - **Checks/**: Contains the individual check scripts.
    - `TLSCipherCheck.psd1`: Module manifest.
    - `TLSCipherCheck.psm1`: Main module logic.
- `Audit-Crypto.ps1`: Wrapper script for easy execution.
- `servers.txt`: List of target servers.

## Adding New Checks

To add a new check:

1. Create a new PowerShell script in `TLSCipherCheck/Checks`.
2. Name it `Check-<Name>.ps1`.
3. The script should output objects with `CheckName` and `Value` properties.

Example:

```powershell
# Check-Example.ps1
[PSCustomObject]@{
    CheckName = "ExampleCheck"
    Value     = "Passed"
}
```
