# Check Specification: OS and .NET Info

## Objective
Gather high-level platform metadata.

## Items to Check
1. **OS Info**:
    - Version, Build, Edition.
    - Source: WMI `Win32_OperatingSystem`.
2. **.NET Versions**:
    - Enumerate installed versions from Registry: `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full` (Release key) and older keys if relevant.
    - Translate Release DWORD to version string (e.g., 528040 -> 4.8).

## Output Details
- **CSV Integration**: Return separate objects for `OSVersion`, `OSBuild`, `OSEdition`, `DotNetVersions` to populate summary columns.
- **Detailed Output**: Full dump of OS and .NET properties.

## Related Windows Server Documentation
- **[Comparison of Windows Server Editions](./ReferenceDocs/WindowsServerDocs/get-started/editions-comparison.md)**: Detailed comparison of Windows Server Standard, Datacenter, and Azure Edition features across different versions
- **[What's New in Windows Server 2022](./ReferenceDocs/WindowsServerDocs/get-started/whats-new-in-windows-server-2022.md)**: Overview of new features, security enhancements, and .NET Framework versions included in Windows Server 2022
