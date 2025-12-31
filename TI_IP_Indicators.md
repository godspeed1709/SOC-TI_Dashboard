# Threat Intelligence IP Indicators

This document contains IP-based threat intelligence indicators for security operations and monitoring.

> **Note**: The IP addresses shown below are examples using documentation IP ranges (RFC 5737, RFC 3849) for illustration purposes. In production, replace these with actual malicious IPs from your threat intelligence sources.

## IP Indicator Table

| Campaign | IP Address | Subnet | Threat Type | Severity | First Seen | Last Seen | Status | Description | Tags | IOC Source |
|----------|------------|--------|-------------|----------|------------|-----------|--------|-------------|------|------------|
| APT-28 | 203.0.113.10 | /24 | C2 Server | Critical | 2024-01-15 | 2024-12-30 | Active | Command and Control server associated with APT-28 group targeting government entities | APT, C2, State-Sponsored | OSINT |
| Emotet Campaign | 198.51.100.40 | /32 | Malware Distribution | High | 2024-11-01 | 2024-12-25 | Active | Known Emotet malware distribution server | Malware, Banking Trojan, Botnet | Threat Feed |
| DDoS-2024-Q4 | 203.0.113.50 | /28 | DDoS Infrastructure | Medium | 2024-10-10 | 2024-12-20 | Monitored | Part of DDoS botnet infrastructure | DDoS, Botnet | Partner Share |
| Phishing-Finance | 198.51.100.75 | /32 | Phishing | High | 2024-12-01 | 2024-12-28 | Active | Phishing site impersonating financial institutions | Phishing, Credential Theft | Internal Detection |
| Ransomware-Group-X | 203.0.113.120 | /30 | Ransomware C2 | Critical | 2024-09-15 | 2024-12-15 | Blocked | Ransomware command and control infrastructure | Ransomware, C2, Encryption | Vendor Feed |
| Cryptominer-Pool | 198.51.100.100 | /32 | Cryptomining | Low | 2024-08-20 | 2024-12-10 | Monitored | Unauthorized cryptomining pool connection | Cryptomining, Resource Abuse | Network Monitor |
| Data-Exfil-2024 | 203.0.113.150 | /29 | Data Exfiltration | Critical | 2024-11-20 | 2024-12-29 | Active | Suspected data exfiltration destination | Exfiltration, APT | SIEM Alert |
| Spam-Botnet-XYZ | 203.0.113.200 | /26 | Spam/Email | Medium | 2024-07-01 | 2024-11-30 | Inactive | Previously active spam botnet nodes | Spam, Botnet, Email | Blacklist |

## Field Definitions

- **Campaign**: Name or identifier of the threat campaign or operation
- **IP Address**: The malicious or suspicious IP address
- **Subnet**: CIDR notation for the network block (if applicable)
- **Threat Type**: Category of threat (C2 Server, Malware Distribution, Phishing, etc.)
- **Severity**: Risk level (Critical, High, Medium, Low)
- **First Seen**: Date when the indicator was first observed
- **Last Seen**: Date when the indicator was most recently observed
- **Status**: Current state (Active, Monitored, Blocked, Inactive)
- **Description**: Detailed information about the threat
- **Tags**: Comma-separated keywords for categorization
- **IOC Source**: Origin of the indicator (OSINT, Threat Feed, Internal Detection, etc.)

## Usage Guidelines

1. **Critical Severity**: Immediate action required - block and investigate
2. **High Severity**: Priority investigation and containment recommended
3. **Medium Severity**: Monitor and investigate as resources permit
4. **Low Severity**: Track for trending and pattern analysis

## Status Definitions

- **Active**: Currently observed malicious activity
- **Monitored**: Under surveillance, no blocking action taken
- **Blocked**: Actively blocked at network/security controls
- **Inactive**: No recent activity observed, retained for historical reference

## Update Information

- **Last Updated**: 2024-12-31
- **Total Indicators**: 8
- **Active Threats**: 4
- **Review Frequency**: Daily
