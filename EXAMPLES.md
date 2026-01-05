# Examples and Use Cases

This document provides practical examples of using the AI Security Assistant.

## Table of Contents

1. [Log File Analysis](#log-file-analysis)
2. [Network Security Monitoring](#network-security-monitoring)
3. [File Integrity Checking](#file-integrity-checking)
4. [Registry Monitoring (Windows)](#registry-monitoring-windows)
5. [AI-Assisted Analysis](#ai-assisted-analysis)
6. [Command Line Usage](#command-line-usage)

---

## Log File Analysis

### Scenario: Detect Failed Login Attempts

**GUI Method:**
1. Go to Settings → Add Log Path
2. Add `/var/log/auth.log` (Linux) or security event logs
3. Go to Security Scans → Scan Log Files
4. Review findings for "Failed Login Attempt" entries
5. Click "Analyze Results with AI" for detailed analysis

**CLI Method:**
```bash
python cli.py scan-logs --file /var/log/auth.log --ai-analysis
```

### Scenario: Monitor Web Server Access Logs

**What to look for:**
- SQL injection attempts
- XSS attack patterns
- Directory traversal attempts
- Suspicious user agents
- Unusual request patterns

**GUI Method:**
1. Add `/var/log/apache2/access.log` or `/var/log/nginx/access.log`
2. Run scan
3. Review HIGH severity findings
4. Get AI recommendations for mitigation

---

## Network Security Monitoring

### Scenario: Identify Suspicious Network Connections

**What the scan detects:**
- Connections to known malicious ports
- Unexpected listening services
- Unusual remote connections
- High-risk protocols (IRC, SOCKS proxy)

**GUI Method:**
1. Go to Security Scans → Analyze Network
2. Review suspicious findings section
3. Check process names for unknown applications
4. Use AI analysis to assess threat level

**CLI Method:**
```bash
python cli.py scan-network --ai-analysis
```

### Common Suspicious Ports

| Port  | Potential Threat |
|-------|------------------|
| 31337 | Back Orifice Trojan |
| 12345 | NetBus Trojan |
| 4444  | Metasploit Default |
| 6667  | IRC (C&C Channel) |
| 3389  | RDP (Brute Force Target) |

---

## File Integrity Checking

### Scenario: Scan Downloaded Executable

**What to check:**
- File hash matches known malware
- Suspicious strings (cmd.exe, powershell, eval)
- Base64-encoded content (obfuscation)
- Network download commands
- System file access patterns

**GUI Method:**
1. Go to Security Scans → Scan File
2. Select the file to scan
3. Review hash values (MD5, SHA256)
4. Check for suspicious strings
5. Get AI assessment of threat level

**CLI Method:**
```bash
python cli.py scan-file --file suspicious_download.exe --ai-analysis
```

### Scenario: Scan Web Application Directory

**For web developers:**
```bash
# Scan uploaded files directory
python cli.py scan-file --directory /var/www/uploads --ai-analysis
```

**What to look for:**
- PHP/Python code injection
- Web shells
- Malicious scripts
- Backdoors

---

## Registry Monitoring (Windows)

### Scenario: Check for Persistence Mechanisms

**What the scan detects:**
- Autorun entries in registry
- Suspicious service installations
- Entries pointing to temp directories
- Obfuscated registry values
- Unknown executables in startup

**GUI Method:**
1. Run application as Administrator
2. Go to Security Scans → Scan Registry
3. Review suspicious autorun entries
4. Check service paths for temp/roaming directories
5. Analyze with AI for remediation steps

**CLI Method (as Administrator):**
```bash
python cli.py scan-registry --ai-analysis
```

### Common Persistence Locations

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services`

---

## AI-Assisted Analysis

### Scenario: Get Remediation Steps

**Question:** "I found a suspicious autorun entry. How do I safely remove it?"

**Steps:**
1. Run registry scan to identify the entry
2. Copy details to chat
3. Ask: "How do I safely remove this registry entry: [details]"
4. AI provides step-by-step remediation

### Scenario: Understand a Threat

**Question:** "What is a Back Orifice trojan and how does it work?"

**Steps:**
1. Go to Chat tab
2. Ask the question
3. Get detailed explanation
4. Follow up: "How can I detect and remove it?"

### Scenario: Analyze Multiple Findings

After running multiple scans:

1. Review all scan results
2. Chat: "I have multiple HIGH severity findings across network and log scans. What should I prioritize?"
3. AI helps you triage based on severity and risk

---

## Command Line Usage

### Basic Security Assessment Script

```bash
#!/bin/bash
# Complete security assessment

echo "=== Running Security Assessment ==="

echo "\n1. Scanning logs..."
python cli.py scan-logs --directory /var/log --ai-analysis

echo "\n2. Analyzing network..."
python cli.py scan-network --ai-analysis

echo "\n3. Checking critical files..."
python cli.py scan-file --file /etc/passwd
python cli.py scan-file --file /etc/shadow

echo "\n=== Assessment Complete ==="
```

### Automated Monitoring

Set up a cron job for regular scans:

```bash
# crontab -e
# Run security scan daily at 2 AM
0 2 * * * /usr/bin/python3 /path/to/AI-Sec-Assist/cli.py scan-logs --ai-analysis > /var/log/security-scan.log 2>&1
```

### Interactive Security Consultation

```bash
# Start interactive chat session
python cli.py chat

# Example conversation:
# You: How do I secure my SSH server?
# AI: [Provides detailed SSH hardening steps]
# You: What about fail2ban configuration?
# AI: [Explains fail2ban setup]
```

---

## Integration Examples

### Python Script Integration

```python
import sys
sys.path.insert(0, 'src')

from scanners.network_analyzer import NetworkAnalyzer
from ai.ollama_client import OllamaClient, SecurityAI

# Run network scan
analyzer = NetworkAnalyzer()
findings = analyzer.analyze_connections()

# Get AI analysis
client = OllamaClient()
ai = SecurityAI(client, "llama2")

for finding in findings:
    if finding.get('severity') == 'HIGH':
        analysis = ai.get_remediation_steps(
            f"{finding['type']}: {finding['description']}"
        )
        print(f"Threat: {finding['description']}")
        print(f"Remediation: {analysis}\n")
```

### Custom Security Check Script

```python
#!/usr/bin/env python3
"""
Custom security checker for specific threat
"""
import sys
sys.path.insert(0, 'src')

from scanners.file_scanner import FileScanner

def check_web_shells(directory):
    """Check web directory for shells"""
    scanner = FileScanner()
    
    # Scan PHP files
    results = scanner.scan_directory(
        directory, 
        extensions=['.php', '.php3', '.phtml']
    )
    
    for result in results:
        findings = result.get('findings', [])
        for finding in findings:
            if finding.get('severity') == 'CRITICAL':
                print(f"⚠️  CRITICAL: {result['filepath']}")
                print(f"   {finding['pattern']}")

if __name__ == "__main__":
    check_web_shells('/var/www/html')
```

---

## Best Practices

### 1. Regular Scanning Schedule

- **Logs**: Daily or real-time
- **Network**: Every hour during business hours
- **Files**: After deployments or updates
- **Registry**: Weekly

### 2. Response Workflow

1. **Detection**: Run automated scans
2. **Analysis**: Use AI to assess severity
3. **Investigation**: Deep dive into HIGH severity items
4. **Remediation**: Follow AI-provided steps
5. **Verification**: Re-scan to confirm resolution

### 3. False Positive Management

- Review AI assessment before taking action
- Cross-reference with other security tools
- Maintain a whitelist of known-good patterns
- Document false positives for future reference

### 4. Security Posture

- Don't rely solely on this tool
- Complement with firewall, IDS/IPS
- Keep systems patched and updated
- Follow security best practices

---

## Getting Help

If you need assistance:

1. **Check AI Chat**: Ask the assistant for guidance
2. **Review Logs**: Check scan reports for details
3. **Consult Documentation**: README and this guide
4. **Community**: GitHub discussions and issues

Remember: This tool assists with security monitoring but doesn't replace comprehensive security practices and human judgment.
