"""
Log File Scanner Module
Scans log files for suspicious activities and security threats
"""
import os
import re
from typing import List, Dict, Tuple
from datetime import datetime


class LogScanner:
    """Scanner for analyzing log files for security threats"""
    
    # Common suspicious patterns in logs
    SUSPICIOUS_PATTERNS = [
        (r'failed.*login', 'Failed Login Attempt'),
        (r'authentication.*fail', 'Authentication Failure'),
        (r'unauthorized.*access', 'Unauthorized Access'),
        (r'sql.*injection', 'Potential SQL Injection'),
        (r'xss|cross.*site.*script', 'Potential XSS Attack'),
        (r'brute.*force', 'Brute Force Attack'),
        (r'denial.*service|dos.*attack', 'DoS Attack'),
        (r'malware|virus|trojan', 'Malware Detection'),
        (r'privilege.*escalation', 'Privilege Escalation'),
        (r'port.*scan', 'Port Scanning'),
        (r'buffer.*overflow', 'Buffer Overflow'),
        (r'directory.*traversal', 'Directory Traversal'),
        (r'command.*injection', 'Command Injection'),
        (r'suspicious.*activity', 'Suspicious Activity'),
        (r'error.*500|internal.*error', 'Server Error'),
        (r'access.*denied', 'Access Denied'),
    ]
    
    def __init__(self):
        self.results = []
        
    def scan_file(self, filepath: str, max_lines: int = 1000) -> List[Dict]:
        """
        Scan a single log file for suspicious patterns
        
        Args:
            filepath: Path to the log file
            max_lines: Maximum number of lines to scan (to prevent memory issues)
            
        Returns:
            List of findings with line numbers and descriptions
        """
        findings = []
        
        if not os.path.exists(filepath):
            return [{"error": f"File not found: {filepath}"}]
            
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        findings.append({
                            "warning": f"Stopped at {max_lines} lines. File may contain more entries."
                        })
                        break
                        
                    for pattern, description in self.SUSPICIOUS_PATTERNS:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append({
                                "line": line_num,
                                "description": description,
                                "content": line.strip()[:200],  # Limit line length
                                "severity": self._assess_severity(description)
                            })
                            break  # Only report first match per line
                            
        except Exception as e:
            findings.append({"error": f"Error reading file: {str(e)}"})
            
        return findings
    
    def scan_directory(self, dirpath: str, extensions: List[str] = None) -> Dict:
        """
        Scan all log files in a directory
        
        Args:
            dirpath: Path to directory
            extensions: List of file extensions to scan (default: .log, .txt)
            
        Returns:
            Dictionary with results per file
        """
        if extensions is None:
            extensions = ['.log', '.txt', '.out']
            
        results = {}
        
        if not os.path.exists(dirpath):
            return {"error": f"Directory not found: {dirpath}"}
            
        try:
            for root, dirs, files in os.walk(dirpath):
                for file in files:
                    if any(file.endswith(ext) for ext in extensions):
                        filepath = os.path.join(root, file)
                        findings = self.scan_file(filepath)
                        if findings:
                            results[filepath] = findings
                            
        except Exception as e:
            results["error"] = f"Error scanning directory: {str(e)}"
            
        return results
    
    def _assess_severity(self, description: str) -> str:
        """Assess the severity level of a finding"""
        high_severity = ['SQL Injection', 'XSS Attack', 'Command Injection', 
                        'Malware', 'Privilege Escalation', 'Buffer Overflow']
        medium_severity = ['Brute Force', 'DoS Attack', 'Port Scanning', 
                          'Unauthorized Access']
        
        for threat in high_severity:
            if threat.lower() in description.lower():
                return "HIGH"
                
        for threat in medium_severity:
            if threat.lower() in description.lower():
                return "MEDIUM"
                
        return "LOW"
    
    def generate_report(self, findings: Dict) -> str:
        """Generate a human-readable report from findings"""
        report = []
        report.append("=" * 60)
        report.append("LOG SCAN REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        if isinstance(findings, dict) and "error" in findings:
            report.append(f"\nERROR: {findings['error']}")
            return "\n".join(report)
        
        total_findings = 0
        high_severity_count = 0
        
        if isinstance(findings, list):
            # Single file results
            total_findings = len([f for f in findings if "line" in f])
            high_severity_count = len([f for f in findings if f.get("severity") == "HIGH"])
            
            report.append(f"\nTotal Findings: {total_findings}")
            report.append(f"High Severity: {high_severity_count}\n")
            
            for finding in findings:
                if "line" in finding:
                    report.append(f"Line {finding['line']}: [{finding['severity']}] {finding['description']}")
                    report.append(f"  Content: {finding['content'][:100]}")
                    
        elif isinstance(findings, dict):
            # Multiple files results
            for filepath, file_findings in findings.items():
                if filepath == "error":
                    continue
                    
                file_total = len([f for f in file_findings if "line" in f])
                file_high = len([f for f in file_findings if f.get("severity") == "HIGH"])
                
                total_findings += file_total
                high_severity_count += file_high
                
                report.append(f"\nFile: {filepath}")
                report.append(f"Findings: {file_total} (High: {file_high})")
                
                for finding in file_findings[:5]:  # Show first 5 per file
                    if "line" in finding:
                        report.append(f"  Line {finding['line']}: [{finding['severity']}] {finding['description']}")
                        
        report.append("\n" + "=" * 60)
        report.append(f"SUMMARY: {total_findings} total findings, {high_severity_count} high severity")
        report.append("=" * 60)
        
        return "\n".join(report)
