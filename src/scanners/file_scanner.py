"""
File Scanner Module
Scans files for suspicious content, strings, and hashes
"""
import os
import hashlib
import re
from typing import Dict, List, Tuple
from datetime import datetime


class FileScanner:
    """Scanner for analyzing files for suspicious content"""
    
    # Suspicious string patterns
    SUSPICIOUS_STRINGS = [
        (r'eval\s*\(', 'Dangerous eval() function'),
        (r'exec\s*\(', 'Dangerous exec() function'),
        (r'system\s*\(', 'System command execution'),
        (r'shell_exec', 'Shell command execution'),
        (r'passthru', 'Command execution'),
        (r'base64_decode', 'Base64 decoding (potential obfuscation)'),
        (r'<script>', 'Script injection'),
        (r'SELECT.*FROM.*WHERE', 'SQL query (potential injection)'),
        (r'cmd\.exe|powershell\.exe', 'Command line execution'),
        (r'wget|curl.*http', 'Remote file download'),
        (r'nc\s+-l|netcat', 'Network connection tool'),
        (r'chmod\s+777', 'Dangerous permission change'),
        (r'/etc/passwd|/etc/shadow', 'System file access'),
        (r'CREATE\s+USER|DROP\s+TABLE', 'Database manipulation'),
    ]
    
    # Known malware file hashes (example - would be a larger database in production)
    KNOWN_MALWARE_HASHES = {
        # These are example hashes - in production, this would be a comprehensive database
        '44d88612fea8a8f36de82e1278abb02f': 'EICAR test file',
    }
    
    def __init__(self):
        self.results = []
        
    def calculate_file_hash(self, filepath: str, algorithm: str = 'sha256') -> str:
        """
        Calculate file hash
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hash string or error message
        """
        try:
            if algorithm == 'md5':
                hasher = hashlib.md5()
            elif algorithm == 'sha1':
                hasher = hashlib.sha1()
            else:
                hasher = hashlib.sha256()
                
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
                    
            return hasher.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    def check_hash(self, file_hash: str) -> Tuple[bool, str]:
        """
        Check if hash matches known malware
        
        Args:
            file_hash: File hash to check
            
        Returns:
            Tuple of (is_malware, description)
        """
        file_hash_lower = file_hash.lower()
        if file_hash_lower in self.KNOWN_MALWARE_HASHES:
            return True, self.KNOWN_MALWARE_HASHES[file_hash_lower]
        return False, "No match found"
    
    def extract_strings(self, filepath: str, min_length: int = 4, max_strings: int = 1000) -> List[str]:
        """
        Extract readable strings from a file
        
        Args:
            filepath: Path to file
            min_length: Minimum string length
            max_strings: Maximum number of strings to return
            
        Returns:
            List of extracted strings
        """
        strings = []
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            # Extract ASCII strings
            pattern = b'[\x20-\x7E]{%d,}' % min_length
            matches = re.findall(pattern, data)
            
            strings = [match.decode('ascii') for match in matches[:max_strings]]
            
        except Exception as e:
            strings.append(f"Error extracting strings: {str(e)}")
            
        return strings
    
    def scan_file_content(self, filepath: str, check_strings: bool = True) -> Dict:
        """
        Scan file content for suspicious patterns
        
        Args:
            filepath: Path to file
            check_strings: Whether to extract and scan strings
            
        Returns:
            Dictionary with scan results
        """
        results = {
            'filepath': filepath,
            'timestamp': datetime.now().isoformat(),
            'findings': []
        }
        
        if not os.path.exists(filepath):
            results['error'] = "File not found"
            return results
        
        try:
            # Get file info
            stat = os.stat(filepath)
            results['size'] = stat.st_size
            results['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            # Calculate hashes
            results['md5'] = self.calculate_file_hash(filepath, 'md5')
            results['sha256'] = self.calculate_file_hash(filepath, 'sha256')
            
            # Check against known malware hashes
            is_malware, description = self.check_hash(results['md5'])
            if is_malware:
                results['findings'].append({
                    'type': 'Known Malware Hash',
                    'description': description,
                    'severity': 'CRITICAL'
                })
            
            # Extract and scan strings if requested
            if check_strings:
                strings = self.extract_strings(filepath, max_strings=500)
                suspicious_found = []
                
                for string in strings:
                    for pattern, description in self.SUSPICIOUS_STRINGS:
                        if re.search(pattern, string, re.IGNORECASE):
                            suspicious_found.append({
                                'string': string[:100],  # Limit length
                                'pattern': description,
                                'severity': self._assess_string_severity(description)
                            })
                            break
                
                if suspicious_found:
                    results['findings'].extend(suspicious_found[:20])  # Limit findings
                    results['suspicious_strings_count'] = len(suspicious_found)
                    
        except Exception as e:
            results['error'] = f"Error scanning file: {str(e)}"
            
        return results
    
    def scan_directory(self, dirpath: str, extensions: List[str] = None, 
                      recursive: bool = False) -> List[Dict]:
        """
        Scan all files in a directory
        
        Args:
            dirpath: Path to directory
            extensions: List of extensions to scan (None = all files)
            recursive: Whether to scan subdirectories
            
        Returns:
            List of scan results
        """
        results = []
        
        if not os.path.exists(dirpath):
            return [{"error": f"Directory not found: {dirpath}"}]
        
        try:
            if recursive:
                for root, dirs, files in os.walk(dirpath):
                    for file in files:
                        if extensions is None or any(file.endswith(ext) for ext in extensions):
                            filepath = os.path.join(root, file)
                            result = self.scan_file_content(filepath)
                            if result.get('findings'):
                                results.append(result)
            else:
                for file in os.listdir(dirpath):
                    filepath = os.path.join(dirpath, file)
                    if os.path.isfile(filepath):
                        if extensions is None or any(file.endswith(ext) for ext in extensions):
                            result = self.scan_file_content(filepath)
                            if result.get('findings'):
                                results.append(result)
                                
        except Exception as e:
            results.append({"error": f"Error scanning directory: {str(e)}"})
            
        return results
    
    def _assess_string_severity(self, description: str) -> str:
        """Assess severity based on finding description"""
        critical = ['eval()', 'exec()', 'system command']
        high = ['shell', 'command execution', 'base64']
        
        desc_lower = description.lower()
        for term in critical:
            if term in desc_lower:
                return "CRITICAL"
        for term in high:
            if term in desc_lower:
                return "HIGH"
        return "MEDIUM"
    
    def generate_report(self, results: Dict) -> str:
        """Generate a report from scan results"""
        report = []
        report.append("=" * 60)
        report.append("FILE SCAN REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        if isinstance(results, dict):
            results = [results]
        
        for result in results:
            if "error" in result:
                report.append(f"\nERROR: {result['error']}")
                continue
                
            report.append(f"\nFile: {result.get('filepath', 'Unknown')}")
            report.append(f"Size: {result.get('size', 0):,} bytes")
            report.append(f"MD5: {result.get('md5', 'N/A')}")
            report.append(f"SHA256: {result.get('sha256', 'N/A')}")
            
            findings = result.get('findings', [])
            if findings:
                report.append(f"\nFindings: {len(findings)}")
                for finding in findings[:10]:  # Show first 10
                    if 'type' in finding:
                        report.append(f"  [{finding.get('severity', 'UNKNOWN')}] {finding['type']}")
                        report.append(f"    {finding['description']}")
                    elif 'pattern' in finding:
                        report.append(f"  [{finding.get('severity', 'UNKNOWN')}] {finding['pattern']}")
                        report.append(f"    String: {finding.get('string', '')[:80]}")
            else:
                report.append("  No suspicious findings")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
