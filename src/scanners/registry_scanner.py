"""
Windows Registry Scanner Module
Scans Windows registry for suspicious entries (Windows only)
"""
import platform
import sys
from typing import List, Dict
from datetime import datetime

# Try to import winreg (Windows only)
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False


class RegistryScanner:
    """Scanner for Windows Registry suspicious entries"""
    
    # Common autorun registry keys
    AUTORUN_KEYS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ] if WINREG_AVAILABLE else []
    
    # Suspicious patterns in registry values
    SUSPICIOUS_PATTERNS = [
        'temp\\',
        'appdata\\roaming',
        'cmd.exe',
        'powershell.exe',
        'wscript.exe',
        'cscript.exe',
        '.vbs',
        '.bat',
        '.ps1',
    ]
    
    def __init__(self):
        self.is_windows = platform.system() == 'Windows'
        self.available = self.is_windows and WINREG_AVAILABLE
        
    def scan_autorun_locations(self) -> List[Dict]:
        """
        Scan common autorun registry locations
        
        Returns:
            List of autorun entries with analysis
        """
        if not self.available:
            return [{"error": "Registry scanning is only available on Windows"}]
        
        findings = []
        
        for hkey, subkey in self.AUTORUN_KEYS:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                
                try:
                    i = 0
                    while True:
                        try:
                            name, value, type_ = winreg.EnumValue(key, i)
                            
                            # Analyze the entry
                            is_suspicious, reasons = self._analyze_entry(name, value)
                            
                            entry = {
                                'location': f"{self._hkey_name(hkey)}\\{subkey}",
                                'name': name,
                                'value': value,
                                'type': type_,
                                'suspicious': is_suspicious,
                            }
                            
                            if is_suspicious:
                                entry['reasons'] = reasons
                                entry['severity'] = 'HIGH' if len(reasons) > 1 else 'MEDIUM'
                            
                            findings.append(entry)
                            i += 1
                            
                        except WindowsError:
                            break
                            
                finally:
                    winreg.CloseKey(key)
                    
            except FileNotFoundError:
                # Key doesn't exist, skip
                pass
            except PermissionError:
                findings.append({
                    "error": f"Permission denied accessing {subkey}. Run as administrator."
                })
            except Exception as e:
                findings.append({
                    "error": f"Error reading {subkey}: {str(e)}"
                })
        
        return findings
    
    def scan_services(self) -> List[Dict]:
        """
        Scan Windows services registry
        
        Returns:
            List of service entries
        """
        if not self.available:
            return [{"error": "Registry scanning is only available on Windows"}]
        
        findings = []
        services_key = r"SYSTEM\CurrentControlSet\Services"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, services_key, 0, winreg.KEY_READ)
            
            try:
                i = 0
                while i < 50:  # Limit to first 50 services to avoid too much data
                    try:
                        service_name = winreg.EnumKey(key, i)
                        
                        # Try to read service details
                        try:
                            service_key = winreg.OpenKey(key, service_name, 0, winreg.KEY_READ)
                            
                            try:
                                image_path, _ = winreg.QueryValueEx(service_key, "ImagePath")
                                
                                is_suspicious, reasons = self._analyze_entry(service_name, image_path)
                                
                                if is_suspicious:
                                    findings.append({
                                        'service': service_name,
                                        'path': image_path,
                                        'suspicious': True,
                                        'reasons': reasons,
                                        'severity': 'HIGH'
                                    })
                                    
                            finally:
                                winreg.CloseKey(service_key)
                                
                        except FileNotFoundError:
                            pass
                        except PermissionError:
                            pass
                            
                        i += 1
                        
                    except WindowsError:
                        break
                        
            finally:
                winreg.CloseKey(key)
                
        except Exception as e:
            findings.append({"error": f"Error scanning services: {str(e)}"})
        
        return findings
    
    def _analyze_entry(self, name: str, value: str) -> tuple:
        """
        Analyze a registry entry for suspicious patterns
        
        Args:
            name: Entry name
            value: Entry value
            
        Returns:
            Tuple of (is_suspicious, list of reasons)
        """
        reasons = []
        
        value_lower = str(value).lower()
        name_lower = str(name).lower()
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in value_lower or pattern in name_lower:
                reasons.append(f"Contains suspicious pattern: {pattern}")
        
        # Check for hidden/temp locations
        if 'temp' in value_lower or 'tmp' in value_lower:
            reasons.append("Located in temporary directory")
        
        # Check for obfuscated or encoded content
        if len(value) > 500:
            reasons.append("Unusually long value (potential obfuscation)")
        
        return len(reasons) > 0, reasons
    
    def _hkey_name(self, hkey) -> str:
        """Convert HKEY constant to readable name"""
        if not WINREG_AVAILABLE:
            return "UNKNOWN"
            
        if hkey == winreg.HKEY_CURRENT_USER:
            return "HKEY_CURRENT_USER"
        elif hkey == winreg.HKEY_LOCAL_MACHINE:
            return "HKEY_LOCAL_MACHINE"
        elif hkey == winreg.HKEY_CLASSES_ROOT:
            return "HKEY_CLASSES_ROOT"
        else:
            return "HKEY_UNKNOWN"
    
    def generate_report(self) -> str:
        """Generate a comprehensive registry scan report"""
        report = []
        report.append("=" * 60)
        report.append("WINDOWS REGISTRY SCAN REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        if not self.available:
            report.append("\nRegistry scanning is only available on Windows systems.")
            report.append("Current system: " + platform.system())
            return "\n".join(report)
        
        # Scan autorun locations
        report.append("\n=== AUTORUN LOCATIONS ===")
        autorun = self.scan_autorun_locations()
        
        suspicious_autorun = [e for e in autorun if e.get('suspicious', False)]
        report.append(f"Total entries: {len([e for e in autorun if 'name' in e])}")
        report.append(f"Suspicious entries: {len(suspicious_autorun)}")
        
        if suspicious_autorun:
            report.append("\nSUSPICIOUS AUTORUN ENTRIES:")
            for entry in suspicious_autorun[:10]:  # Show first 10
                report.append(f"\n  [{entry.get('severity', 'UNKNOWN')}] {entry.get('name', 'Unknown')}")
                report.append(f"    Location: {entry.get('location', 'Unknown')}")
                report.append(f"    Value: {str(entry.get('value', ''))[:100]}")
                if 'reasons' in entry:
                    for reason in entry['reasons']:
                        report.append(f"    - {reason}")
        
        # Scan services
        report.append("\n\n=== SERVICES ===")
        services = self.scan_services()
        
        suspicious_services = [s for s in services if s.get('suspicious', False)]
        report.append(f"Suspicious services: {len(suspicious_services)}")
        
        if suspicious_services:
            report.append("\nSUSPICIOUS SERVICES:")
            for service in suspicious_services:
                report.append(f"\n  [{service.get('severity', 'UNKNOWN')}] {service.get('service', 'Unknown')}")
                report.append(f"    Path: {service.get('path', 'Unknown')}")
                if 'reasons' in service:
                    for reason in service['reasons']:
                        report.append(f"    - {reason}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
