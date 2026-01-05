#!/usr/bin/env python3
"""
Test scanner modules without GUI
"""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanners.log_scanner import LogScanner
from scanners.network_analyzer import NetworkAnalyzer
from scanners.file_scanner import FileScanner
from scanners.registry_scanner import RegistryScanner


def test_log_scanner():
    """Test log scanner"""
    print("=" * 60)
    print("Testing Log Scanner")
    print("=" * 60)
    
    scanner = LogScanner()
    
    # Create a test log file
    test_log = "/tmp/test_security.log"
    with open(test_log, 'w') as f:
        f.write("2024-01-05 10:00:00 INFO User logged in successfully\n")
        f.write("2024-01-05 10:05:00 ERROR Failed login attempt for user admin\n")
        f.write("2024-01-05 10:06:00 WARN Possible SQL injection attempt detected\n")
        f.write("2024-01-05 10:07:00 ERROR Authentication failure from IP 192.168.1.100\n")
        f.write("2024-01-05 10:10:00 ALERT Malware detected in uploaded file\n")
    
    # Scan the test file
    results = scanner.scan_file(test_log)
    report = scanner.generate_report(results)
    
    print(report)
    
    # Clean up
    os.remove(test_log)
    
    print("\n✓ Log Scanner test completed\n")


def test_network_analyzer():
    """Test network analyzer"""
    print("=" * 60)
    print("Testing Network Analyzer")
    print("=" * 60)
    
    analyzer = NetworkAnalyzer()
    
    # Get active connections
    connections = analyzer.get_active_connections()
    print(f"Active connections found: {len([c for c in connections if 'error' not in c])}")
    
    # Analyze for threats
    findings = analyzer.analyze_connections()
    print(f"Suspicious findings: {len([f for f in findings if 'severity' in f])}")
    
    # Get network stats
    stats = analyzer.get_network_stats()
    if 'error' not in stats:
        print(f"Bytes sent: {stats['bytes_sent']:,}")
        print(f"Bytes received: {stats['bytes_recv']:,}")
    
    print("\n✓ Network Analyzer test completed\n")


def test_file_scanner():
    """Test file scanner"""
    print("=" * 60)
    print("Testing File Scanner")
    print("=" * 60)
    
    scanner = FileScanner()
    
    # Create a test file with suspicious content
    test_file = "/tmp/test_suspicious.txt"
    with open(test_file, 'w') as f:
        f.write("Normal content here\n")
        f.write("eval(base64_decode($encoded_data));\n")
        f.write("system('rm -rf /');\n")
        f.write("SELECT * FROM users WHERE username='admin';\n")
    
    # Scan the file
    results = scanner.scan_file_content(test_file)
    report = scanner.generate_report(results)
    
    print(report)
    
    # Test hash calculation
    md5_hash = scanner.calculate_file_hash(test_file, 'md5')
    sha256_hash = scanner.calculate_file_hash(test_file, 'sha256')
    print(f"\nFile Hashes:")
    print(f"MD5: {md5_hash}")
    print(f"SHA256: {sha256_hash}")
    
    # Clean up
    os.remove(test_file)
    
    print("\n✓ File Scanner test completed\n")


def test_registry_scanner():
    """Test registry scanner"""
    print("=" * 60)
    print("Testing Registry Scanner")
    print("=" * 60)
    
    scanner = RegistryScanner()
    
    if scanner.available:
        print("Registry scanner is available (Windows detected)")
        # Note: Won't actually scan in non-Windows environment
    else:
        print("Registry scanner not available (non-Windows system)")
        print("This is expected on Linux/Mac systems")
    
    print("\n✓ Registry Scanner test completed\n")


def main():
    """Run all tests"""
    print("\n")
    print("=" * 60)
    print("AI Security Assistant - Scanner Module Tests")
    print("=" * 60)
    print("\n")
    
    try:
        test_log_scanner()
        test_network_analyzer()
        test_file_scanner()
        test_registry_scanner()
        
        print("=" * 60)
        print("✓ All scanner tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
