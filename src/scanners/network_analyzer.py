"""
Network Traffic Analyzer Module
Analyzes network connections and traffic patterns for security threats
"""
import psutil
import socket
from typing import List, Dict
from datetime import datetime


class NetworkAnalyzer:
    """Analyzer for network connections and traffic patterns"""
    
    # Known suspicious ports
    SUSPICIOUS_PORTS = {
        31337: "Back Orifice Trojan",
        12345: "NetBus Trojan",
        1080: "SOCKS Proxy (Potential)",
        3389: "RDP (Monitor for brute force)",
        4444: "Metasploit Default",
        5900: "VNC (Monitor for unauthorized)",
        6667: "IRC (Potential C&C)",
        8080: "HTTP Proxy (Monitor)",
    }
    
    def __init__(self):
        self.connections = []
        
    def get_active_connections(self) -> List[Dict]:
        """
        Get all active network connections
        
        Returns:
            List of connection details
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connection_info = {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid,
                    }
                    
                    # Get process name
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            connection_info['process'] = process.name()
                        else:
                            connection_info['process'] = "Unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        connection_info['process'] = "Unknown"
                    
                    connections.append(connection_info)
                    
        except (psutil.AccessDenied, PermissionError):
            connections.append({"error": "Permission denied. Run as administrator for full access."})
            
        return connections
    
    def analyze_connections(self) -> List[Dict]:
        """
        Analyze active connections for suspicious activity
        
        Returns:
            List of suspicious findings
        """
        findings = []
        connections = self.get_active_connections()
        
        for conn in connections:
            if "error" in conn:
                findings.append(conn)
                continue
                
            # Check for suspicious ports
            if conn.get('remote_addr') and conn['remote_addr'] != "N/A":
                try:
                    remote_port = int(conn['remote_addr'].split(':')[1])
                    if remote_port in self.SUSPICIOUS_PORTS:
                        findings.append({
                            'type': 'Suspicious Port',
                            'description': self.SUSPICIOUS_PORTS[remote_port],
                            'port': remote_port,
                            'connection': conn,
                            'severity': 'HIGH'
                        })
                except (ValueError, IndexError):
                    pass
            
            # Check for unusual local ports
            if conn.get('local_addr') and conn['local_addr'] != "N/A":
                try:
                    local_port = int(conn['local_addr'].split(':')[1])
                    if local_port in self.SUSPICIOUS_PORTS:
                        findings.append({
                            'type': 'Suspicious Local Port',
                            'description': f"Local port {local_port} - {self.SUSPICIOUS_PORTS[local_port]}",
                            'port': local_port,
                            'connection': conn,
                            'severity': 'MEDIUM'
                        })
                except (ValueError, IndexError):
                    pass
                    
        return findings
    
    def get_network_stats(self) -> Dict:
        """
        Get network interface statistics
        
        Returns:
            Dictionary with network statistics
        """
        stats = {}
        
        try:
            net_io = psutil.net_io_counters()
            stats = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout,
            }
        except Exception as e:
            stats['error'] = f"Error getting network stats: {str(e)}"
            
        return stats
    
    def check_listening_ports(self) -> List[Dict]:
        """
        Check all listening ports on the system
        
        Returns:
            List of listening ports with details
        """
        listening = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port if conn.laddr else "N/A",
                        'address': conn.laddr.ip if conn.laddr else "N/A",
                        'pid': conn.pid,
                    }
                    
                    # Get process name
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            port_info['process'] = process.name()
                        else:
                            port_info['process'] = "Unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        port_info['process'] = "Unknown"
                    
                    # Check if suspicious
                    if port_info['port'] in self.SUSPICIOUS_PORTS:
                        port_info['warning'] = self.SUSPICIOUS_PORTS[port_info['port']]
                        port_info['severity'] = 'HIGH'
                    
                    listening.append(port_info)
                    
        except (psutil.AccessDenied, PermissionError):
            listening.append({"error": "Permission denied. Run as administrator for full access."})
            
        return listening
    
    def generate_report(self) -> str:
        """Generate a comprehensive network analysis report"""
        report = []
        report.append("=" * 60)
        report.append("NETWORK ANALYSIS REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        # Active connections
        connections = self.get_active_connections()
        report.append(f"\nActive Connections: {len([c for c in connections if 'error' not in c])}")
        
        # Suspicious findings
        findings = self.analyze_connections()
        suspicious_count = len([f for f in findings if 'severity' in f])
        report.append(f"Suspicious Findings: {suspicious_count}")
        
        if suspicious_count > 0:
            report.append("\nSUSPICIOUS ACTIVITIES:")
            for finding in findings:
                if 'severity' in finding:
                    report.append(f"  [{finding['severity']}] {finding['type']}: {finding['description']}")
                    report.append(f"    Port: {finding['port']}")
                    if 'connection' in finding and 'process' in finding['connection']:
                        report.append(f"    Process: {finding['connection']['process']}")
        
        # Listening ports
        listening = self.check_listening_ports()
        report.append(f"\nListening Ports: {len([p for p in listening if 'error' not in p])}")
        
        suspicious_ports = [p for p in listening if 'warning' in p]
        if suspicious_ports:
            report.append("\nSUSPICIOUS LISTENING PORTS:")
            for port in suspicious_ports:
                report.append(f"  Port {port['port']}: {port['warning']}")
                report.append(f"    Process: {port['process']}")
        
        # Network stats
        stats = self.get_network_stats()
        if 'error' not in stats:
            report.append("\nNETWORK STATISTICS:")
            report.append(f"  Bytes Sent: {stats['bytes_sent']:,}")
            report.append(f"  Bytes Received: {stats['bytes_recv']:,}")
            report.append(f"  Packets Sent: {stats['packets_sent']:,}")
            report.append(f"  Packets Received: {stats['packets_recv']:,}")
            if stats['errin'] > 0 or stats['errout'] > 0:
                report.append(f"  Errors: In={stats['errin']}, Out={stats['errout']}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
