#!/usr/bin/env python3
"""
CLI Interface for AI Security Assistant
Run security scans from command line
"""
import argparse
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanners.log_scanner import LogScanner
from scanners.network_analyzer import NetworkAnalyzer
from scanners.file_scanner import FileScanner
from scanners.registry_scanner import RegistryScanner
from ai.ollama_client import OllamaClient, SecurityAI
from utils.config_manager import ConfigManager


def scan_logs(args):
    """Scan log files"""
    scanner = LogScanner()
    
    if args.file:
        results = scanner.scan_file(args.file)
        report = scanner.generate_report(results)
    elif args.directory:
        results = scanner.scan_directory(args.directory)
        report = scanner.generate_report(results)
    else:
        # Use configured paths
        config = ConfigManager()
        paths = config.get_log_paths()
        if not paths:
            print("No log paths configured. Use --file or --directory option.")
            return 1
        
        results = {}
        for path in paths:
            if os.path.isfile(path):
                findings = scanner.scan_file(path)
                if findings:
                    results[path] = findings
            elif os.path.isdir(path):
                dir_results = scanner.scan_directory(path)
                results.update(dir_results)
        
        report = scanner.generate_report(results)
    
    print(report)
    
    if args.ai_analysis:
        analyze_with_ai("log", report, args)
    
    return 0


def scan_network(args):
    """Scan network connections"""
    analyzer = NetworkAnalyzer()
    report = analyzer.generate_report()
    print(report)
    
    if args.ai_analysis:
        analyze_with_ai("network", report, args)
    
    return 0


def scan_file(args):
    """Scan a file"""
    scanner = FileScanner()
    
    if not args.file:
        print("Error: --file argument required")
        return 1
    
    results = scanner.scan_file_content(args.file)
    report = scanner.generate_report(results)
    print(report)
    
    if args.ai_analysis:
        analyze_with_ai("file", report, args)
    
    return 0


def scan_registry(args):
    """Scan Windows registry"""
    scanner = RegistryScanner()
    
    if not scanner.available:
        print("Registry scanning is only available on Windows.")
        return 1
    
    report = scanner.generate_report()
    print(report)
    
    if args.ai_analysis:
        analyze_with_ai("registry", report, args)
    
    return 0


def analyze_with_ai(scan_type, results, args):
    """Analyze results with AI"""
    config = ConfigManager()
    
    print("\n" + "=" * 60)
    print("AI ANALYSIS")
    print("=" * 60)
    
    client = OllamaClient(config.get_ollama_url())
    
    if not client.is_available():
        print("Error: Ollama is not available. Please start Ollama first.")
        return
    
    ai = SecurityAI(client, config.get_ai_model())
    analysis = ai.analyze_scan_results(scan_type, results)
    
    print(analysis)
    print("=" * 60)


def interactive_chat(args):
    """Start interactive chat with AI"""
    config = ConfigManager()
    
    client = OllamaClient(config.get_ollama_url())
    
    if not client.is_available():
        print("Error: Ollama is not available. Please start Ollama first.")
        return 1
    
    ai = SecurityAI(client, config.get_ai_model())
    
    print("=" * 60)
    print("AI Security Assistant - Interactive Chat")
    print("=" * 60)
    print("Type 'exit' or 'quit' to end the session")
    print()
    
    while True:
        try:
            user_input = input("You: ").strip()
            
            if user_input.lower() in ['exit', 'quit']:
                print("Goodbye!")
                break
            
            if not user_input:
                continue
            
            response = ai.chat_conversation(user_input)
            print(f"\nAI Assistant: {response}\n")
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {str(e)}")
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="AI Security Assistant - Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan-logs --file /var/log/auth.log
  %(prog)s scan-network --ai-analysis
  %(prog)s scan-file --file suspicious.exe
  %(prog)s scan-registry
  %(prog)s chat
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan logs command
    logs_parser = subparsers.add_parser('scan-logs', help='Scan log files')
    logs_parser.add_argument('--file', help='Scan a specific log file')
    logs_parser.add_argument('--directory', help='Scan all logs in a directory')
    logs_parser.add_argument('--ai-analysis', action='store_true', 
                            help='Analyze results with AI')
    
    # Scan network command
    network_parser = subparsers.add_parser('scan-network', help='Analyze network connections')
    network_parser.add_argument('--ai-analysis', action='store_true',
                               help='Analyze results with AI')
    
    # Scan file command
    file_parser = subparsers.add_parser('scan-file', help='Scan a file for threats')
    file_parser.add_argument('--file', required=True, help='File to scan')
    file_parser.add_argument('--ai-analysis', action='store_true',
                            help='Analyze results with AI')
    
    # Scan registry command
    registry_parser = subparsers.add_parser('scan-registry', 
                                           help='Scan Windows registry (Windows only)')
    registry_parser.add_argument('--ai-analysis', action='store_true',
                                help='Analyze results with AI')
    
    # Chat command
    chat_parser = subparsers.add_parser('chat', help='Interactive chat with AI assistant')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    if args.command == 'scan-logs':
        return scan_logs(args)
    elif args.command == 'scan-network':
        return scan_network(args)
    elif args.command == 'scan-file':
        return scan_file(args)
    elif args.command == 'scan-registry':
        return scan_registry(args)
    elif args.command == 'chat':
        return interactive_chat(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
