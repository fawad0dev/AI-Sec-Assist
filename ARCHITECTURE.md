# Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI Security Assistant                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        User Interfaces                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────────┐              ┌──────────────────┐        │
│  │   GUI (Tkinter)  │              │   CLI (Argparse) │        │
│  │  main_gui.py     │              │   cli.py         │        │
│  │                  │              │                  │        │
│  │ • Chat Tab       │              │ • scan-logs      │        │
│  │ • Scans Tab      │              │ • scan-network   │        │
│  │ • Settings Tab   │              │ • scan-file      │        │
│  └──────────────────┘              │ • scan-registry  │        │
│                                     │ • chat           │        │
│                                     └──────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Core Components                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Configuration Manager                       │   │
│  │              (config_manager.py)                        │   │
│  │                                                          │   │
│  │  • Load/Save Settings                                   │   │
│  │  • Log Paths Management                                 │   │
│  │  • AI Model Configuration                               │   │
│  │  • Persistent Storage (config.json)                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
┌──────────────────────────┐  ┌──────────────────────────┐
│   Security Scanners      │  │     AI Integration       │
├──────────────────────────┤  ├──────────────────────────┤
│                          │  │                          │
│ ┌──────────────────────┐ │  │ ┌──────────────────────┐ │
│ │  Log Scanner         │ │  │ │  Ollama Client       │ │
│ │  log_scanner.py      │ │  │ │  ollama_client.py    │ │
│ │                      │ │  │ │                      │ │
│ │ • Pattern Matching   │ │  │ │ • API Integration    │ │
│ │ • Threat Detection   │ │  │ │ • Model Selection    │ │
│ │ • Severity Rating    │ │  │ │ • Generate/Chat      │ │
│ └──────────────────────┘ │  │ └──────────────────────┘ │
│                          │  │                          │
│ ┌──────────────────────┐ │  │ ┌──────────────────────┐ │
│ │  Network Analyzer    │ │  │ │  Security AI         │ │
│ │  network_analyzer.py │ │  │ │  ollama_client.py    │ │
│ │                      │ │  │ │                      │ │
│ │ • Connection Monitor │ │  │ │ • Scan Analysis      │ │
│ │ • Port Detection     │ │  │ │ • Q&A System         │ │
│ │ • Process Tracking   │ │  │ │ • Remediation Guide  │ │
│ └──────────────────────┘ │  │ │ • Non-hallucination  │ │
│                          │  │ └──────────────────────┘ │
│ ┌──────────────────────┐ │  │                          │
│ │  File Scanner        │ │  └──────────────────────────┘
│ │  file_scanner.py     │ │               │
│ │                      │ │               │
│ │ • Hash Calculation   │ │               ▼
│ │ • String Extraction  │ │  ┌──────────────────────────┐
│ │ • Malware Detection  │ │  │    Ollama Service        │
│ └──────────────────────┘ │  │    (External)            │
│                          │  │                          │
│ ┌──────────────────────┐ │  │ • Local AI Models        │
│ │  Registry Scanner    │ │  │ • llama2, mistral, etc   │
│ │  registry_scanner.py │ │  │ • HTTP API (port 11434)  │
│ │  (Windows Only)      │ │  │ • Privacy-focused        │
│ │                      │ │  └──────────────────────────┘
│ │ • Autorun Detection  │ │
│ │ • Service Monitor    │ │
│ │ • Registry Analysis  │ │
│ └──────────────────────┘ │
│                          │
└──────────────────────────┘
```

## Data Flow

### Scanning Flow

```
User Action (GUI/CLI)
        │
        ▼
Scanner Module (log/network/file/registry)
        │
        ▼
Data Collection & Pattern Matching
        │
        ▼
Findings with Severity Classification
        │
        ▼
Report Generation
        │
        ├──────────────┐
        ▼              ▼
    Display to    AI Analysis (Optional)
      User              │
                        ▼
                 Security AI System
                        │
                        ▼
                 Ollama API Call
                        │
                        ▼
                  AI Response
                        │
                        ▼
               Enhanced Report with
               Recommendations
                        │
                        ▼
                  Display to User
```

### Chat Flow

```
User Question
      │
      ▼
Security AI System
      │
      ├─── Add to Conversation History
      │
      ▼
System Prompt + User Message
      │
      ▼
Ollama Chat API
      │
      ▼
AI Response (Temperature 0.1)
      │
      ├─── Add to Conversation History
      │
      ▼
Display to User
```

## Module Dependencies

```
main.py
  └── gui/main_gui.py
       ├── scanners/
       │   ├── log_scanner.py
       │   ├── network_analyzer.py
       │   ├── file_scanner.py
       │   └── registry_scanner.py
       ├── ai/
       │   └── ollama_client.py
       │       ├── OllamaClient
       │       └── SecurityAI
       └── utils/
           └── config_manager.py

cli.py
  ├── scanners/ (same as above)
  ├── ai/ (same as above)
  └── utils/config_manager.py
```

## External Dependencies

### Python Libraries
- `customtkinter` - Modern GUI framework
- `requests` - HTTP client for Ollama API
- `psutil` - System monitoring (network, processes)
- `scapy` - Network packet analysis (optional)
- `pefile` - PE file analysis (optional)
- `yara-python` - Pattern matching (optional)

### External Services
- **Ollama** - Local AI model inference
  - Required for AI features
  - Optional for basic scanning
  - Default URL: http://localhost:11434

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────┐
│         User Input Validation           │
└─────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│      Permission & Access Control        │
└─────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│        Secure Scanning Operations       │
│  • Read-only by default                 │
│  • No automatic remediation             │
│  • User confirmation required           │
└─────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│         AI Safety Measures              │
│  • Low temperature (0.1)                │
│  • Strict system prompts                │
│  • Fact-based responses                 │
│  • No speculative analysis              │
└─────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│         Privacy Protection              │
│  • 100% local processing                │
│  • No cloud connectivity                │
│  • No data collection                   │
└─────────────────────────────────────────┘
```

## Scalability Considerations

### Resource Management
- **Log Scanning**: Configurable line limits (default 1000)
- **String Extraction**: Limited to first 500 strings
- **Network Monitoring**: Efficient connection enumeration
- **Memory Usage**: Chunked file reading
- **Model Selection**: Support for lightweight models (mistral, phi)

### Concurrent Operations
- **GUI**: Threaded scanning (non-blocking UI)
- **CLI**: Sequential processing
- **AI Calls**: Single request with timeout (120s)

## Extensibility Points

### Adding New Scanners
1. Create new module in `src/scanners/`
2. Implement scanning logic
3. Add to GUI and CLI interfaces
4. Update documentation

### Adding AI Features
1. Extend `SecurityAI` class
2. Add new prompts/methods
3. Integrate with existing UI
4. Test with different models

### Custom Detection Patterns
1. Edit scanner modules
2. Add to pattern lists
3. Update severity classifications
4. Test with sample data

## Performance Characteristics

### Typical Operation Times
- **Log Scan**: 1-5 seconds (1000 lines)
- **Network Scan**: 2-3 seconds
- **File Scan**: 1-2 seconds (small file)
- **Registry Scan**: 3-5 seconds (Windows)
- **AI Analysis**: 10-60 seconds (model dependent)

### Resource Usage
- **Memory**: 100-500 MB (varies with model)
- **CPU**: Moderate (spikes during AI inference)
- **Disk**: Minimal (config.json only)
- **Network**: None (except localhost for Ollama)

## Deployment Options

### Standalone Desktop
- Install Python dependencies
- Run Ollama locally
- Use GUI interface

### Server Environment
- Use CLI interface
- Schedule with cron
- Log to file
- Optional: Remote Ollama server

### Container (Future)
- Docker container with dependencies
- Pre-configured Ollama
- Volume mounts for logs
- Web-based GUI option

---

This architecture provides a solid foundation for security monitoring while maintaining modularity, extensibility, and user privacy.
