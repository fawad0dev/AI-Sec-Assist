# AI Security Assistant 🛡️

An intelligent AI-powered security assistant that helps protect your system through automated security scanning and analysis. This application combines multiple security scanning capabilities with local AI models (via Ollama) to provide comprehensive security monitoring and actionable insights.

## Features ✨

### 🔍 Security Scanning Capabilities

1. **Log File Scanner**
   - Scans log files for suspicious patterns and security threats
   - Detects failed login attempts, authentication failures, SQL injection attempts
   - Identifies XSS attacks, brute force attempts, malware signatures
   - Configurable log file paths and directories
   - Severity-based threat classification (HIGH, MEDIUM, LOW)

2. **Network Traffic Analyzer**
   - Monitors active network connections in real-time
   - Detects suspicious ports and connections
   - Identifies known malicious ports (Back Orifice, NetBus, Metasploit, etc.)
   - Tracks listening ports and associated processes
   - Network statistics monitoring

3. **File Scanner**
   - Calculates file hashes (MD5, SHA256)
   - Checks hashes against known malware databases
   - Extracts and analyzes strings from binary files
   - Detects suspicious code patterns (eval, exec, shell commands)
   - Scans files and directories for threats
   - Identifies potential code injection vulnerabilities

4. **Windows Registry Scanner** (Windows Only)
   - Scans common autorun registry locations
   - Monitors Windows services for suspicious entries
   - Detects potentially malicious registry modifications
   - Identifies entries in temporary directories
   - Flags obfuscated or suspicious registry values

### 🤖 AI-Powered Analysis

- **Local AI Integration** via Ollama (privacy-focused, no cloud dependency)
- **Non-Hallucinating Responses** - Low temperature settings ensure factual, grounded responses
- **Security-Focused Prompts** - Specialized system prompts for accurate security analysis
- **Conversational Interface** - Chat with the AI about security concerns
- **Automated Scan Analysis** - AI analyzes scan results and provides remediation steps
- **Context-Aware** - Maintains conversation history for better understanding

### 🖥️ GUI Interface

- **Modern Dark Theme** using CustomTkinter
- **Tabbed Interface**:
  - **Chat Tab**: Interactive AI security assistant
  - **Security Scans Tab**: Execute and view security scans
  - **Settings Tab**: Configure log paths, AI model, and Ollama connection
- **Real-time Results** display with threaded scanning (non-blocking UI)
- **Configurable Settings** with persistent storage

## Installation 📦

### Prerequisites

1. **Python 3.8+** required
2. **Ollama** - Install from [ollama.ai](https://ollama.ai/)
   ```bash
   # Start Ollama service
   ollama serve
   
   # Pull a model (recommended: llama2 for general use, mistral for low RAM)
   ollama pull llama2
   # or for low RAM systems:
   ollama pull mistral
   ```

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/fawad0dev/AI-Sec-Assist.git
   cd AI-Sec-Assist
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage 🚀

### Quick Start

1. **Launch the application**: `python main.py`
2. **Configure Settings**:
   - Go to "Settings" tab
   - Verify Ollama connection status
   - Select your preferred AI model
   - Add log file paths to monitor
3. **Run Security Scans**:
   - Go to "Security Scans" tab
   - Click any scan button (Log Files, Network, File, Registry)
   - View results in the right panel
4. **AI Analysis**:
   - After running a scan, click "Analyze Results with AI"
   - Get detailed security assessment and remediation steps
5. **Chat with AI**:
   - Go to "Chat" tab
   - Ask security questions or request analysis

### Example Use Cases

#### 1. Monitoring System Logs
```
Settings → Add Log Path → Select /var/log/auth.log
Security Scans → Scan Log Files
Review suspicious activities → Analyze with AI
```

#### 2. Network Security Check
```
Security Scans → Analyze Network
Review active connections and suspicious ports
Analyze with AI for threat assessment
```

#### 3. File Integrity Check
```
Security Scans → Scan File → Select suspicious file
View hash, strings, and security findings
Analyze with AI for malware indicators
```

#### 4. Registry Monitoring (Windows)
```
Security Scans → Scan Registry
Review autorun locations and services
Identify persistence mechanisms
```

### Chat Examples

- "What are the most critical security threats I should address?"
- "How do I remediate a brute force attack?"
- "Explain the suspicious activity found in my logs"
- "What ports should I be monitoring?"
- "How can I prevent SQL injection attacks?"

## Configuration ⚙️

Configuration is stored in `config.json` (auto-created on first run):

```json
{
  "ai": {
    "model": "llama2",
    "ollama_url": "http://localhost:11434",
    "temperature": 0.1
  },
  "scan": {
    "log_paths": [],
    "max_log_lines": 1000,
    "scan_file_strings": true,
    "network_scan_enabled": true,
    "registry_scan_enabled": true
  },
  "ui": {
    "theme": "dark",
    "window_width": 1200,
    "window_height": 800
  }
}
```

## AI Model Selection 🧠

### Recommended Models

1. **llama2** (Default)
   - Good balance of accuracy and performance
   - RAM: ~4-8GB
   - Best for: General security analysis

2. **mistral**
   - Faster, more efficient
   - RAM: ~4GB
   - Best for: Low RAM systems, quick responses

3. **codellama**
   - Specialized for code analysis
   - RAM: ~4-8GB
   - Best for: Source code security scanning

4. **phi**
   - Smallest model
   - RAM: ~2GB
   - Best for: Very low RAM systems (may be less accurate)

### Temperature Settings

The application uses **temperature 0.1** by default to minimize hallucinations:
- **0.0-0.2**: More deterministic, factual (security-appropriate)
- **0.3-0.7**: Balanced creativity and accuracy
- **0.8-1.0**: More creative but may hallucinate

For security purposes, we maintain low temperature to ensure responses are grounded in the actual scan data.

## Security Features 🔒

### Non-Hallucination Safeguards

1. **Low Temperature Settings** (0.1) - Ensures factual, deterministic responses
2. **Strict System Prompts** - AI instructed to only analyze provided data
3. **Explicit Instructions** - AI told to say "I don't know" rather than speculate
4. **Context Limiting** - Truncates large inputs to prevent confusion
5. **Fact-Based Analysis** - All responses must reference actual scan data

### Privacy & Local Processing

- **100% Local** - No data sent to cloud services
- **Ollama Integration** - All AI processing happens on your machine
- **Offline Capable** - Works without internet connection
- **No Data Collection** - Your security data stays private

## Permissions 🔐

Some scans require elevated privileges:

- **Linux/Mac**: Run as root or with sudo for full network/file access
  ```bash
  sudo python main.py
  ```

- **Windows**: Run as Administrator for registry and full network access
  - Right-click → "Run as Administrator"

## Troubleshooting 🔧

### Ollama Not Connected
```
Error: Ollama is not available
Solution: 
1. Ensure Ollama is installed
2. Start Ollama service: ollama serve
3. Check URL in Settings (default: http://localhost:11434)
```

### Permission Denied Errors
```
Error: Permission denied
Solution: Run application with administrator/root privileges
```

### No Models Found
```
Error: No models found
Solution: Pull a model first: ollama pull llama2
```

### High Memory Usage
```
Issue: System running out of RAM
Solution: 
1. Switch to smaller model (mistral or phi)
2. Close other applications
3. Reduce scan scope (fewer log files)
```

## Architecture 📐

```
AI-Sec-Assist/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── config.json            # User configuration (auto-generated)
└── src/
    ├── scanners/          # Security scanning modules
    │   ├── log_scanner.py
    │   ├── network_analyzer.py
    │   ├── file_scanner.py
    │   └── registry_scanner.py
    ├── ai/                # AI integration
    │   └── ollama_client.py
    ├── gui/               # GUI interface
    │   └── main_gui.py
    └── utils/             # Utilities
        └── config_manager.py
```

## Contributing 🤝

Contributions are welcome! Areas for improvement:
- Additional security scanning modules
- More threat detection patterns
- Enhanced AI prompts
- Performance optimizations
- Cross-platform compatibility

## License 📄

This project is open source. Please ensure you comply with all applicable security and privacy regulations when using this tool.

## Disclaimer ⚠️

This tool is for legitimate security monitoring and research purposes only. Users are responsible for:
- Ensuring they have authorization to scan systems
- Complying with local laws and regulations
- Understanding the tool's limitations
- Not relying solely on AI analysis for critical security decisions

**Note**: While the AI is designed to minimize hallucinations, always verify critical security findings through additional means.

## Support 💬

For issues, questions, or contributions:
- GitHub Issues: Report bugs or request features
- Discussions: Ask questions or share use cases

## Acknowledgments 🙏

- **Ollama** - Local AI model inference
- **CustomTkinter** - Modern GUI framework
- **psutil** - System monitoring capabilities
- Security research community for threat patterns
