# Quick Start Guide

Get up and running with AI Security Assistant in 5 minutes!

## Prerequisites

- Python 3.8 or higher
- Ollama (optional, but required for AI features)

## Installation Steps

### Step 1: Install Ollama (Optional but Recommended)

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

**Windows:**
Download from [ollama.ai](https://ollama.ai/)

### Step 2: Start Ollama and Pull a Model

```bash
# Start Ollama service
ollama serve

# In another terminal, pull a model
ollama pull llama2

# For low RAM systems, use mistral instead:
ollama pull mistral
```

### Step 3: Clone and Setup

```bash
# Clone repository
git clone https://github.com/fawad0dev/AI-Sec-Assist.git
cd AI-Sec-Assist

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python test_installation.py
```

### Step 4: Run the Application

**GUI Mode:**
```bash
python main.py
```

**CLI Mode:**
```bash
# Show help
python cli.py --help

# Run a quick scan
python cli.py scan-network
```

## First Time Configuration

1. Launch the application: `python main.py`

2. Go to **Settings** tab:
   - Verify Ollama status (should show green checkmark)
   - Select your AI model (llama2 recommended)
   - Add log paths you want to monitor

3. Go to **Security Scans** tab:
   - Click "Analyze Network" to run your first scan
   - Review the results
   - Click "Analyze Results with AI" to get insights

4. Go to **Chat** tab:
   - Ask: "What should I do if I find suspicious network activity?"
   - Get expert security advice

## Common First Steps

### Monitor System Logs (Linux)
```bash
# Settings → Add Log Path
/var/log/auth.log
/var/log/syslog
```

### Monitor System Logs (Windows)
Use the GUI to add:
- Event Viewer logs
- Application logs
- Security logs

### Run Complete Security Check
```bash
# Using CLI
python cli.py scan-logs --directory /var/log
python cli.py scan-network
python cli.py scan-registry  # Windows only
```

## Troubleshooting

### Ollama Not Connected?

**Check if Ollama is running:**
```bash
# Should return status 200
curl http://localhost:11434/
```

**Start Ollama:**
```bash
ollama serve
```

### Permission Errors?

**Linux/Mac:**
```bash
# Run with sudo for full access
sudo python main.py
```

**Windows:**
- Right-click `main.py`
- Select "Run as Administrator"

### Import Errors?

```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

## What to Do Next

1. **Regular Monitoring**: Set up daily scans for your critical logs
2. **Learn Patterns**: Review what the scanners detect
3. **Use AI Assistant**: Ask questions about security findings
4. **Customize**: Add your specific log paths and monitoring needs
5. **Automate**: Use CLI with cron jobs for scheduled scans

## Getting Help

- **In-App**: Use the Chat tab to ask the AI assistant
- **Documentation**: See README.md for full documentation
- **Examples**: Check EXAMPLES.md for use cases
- **Issues**: GitHub Issues for bugs or feature requests

## Security Tips

✓ Run with appropriate permissions (root/admin for full access)
✓ Start with read-only scans before taking action
✓ Verify AI recommendations before implementing
✓ Keep Ollama and models updated
✓ Review scan results regularly
✓ Don't rely solely on this tool - use defense in depth

---

**You're ready to start!** Run `python main.py` and explore the interface.
