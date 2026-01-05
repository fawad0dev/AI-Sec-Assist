# Contributing to AI Security Assistant

Thank you for your interest in contributing! We welcome contributions from the community.

## Ways to Contribute

### 1. Report Bugs
- Use GitHub Issues
- Provide detailed description
- Include steps to reproduce
- Share system information (OS, Python version)
- Attach relevant logs/screenshots

### 2. Suggest Features
- Open a GitHub Issue with label "enhancement"
- Describe the feature and use case
- Explain why it would be valuable
- Consider implementation complexity

### 3. Improve Documentation
- Fix typos or unclear sections
- Add examples or use cases
- Improve installation instructions
- Translate documentation

### 4. Submit Code

#### Before You Start
1. Check existing issues and PRs
2. Open an issue to discuss major changes
3. Fork the repository
4. Create a feature branch

#### Development Setup
```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/AI-Sec-Assist.git
cd AI-Sec-Assist

# Install dependencies
pip install -r requirements.txt

# Run tests
python test_installation.py
python test_scanners.py
```

#### Code Guidelines
- Follow existing code style
- Add docstrings to functions
- Include comments for complex logic
- Keep functions focused and small
- Handle errors gracefully
- Add type hints where possible

#### Testing
- Test your changes thoroughly
- Ensure existing tests pass
- Add new tests for new features
- Test on multiple platforms if possible

#### Commit Messages
- Use clear, descriptive messages
- Start with verb (Add, Fix, Update, etc.)
- Reference issue numbers (#123)
- Keep first line under 50 characters

Example:
```
Add hash verification for downloaded files (#123)

- Implement SHA256 hash checking
- Add progress indicator
- Update documentation
```

#### Pull Request Process
1. Update documentation if needed
2. Ensure tests pass
3. Update CHANGELOG (if exists)
4. Create PR with clear description
5. Link related issues
6. Wait for review

### 5. Add Detection Patterns

#### New Threat Patterns
To add new detection patterns to scanners:

**Log Scanner** (`src/scanners/log_scanner.py`):
```python
SUSPICIOUS_PATTERNS = [
    # ... existing patterns ...
    (r'your_pattern_here', 'Threat Description'),
]
```

**File Scanner** (`src/scanners/file_scanner.py`):
```python
SUSPICIOUS_STRINGS = [
    # ... existing patterns ...
    (r'your_pattern_here', 'Threat Description'),
]
```

**Network Analyzer** (`src/scanners/network_analyzer.py`):
```python
SUSPICIOUS_PORTS = {
    # ... existing ports ...
    12345: "Threat Description",
}
```

### 6. Improve AI Prompts

Help improve AI accuracy by refining prompts in `src/ai/ollama_client.py`:
- Make prompts more specific
- Add security context
- Reduce hallucination risk
- Test with multiple models

## Code of Conduct

### Our Standards
- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what's best for the project
- Show empathy towards others

### Unacceptable Behavior
- Harassment or discrimination
- Trolling or insulting comments
- Personal or political attacks
- Publishing others' private information
- Other unethical or unprofessional conduct

## Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email maintainers privately
2. Provide detailed description
3. Include steps to reproduce
4. Allow time for fix before disclosure

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md (if created)
- Mentioned in release notes
- Given credit in commits

## Questions?

- Open a GitHub Discussion
- Ask in the Issues section
- Check existing documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make AI Security Assistant better! 🛡️
