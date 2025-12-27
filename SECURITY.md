# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | :white_check_mark: |
| 1.4.x   | :white_check_mark: |
| < 1.4   | :x:                |

## Vulnerability Disclosure Policy (VDP)

We take security seriously and appreciate your help in keeping What's for Dinner safe.

### Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report security issues via one of these methods:

1. **GitHub Security Advisories** (Preferred):
   - Go to https://github.com/techmad220/what-s-for-dinner/security/advisories
   - Click "New draft security advisory"
   - Fill in the details

2. **Email**: Contact the maintainer directly through GitHub

### What to Include

Please provide:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Safe Harbor

We consider security research conducted in good faith to be:
- Authorized concerning any applicable anti-hacking laws
- Exempt from restrictions in our Terms of Service
- Lawful and helpful to the overall security of the internet

We will not pursue civil action or initiate a complaint for accidental, good-faith
violations of this policy.

## Security Measures

This application implements the following security controls:

### Input Validation
- All user inputs are validated and sanitized
- Maximum length limits on all text fields
- Pattern matching to block suspicious content
- Path traversal prevention

### XSS Prevention
- Script tags and JavaScript blocked
- Event handlers (onclick, onerror, etc.) blocked
- Control characters stripped

### File Security
- Plugin files must start with `plugin_`
- Static analysis of plugin code before loading
- Dangerous imports/functions flagged
- File permission checks

### Data Integrity
- JSON validation on all data files
- Type checking on loaded data
- Graceful handling of malformed data

### Logging
- Rotating log files (1MB max, 3 backups)
- Error logging with stack traces
- No sensitive data logged

## Security Testing

Run security checks locally:

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run bandit security scanner
bandit -r dinner_app/ -ll

# Scan for secrets
detect-secrets scan --all-files

# Run full test suite
pytest tests/ -v
```

## Known Limitations

- **Local Application**: This is a local desktop app with no network features.
  Authentication and session management are not applicable.
- **Plugin System**: Plugins have full Python access. Only install plugins you trust.
- **Data Storage**: Data is stored in plaintext JSON files. Do not store sensitive
  information in recipes.
