# Contributing to What's for Dinner

Thank you for your interest in contributing! This document explains how to
contribute while maintaining code quality and security.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR-USERNAME/what-s-for-dinner.git
   cd what-s-for-dinner
   ```
3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   pre-commit install
   ```

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `security/description` - Security improvements
- `docs/description` - Documentation updates

### Making Changes

1. Create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature
   ```

2. Make your changes following our code standards

3. Run the quality gates:
   ```bash
   # Format and lint
   ruff format dinner_app/ tests/
   ruff check dinner_app/ tests/ --fix

   # Security scan
   bandit -r dinner_app/ -ll

   # Run tests
   pytest tests/ -v
   ```

4. Commit your changes:
   ```bash
   git add .
   git commit -m "feat: your descriptive message"
   ```

5. Push and create a Pull Request

## Quality Gates

All PRs must pass these automated checks:

### 1. Linting (ruff)
- No syntax errors
- Follows PEP 8 style
- No unused imports/variables
- Proper import ordering

### 2. Security (bandit)
- No high/medium severity issues
- No hardcoded secrets
- Safe file operations

### 3. Secrets Detection
- No API keys, passwords, or tokens
- No private keys
- Pre-commit hook blocks commits with secrets

### 4. Tests
- All existing tests must pass
- New features require tests
- Minimum coverage: maintain or improve

### 5. Code Review
- At least one approval required
- Security-sensitive changes require maintainer review

## Code Standards

### Python Style
- Python 3.9+ compatible
- Type hints encouraged
- Docstrings for public functions
- Max line length: 100 characters

### Security Requirements
- Validate ALL user inputs
- Use `dinner_app.security` module for sanitization
- No `eval()`, `exec()`, or `os.system()`
- No hardcoded credentials
- Log errors without sensitive data

### Testing Requirements
- Unit tests for new functions
- Integration tests for features
- Security tests for input handling
- Tests should be deterministic

## Pull Request Process

1. **Title**: Use conventional commits format
   - `feat:` New feature
   - `fix:` Bug fix
   - `security:` Security improvement
   - `docs:` Documentation
   - `refactor:` Code refactoring
   - `test:` Test additions/changes

2. **Description**: Include
   - What the PR does
   - Why it's needed
   - How to test it
   - Screenshots (for UI changes)

3. **Checklist**:
   - [ ] Code follows style guidelines
   - [ ] Tests added/updated
   - [ ] Documentation updated
   - [ ] No security issues introduced
   - [ ] PR is focused (one feature/fix)

## Security Contributions

For security improvements:
1. Clearly document the vulnerability being fixed
2. Add regression tests
3. Mark PR with `security` label
4. Request maintainer review

For reporting vulnerabilities, see [SECURITY.md](SECURITY.md).

## Getting Help

- Open an issue for questions
- Tag maintainers for security concerns
- Check existing issues/PRs first

## License

By contributing, you agree that your contributions will be licensed under the
same license as the project (MIT Non-Commercial).
