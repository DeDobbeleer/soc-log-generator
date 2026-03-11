# Contributing to SOC Log Generator

Thank you for your interest in contributing to SOC Log Generator! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Respect different viewpoints and experiences

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/soc-log-generator.git
   cd soc-log-generator
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/soc-log-generator.git
   ```

## Development Setup

### Prerequisites

- Python 3.9+
- pip or poetry
- Git

### Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Verify installation
python -m soc_log_generator --version
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=soc_log_generator --cov-report=html

# Run specific test file
pytest tests/test_generators.py

# Run with verbose output
pytest -v
```

## How to Contribute

### Reporting Bugs

Before creating a bug report, please:
1. Check the [existing issues](https://github.com/.../issues)
2. Update to the latest version to see if the bug is already fixed

When reporting bugs, include:
- **Description**: Clear description of the bug
- **Steps to Reproduce**: Minimal steps to reproduce the issue
- **Expected Behavior**: What you expected to happen
- **Actual Behavior**: What actually happened
- **Environment**: Python version, OS, relevant package versions
- **Logs/Screenshots**: If applicable

### Suggesting Features

Feature requests are welcome! Please provide:
- **Clear description** of the feature
- **Use case**: Why is this feature needed?
- **Proposed implementation**: If you have ideas on how to implement it
- **Priority**: Is this critical, nice-to-have, or future work?

### Adding New Log Sources

To add a new log source generator:

1. **Check the [SPECS.md](SPECS.md)** for generator architecture
2. **Create your generator** in the appropriate directory:
   ```
   generators/<category>/<source_name>.py
   ```
3. **Inherit from BaseGenerator**:
   ```python
   from ..core import BaseGenerator, LogEvent, EventSeverity
   
   class MyNewGenerator(BaseGenerator):
       def generate_event(self) -> LogEvent:
           # Implementation
           pass
   ```
4. **Add tests** in `tests/generators/test_<source_name>.py`
5. **Update documentation** in README.md and INDEX.md
6. **Add configuration** example in config/default.yaml

### Adding Business Vertical Sources

For industry-specific sources (Healthcare, Finance, etc.):

1. **Create generator** in `business/<vertical>/`
2. **Add vertical documentation** in `docs/verticals/<VERTICAL>.md`
3. **Include real-world examples** and compliance requirements
4. **Reference regulations** (HIPAA, PCI-DSS, etc.)

### Contributing Scenarios

To add attack scenarios:

1. **Follow the template**: [threat_intel/cisa/TEMPLATE_CISA_ALERT.yaml](threat_intel/cisa/TEMPLATE_CISA_ALERT.yaml)
2. **Map to MITRE ATT&CK** techniques
3. **Include detection rules** (Sigma, Splunk, KQL)
4. **Add variations** for different attack speeds/styles
5. **Place in appropriate directory**:
   - CISA-based: `threat_intel/cisa/`
   - MITRE-based: `threat_intel/mitre/`
   - Custom: `scenarios/`

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 100 characters maximum
- **Docstrings**: Google style
- **Type hints**: Required for all public functions
- **Imports**: Grouped as stdlib, third-party, local

Example:
```python
"""Brief description.

Detailed description of the function.

Args:
    param1: Description of param1
    param2: Description of param2

Returns:
    Description of return value

Raises:
    ValueError: When invalid input is provided
"""
from typing import Dict, List

def process_logs(logs: List[str], config: Dict) -> List[LogEvent]:
    """Process raw logs into structured events."""
    # Implementation
    pass
```

### Code Quality Tools

```bash
# Format code
black soc_log_generator/ tests/

# Check imports
isort --check-only soc_log_generator/ tests/

# Lint
pylint soc_log_generator/
flake8 soc_log_generator/

# Type checking
mypy soc_log_generator/
```

### Project Structure

```
soc-log-generator/
├── core/               # Core engine components
├── generators/         # Log generators by category
├── scenarios/          # Attack scenarios
├── threat_intel/       # Threat intelligence scenarios
├── ai/                 # AI/LLM integration
├── parsers/            # Log parsers
├── business/           # Industry-specific sources
├── tests/              # Test suite
│   ├── unit/           # Unit tests
│   ├── integration/    # Integration tests
│   └── fixtures/       # Test data
├── docs/               # Documentation
└── config/             # Configuration files
```

## Testing

### Test Categories

1. **Unit Tests**: Test individual functions/classes
2. **Integration Tests**: Test component interactions
3. **E2E Tests**: Test complete workflows

### Writing Tests

```python
import pytest
from soc_log_generator.generators.windows import WindowsEventGenerator

def test_windows_process_creation():
    """Test Windows process creation event generation."""
    generator = WindowsEventGenerator(config={})
    event = generator._generate_process_create_event()
    
    assert event.source_type == "windows"
    assert event.fields["EventID"] == 4688
    assert "CommandLine" in event.fields
```

### Test Data

- Use fixtures in `tests/fixtures/`
- Generate sample data with factories
- Don't commit real log samples with sensitive data

## Documentation

### Updating Documentation

When adding features, update:

1. **README.md**: User-facing documentation
2. **SPECS.md**: Technical specifications
3. **INDEX.md**: Navigation and links
4. **Docstrings**: Code documentation
5. **CHANGELOG.md**: Release notes

### Documentation Style

- Use clear, concise language
- Include code examples
- Use English for all documentation and code
- Use markdown formatting

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Build process, dependencies, etc.

Examples:
```
feat(generators): add Linux Sysmon support

Implement Event ID 1, 3, 9, 11 for Linux Sysmon
generator based on eBPF events.

fix(core): resolve rate limiter drift

core: add AssetInventory caching

docs: update README with new output formats
```

## Pull Request Process

1. **Update your fork**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/my-new-feature
   ```

3. **Make your changes** with clear, focused commits

4. **Run tests and checks**:
   ```bash
   pytest
   black --check .
   flake8
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/my-new-feature
   ```

6. **Create Pull Request** on GitHub:
   - Fill in the PR template
   - Link related issues
   - Request review from maintainers

### PR Checklist

- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] All tests pass
- [ ] No merge conflicts
- [ ] PR description is clear

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by at least one maintainer
3. **Approval** required before merge
4. **Squash merge** preferred for clean history

## Release Process

Releases follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

## Questions?

- **General questions**: Open a [Discussion](https://github.com/.../discussions)
- **Bug reports**: Open an [Issue](https://github.com/.../issues)
- **Security issues**: Email security@example.com (DO NOT open public issue)

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- CONTRIBUTORS.md
- Release notes

Thank you for contributing to SOC Log Generator!
