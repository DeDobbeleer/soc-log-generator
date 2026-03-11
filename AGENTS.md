# Agent Guidelines - SOC Log Generator

## Language Policy

**ALL documentation, code, comments, and scripts MUST be in English.**

This includes:
- All `.md` documentation files
- All Python code and comments
- All shell scripts and comments
- All test procedures and guides
- All Git commit messages
- All issue descriptions

## Rationale

- International team collaboration
- Industry standard for security tools
- Consistency across the project
- Easier external contributions

## Translation Checklist

Before committing, verify:
- [ ] No French text in documentation
- [ ] No French text in code comments
- [ ] No French text in error messages
- [ ] No French text in test scripts
- [ ] All user-facing messages in English

## Translation History

- 2024-03-08: All documents translated from French to English
  - README.md
  - TEST_PROCEDURE.md
  - STATUS.md
  - test_scripts/*.sh
  - test_scripts/README.md
- 2026-03-07: Complete translation of remaining French text
  - config/default.yaml
  - generators/endpoint/windows_generator.py
  - generators/endpoint/linux_generator.py
  - generators/endpoint/nxlog_windows.py
  - CONTRIBUTING.md

## Exceptions

None. All content must be in English.

---

## Development Guidelines

### Code Style
- Follow PEP 8 for Python code
- Use type hints where possible
- Document all public functions
- Keep functions focused and small

### Testing
- All generators must pass validation tests
- New features require tests
- Update TEST_PROCEDURE.md for SIEM changes

### Documentation
- Update INDEX.md when adding new docs
- Keep STATUS.md current
- Add examples for new features
