# fuwarp Test Suite

Integration test suite for the fuwarp.py script

## Overview

This directory contains the integration test suite for fuwarp.py. The tests are maintained separately from the main script to preserve fuwarp.py as a standalone, single-file distribution.

The test suite provides comprehensive coverage of fuwarp's functionality through mocked external dependencies, ensuring reliability across different environments and configurations.

## Quick Start

```bash
cd test_suite
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
python -m pytest test_fuwarp_integration.py -v
```

## Installation

### Prerequisites

- Python 3.10 or higher
- uv package manager (or standard pip)

### Setup Steps

1. Create and activate a virtual environment:
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install test dependencies:
   ```bash
   uv pip install -r requirements.txt
   ```

## Running Tests

### Basic Commands

```bash
# Run all tests with verbose output
python -m pytest test_fuwarp_integration.py -v

# Run tests quietly
python -m pytest test_fuwarp_integration.py -q

# Run specific test class
python -m pytest test_fuwarp_integration.py::TestCertificateManagement -v

# Run specific test method
python -m pytest test_fuwarp_integration.py::TestToolSetup::test_node_npm_setup_workflow -v

# Stop on first failure
python -m pytest test_fuwarp_integration.py -x

# Run with coverage report
python -m pytest test_fuwarp_integration.py --cov=fuwarp --cov-report=term-missing
```

### Debugging Tests

```bash
# Show print statements and logging
python -m pytest test_fuwarp_integration.py -v -s

# Drop into debugger on failure
python -m pytest test_fuwarp_integration.py --pdb

# Show full traceback
python -m pytest test_fuwarp_integration.py -v --tb=long
```

## Test Architecture

### Directory Structure

```
test_suite/
├── conftest.py                 # Pytest configuration and shared fixtures
├── fixtures/
│   └── sample_cert.pem        # Sample certificate for testing
├── helpers.py                 # Test utilities and MockBuilder
├── mock_data.py              # Centralized mock responses
├── requirements.txt          # Test dependencies
├── test_fuwarp_integration.py # Main test suite
└── README.md                 # This file
```

### Test Organization

Tests are organized into focused classes:

- **TestCertificateManagement**: Certificate download, validation, and storage
- **TestToolSetup**: Individual tool configuration workflows
- **TestCLIAndWorkflow**: Command-line interface and complete workflows
- **TestToolSelection**: Tool filtering and selection logic
- **TestErrorScenarios**: Error handling and edge cases
- **TestConnectionVerification**: HTTPS connection testing
- **TestPlatformSpecific**: Platform-dependent behavior

### Mock Strategy

The test suite uses a comprehensive mocking approach:

- **MockBuilder**: Fluent interface for constructing test environments
- **Centralized mock data**: Realistic command outputs and responses in `mock_data.py`
- **Context managers**: Clean setup and teardown of mock environments
- **No external dependencies**: All subprocess calls, file operations, and network requests are mocked

## Development Guidelines

### Adding Tests for New Tools

When adding support for a new tool in fuwarp.py:

1. Add mock data to `mock_data.py`:
   ```python
   NEWTOOL_VERSION = "1.0.0"
   NEWTOOL_CONFIG_PATH = "/path/to/config"
   ```

2. Create test in appropriate test class:
   ```python
   def test_newtool_setup_workflow(self):
       """Test NewTool certificate configuration."""
       mock_config = (MockBuilder()
           .with_certificate()
           .with_tool('newtool')
           .with_subprocess_response(stdout=mock_data.NEWTOOL_VERSION)
           .build())
       
       with mock_fuwarp_environment(mock_config) as mocks:
           instance = self.create_fuwarp_instance(mode='install')
           instance.setup_newtool_cert()
           
           # Verify tool was detected and configured
           assert mocks['which'].called
   ```

### Writing Effective Tests

1. **Use descriptive test names**: Test method names should clearly describe what is being tested
2. **One assertion focus**: Each test should verify a single behavior
3. **Mock realistically**: Use authentic command outputs and error messages
4. **Test error paths**: Include tests for failure scenarios and edge cases
5. **Maintain independence**: Tests should not depend on execution order

### Test Coverage Standards

New features should include:
- Positive test cases (happy path)
- Negative test cases (error conditions)
- Edge cases (boundary conditions)
- Integration tests (workflow verification)

## Continuous Integration

### GitHub Actions Integration

The test suite is designed for CI/CD pipelines:

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ['3.10', '3.11', '3.12']
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install uv
      run: pip install uv
    
    - name: Run tests
      run: |
        cd test_suite
        uv venv
        source .venv/bin/activate
        uv pip install -r requirements.txt
        python -m pytest test_fuwarp_integration.py -v
```

## Maintenance

### Updating Dependencies

```bash
# List outdated packages
uv pip list --outdated

# Update specific packages
uv pip install --upgrade pytest pytest-mock

# Regenerate requirements.txt
uv pip freeze > requirements.txt
```

### When fuwarp.py Changes

1. Run existing tests to detect regressions
2. Update mock data if command outputs change
3. Add tests for new functionality
4. Update test documentation as needed

### Common Issues and Solutions

**Import Errors**
- Ensure virtual environment is activated
- Verify you're in the test_suite directory
- Check Python version compatibility

**Mock Failures**
- Verify patch paths match imports in fuwarp.py
- Check mock_data.py for correct response formats
- Ensure MockBuilder configuration matches test requirements

**Assertion Errors**
- Use -v flag for detailed output
- Check actual vs expected values in error messages
- Verify mock responses match real command outputs

## Design Principles

1. **Isolation**: Tests do not modify the actual system or require external services
2. **Reproducibility**: Tests produce consistent results across environments
3. **Maintainability**: Clear structure and documentation for easy updates
4. **Performance**: Fast execution through comprehensive mocking
5. **Completeness**: Coverage of both success and failure scenarios

## Contributing

When contributing tests:

1. Follow existing patterns and conventions
2. Ensure all tests pass before submitting
3. Add appropriate mock data for new scenarios
4. Update documentation for significant changes
5. Include tests with bug fixes to prevent regressions

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [unittest.mock guide](https://docs.python.org/3/library/unittest.mock.html)
- [pytest-mock documentation](https://pytest-mock.readthedocs.io/)