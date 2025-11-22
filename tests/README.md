# Tests

This directory contains the test suite for the Port Scanner application.

## Running Tests

### Using pytest directly:
```bash
pytest tests/ -v
```

### Using Python module:
```bash
python -m pytest tests/ -v
```

### Using conda (in CI):
```bash
conda run -n base python -m pytest tests/ -v
```

## Test Coverage

The test suite includes:

- **test_python_version**: Validates Python 3.10+ requirement
- **test_required_modules_available**: Checks standard library imports
- **test_pyside6_available**: Tests PySide6 availability (optional)
- **test_scapy_import**: Tests Scapy availability (optional)
- **test_ipaddress_parsing**: Validates IP address parsing
- **test_socket_functionality**: Tests socket operations
- **test_port_range_generation**: Validates port range logic
- **test_json_csv_modules**: Tests JSON and CSV operations
- **test_logging_setup**: Validates logging configuration
- **test_threading_available**: Tests threading functionality
- **test_environment_variables**: Tests environment access

## Notes

- Tests are designed to work without GUI dependencies
- Optional dependencies (PySide6, Scapy) are gracefully handled
- All tests use standard library functionality
- No network access required for tests
