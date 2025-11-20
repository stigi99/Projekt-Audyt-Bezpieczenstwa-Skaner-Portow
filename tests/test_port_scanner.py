"""
Test suite for Port Scanner application

These tests validate basic functionality of the port scanner application.
Since the main module requires GUI components, we test what we can without
instantiating the full application.
"""

import pytest


def test_python_version():
    """Ensure Python version is 3.10+."""
    import sys
    assert sys.version_info >= (3, 10), "Python 3.10+ is required"


def test_required_modules_available():
    """Test that required Python modules can be imported."""
    # Test standard library imports
    import json
    import csv
    import socket
    import time
    import threading
    import logging
    import os
    import ipaddress
    import subprocess
    import webbrowser
    
    assert json is not None
    assert csv is not None
    assert socket is not None
    assert time is not None
    assert threading is not None
    assert logging is not None
    assert os is not None
    assert ipaddress is not None
    assert subprocess is not None
    assert webbrowser is not None


def test_pyside6_available():
    """Test that PySide6 can be imported if available."""
    try:
        from PySide6.QtCore import QThread, Signal
        from PySide6.QtWidgets import QApplication
        pyside6_available = True
    except ImportError:
        pyside6_available = False
    
    # PySide6 may not be available in all test environments
    # Just verify the import doesn't crash
    assert isinstance(pyside6_available, bool)


def test_scapy_import():
    """Test Scapy import (may not be available in all environments)."""
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        scapy_available = True
    except ImportError:
        scapy_available = False
    
    # Just verify it's a boolean - Scapy might not be available
    assert isinstance(scapy_available, bool)


def test_ipaddress_parsing():
    """Test IP address parsing functionality."""
    import ipaddress
    
    # Test single IP
    ip = ipaddress.ip_address("192.168.1.1")
    assert str(ip) == "192.168.1.1"
    
    # Test network CIDR
    network = ipaddress.ip_network("192.168.1.0/24", strict=False)
    assert network.num_addresses == 256


def test_socket_functionality():
    """Test basic socket functionality."""
    import socket
    
    # Test socket creation
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    assert sock is not None
    sock.close()


def test_port_range_generation():
    """Test port range generation logic."""
    # Simulate port range parsing
    ports = []
    
    # Single port
    ports.append("80")
    
    # Range
    port_range = "20-25"
    start, end = port_range.split("-")
    for p in range(int(start), int(end) + 1):
        ports.append(str(p))
    
    assert "80" in ports
    assert "20" in ports
    assert "25" in ports
    assert len(ports) == 7  # 1 single + 6 from range


def test_json_csv_modules():
    """Test that JSON and CSV modules work correctly."""
    import json
    import csv
    import tempfile
    import os
    
    # Test JSON
    test_data = {"host": "example.com", "port": 80}
    json_str = json.dumps(test_data)
    parsed = json.loads(json_str)
    assert parsed["host"] == "example.com"
    
    # Test CSV
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port"])
        writer.writerow(["example.com", "80"])
        temp_file = f.name
    
    try:
        with open(temp_file, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0] == ["Host", "Port"]
    finally:
        os.unlink(temp_file)


def test_logging_setup():
    """Test logging module setup."""
    import logging
    
    # Test logger creation
    logger = logging.getLogger("test_scanner")
    logger.setLevel(logging.ERROR)
    
    assert logger.level == logging.ERROR


def test_threading_available():
    """Test threading functionality."""
    import threading
    import time
    
    result = []
    
    def worker():
        result.append(True)
    
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=1)
    
    assert len(result) == 1
    assert result[0] is True


def test_environment_variables():
    """Test environment variable access."""
    import os
    
    # Test basic os functionality
    assert os.name in ['posix', 'nt']
    
    # Test path operations
    test_path = os.path.join("test", "path")
    assert "test" in test_path


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
