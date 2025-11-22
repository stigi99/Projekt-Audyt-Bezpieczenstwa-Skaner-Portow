import os
import importlib.util
import sys


def load_main_module():
    # Monkeypatch is done in the test caller; just import module from file path
    root = os.path.abspath(os.path.dirname(__file__) + "/..")
    file_path = os.path.join(root, "Projekt AB Skaner Portów.py")
    spec = importlib.util.spec_from_file_location("main_module", file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_hosts_simple(monkeypatch):
    # conftest provides minimal stubs for PySide6 and scapy

    module = load_main_module()
    ui = module.Ui_dialog()

    # Single host
    hosts = ui.parse_hosts("127.0.0.1")
    assert hosts == ["127.0.0.1"]

    # CIDR
    hosts = ui.parse_hosts("192.168.1.0/30")
    # 192.168.1.0/30 network has two hosts 192.168.1.1 and 192.168.1.2; may include network address depending on code
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts


def test_parse_hosts_complex(monkeypatch):
    # conftest has stubs; load module
    module = load_main_module()
    ui = module.Ui_dialog()

    # Range and single ports in input - parse string includes hostnames and ranges
    hosts = ui.parse_hosts("example.com 10.0.0.1/30")
    assert "example.com" in hosts
    assert "10.0.0.1" in hosts


def test_parse_hosts_range_full(monkeypatch):
    module = load_main_module()
    ui = module.Ui_dialog()
    hosts = ui.parse_hosts("192.168.1.10-192.168.1.12")
    assert "192.168.1.10" in hosts
    assert "192.168.1.11" in hosts
    assert "192.168.1.12" in hosts


def test_parse_hosts_range_shorthand_last_octet(monkeypatch):
    module = load_main_module()
    ui = module.Ui_dialog()
    hosts = ui.parse_hosts("192.168.1.10-12")
    assert "192.168.1.10" in hosts
    assert "192.168.1.11" in hosts
    assert "192.168.1.12" in hosts
