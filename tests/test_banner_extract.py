import os
import sys
import importlib.util


def load_main_module(monkeypatch):
    # conftest provides minimal stubs for PySide6 and scapy

    root = os.path.abspath(os.path.dirname(__file__) + "/..")
    file_path = os.path.join(root, "Projekt AB Skaner Portów.py")
    spec = importlib.util.spec_from_file_location("main_module", file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extract_banner_basic(monkeypatch):
    module = load_main_module(monkeypatch)
    # Create a dummy ScanThread instance - we can pass None/empty values for the params
    scan = module.ScanThread("TCP Connect", ["127.0.0.1"], ["80"], 1, None, False)

    # HTTP banner
    banner = "HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nDate: Tue"
    extracted = scan._extract_banner_info(banner, 80)
    assert "nginx" in extracted or "nginx/1.18.0" in extracted

    # SSH banner
    banner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
    assert scan._extract_banner_info(banner, 22).startswith("SSH-2.0-OpenSSH")

    # FTP first line
    banner = "220 (vsFTPd 3.0.3)\r\n"
    assert "vsFTPd" in scan._extract_banner_info(banner, 21)
