API Reference (Static)
======================

This page describes the main classes and functions used in the project.

ScanThread
----------
- Implements scanning logic using QThread triggers.
- Methods:
  - `scan_tcp_connect_port(host, port, idx, total_ports)` — Standard TCP connect scan and banner grabbing.
  - `scan_syn_port(host, port, idx, total_ports)` — SYN scan (Scapy required).
  - `scan_udp_port(host, port, idx, total_ports)` — UDP scan with service-specific probes.
  - `grab_banner(sock, port)` — Attempts multiple methods to grab protocol banners and cleans them up.
  - `run()` — Orchestrates discovery (optional) and parallel scanning using ThreadPoolExecutor.

Ui_dialog
---------
- The Qt GUI layer handling layout and user interaction.
- Methods and features:
  - `setupUi(dialog)` — Builds the GUI layout and wires signals.
  - `start_scan()` — Prepares input and launches a `ScanThread`.
  - `update_open_ports(host, port, banner)` — Adds results to the UI table and maintains local list.
  - `save_results()` — Exports results to TXT, CSV, or JSON

Other utilities
---------------
- `parse_hosts(host_input)` — Handles IPs, CIDRs, names and ranges and derails a list of scan targets.

For a detailed programmatic API reference — converting to importable module(s) and using sphinx-autodoc would be necessary.
