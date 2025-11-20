Usage
=====

Running the GUI
---------------

The application is started from the project root:

.. code-block:: bash

    python "Projekt AB Skaner Portów.py"

Basic usage

1. Enter a target host or a list of hosts (CIDR or comma/space separated). Example: `192.168.1.1 192.168.1.0/24`
3. Use the `Host Discovery` checkbox to pre-run ICMP pings and filter out non-responsive hosts.
4. Select the interface for raw scanning (only enabled when Scapy is present and you select a raw scan type).
5. Press `Scan` to start.
2. Enter ports to scan; you can specify ranges such as `20-25 80 443` or leave blank to scan all ports.
3. Pick scan type: `TCP Connect`, `TCP SYN Scan` (Scapy required), `UDP Scan` (Scapy required).
4. Optionally select a network interface for raw scans.
5. Press `Scan` and watch results. Use `Save Results` to export.

Notes
Tips and best practices
-----------------------

- Use `Delay` in the scanner to slow down the rate and reduce the chance of missing ports or being rate‑limited.
- If scanning large networks, use `Host Discovery` to reduce scanned targets to live hosts only.
- For banner grabbing connect with TCP Connect scan; SYN scans are faster but do not collect banners by default.
