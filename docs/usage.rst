Usage
=====

Running the GUI
---------------

The application is started from the project root:

.. code-block:: bash

    python "Projekt AB Skaner Portów.py"

Basic usage
-----------

1. Enter a target host or a list of hosts (CIDR or comma/space separated). Example: `192.168.1.1 192.168.1.0/24`
2. Enter ports to scan; you can specify ranges such as `20-25 80 443` or leave blank to scan all ports.
3. Pick scan type: `TCP Connect`, `TCP SYN Scan` (Scapy required), `UDP Scan` (Scapy required).
4. Optionally select a network interface for raw scans.
5. Press `Scan` and watch results. Use `Save Results` to export.

Notes
-----
- Running raw scans (`TCP SYN` or `UDP Scan`) requires Scapy and elevated privileges.
- Be mindful of the scan's legal/ethical implications.
