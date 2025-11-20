Advanced Topics and Troubleshooting
====================================

Permissions and Privileges
--------------------------

* On Linux/macOS, raw sockets and certain Scapy operations require root. Run with `sudo` for SYN/UDP scans.
* On Windows, run PowerShell or Command Prompt as Administrator.

Selecting a Network Interface
-----------------------------

Scapy may detect multiple interfaces; select the correct one (the one with connectivity to the scan targets). If no interface is shown, Scapy might not be installed or you may need administrative rights.

Common Problems
---------------

* Scapy import problems: install scapy using `pip install scapy` or check your Python environment.
* PySide6 GUI does not start: ensure PySide6 is installed and your graphics stack is supported (try running a simpler PySide6 sample app).
* Banner grabbing empty: sometimes services are not configured to show banners; attempt protocol‑specific probes or increase timeout.

Logging and Debugging
---------------------

Set `logging` module level to DEBUG in the script to get more diagnostic output:

.. code-block:: python

   import logging
   logging.basicConfig(level=logging.DEBUG)

This will print scapy and scan debug messages to stdout.
