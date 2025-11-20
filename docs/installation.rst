Installation
============

Prerequisites
-------------

- Python 3.10+ (3.11 recommended)
- `pip` or `pipx` for managing virtual environments

Install dependencies
---------------------

Create virtual environment and install dependencies:

.. code-block:: bash

   python3 -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   python -m pip install -r requirements.txt

Note on Scapy
-------------

Scapy may need system-level privileges to use raw sockets for SYN/UDP scanning. On macOS or Linux, you can run the script using sudo; on Windows run PowerShell as Administrator.
