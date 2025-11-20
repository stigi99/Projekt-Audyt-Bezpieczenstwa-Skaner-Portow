FAQ
===

Q: Why is PySide6 not required in CI for docs?
A: PySide6 is a heavy GUI package and not needed to build static docs. We mock it in `conf.py` so the docs build without it.

Q: Why are some UDP ports listed as `open|filtered`?
A: UDP responses are often silent for open ports; lack of response means either the port is open or filtered by a firewall. If you receive an ICMP Port Unreachable message (type 3, code 3) the port is definitely closed.

Q: Can I scan a remote network?
A: Only if you have explicit permission from the network owner. Scanning remote networks without permission can be illegal and unethical.

Q: Why does SYN scan require root?
A: SYN scan uses raw sockets, which need elevated privileges to craft and send raw packets.
