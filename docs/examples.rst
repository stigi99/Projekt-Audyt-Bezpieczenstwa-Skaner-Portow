Examples
========

Example 1 — Local host quick scan
------------------------------------

1. Set `Ip` to `127.0.0.1`
2. Set `Ports` to `22 80` (or `1-1024` to scan first 1024 ports)
3. Choose `TCP Connect` as scan type and press `Scan`

Example 2 — Scan a subnet but use Host Discovery
-------------------------------------------------

1. Set `Ip` to `192.168.1.0/24`
2. Set `Ports` to `80 443 22`
3. Check `Host Discovery` and choose a 10–50 ms delay
4. Use `Save Results` to export to CSV

Notes
-----
- Watch the console logs for the `ScanThread` to see advanced debugging output (set `logging.DEBUG` to view more).
