Przepływ skanowania i sekwencje
================================

Sekwencja działania skanera i diagramy krok po kroku.

1. Sekwencja skanowania
------------------------

.. mermaid::

   sequenceDiagram
       participant U as User
       participant UI as UI (Ui_dialog)
       participant T as Thread (ScanThread)
       participant E as Executor (ThreadPool)
       participant S as Scapy/Socket
       U->>UI: Kliknij "Scan"
       UI->>T: start_scan(hosts, ports, type)
       T->>T: (opcjonalnie) discover_hosts()
       T->>E: submit(scan_task(host,port))
       E->>S: wykonaj skan (connect/syn/udp)
       S-->>E: wynik (open/closed/filtered/banner)
       E-->>T: przekaz wynik
       T-->>UI: signal_open_port(host, port, banner)
       UI->>UI: aktualizuj tabela i pasek postępu
       T-->>UI: signal_end_scan

2. Cykl życia skanu — stan
---------------------------

.. mermaid::

   stateDiagram-v2
       [*] --> Idle
       Idle --> Scanning : start_scan()
       Scanning --> Discovery : host_discovery_enabled
       Discovery --> Scanning : hosts_found
       Scanning --> Cancelled : stop() / cancel
       Scanning --> Completed : all_tasks_done
       Cancelled --> Idle
       Completed --> Idle

Opis kroków
-----------

* start_scan — walidacja pól wejścia, przygotowanie list hostów i portów, utworzenie wątku ScanThread.
* host_discovery (opcjonalne) — wykrywanie aktywnych hostów przy pomocy ICMP/Scapy/OS ping.
* submit tasks — każde zadanie odpowiada pojedynczemu host:port i trafia do pul wątków.
* wykonanie skanu — worker próbuje wykonać wybraną technikę (Connect/SYN/UDP), pobiera banner dla TCP Connect i interpretuje odpowiedzi.
* UI update — zakończenie każdego tasku informuje UI poprzez sygnały Qt; UI aktualizuje stan paska i tabeli wyników.
