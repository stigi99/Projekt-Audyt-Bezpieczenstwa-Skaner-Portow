Architektura projektu
=====================

W tej sekcji przedstawiono diagram komponentów aplikacji oraz krótki opis zależności między modułami.

Diagrams
--------

.. mermaid::

   graph LR
       UI["GUI (Ui_dialog)"] -- "wysyła sygnały" --> ScanThread["ScanThread (QThread)"]
       ScanThread -- "używa" --> Executor["ThreadPoolExecutor"]
       ScanThread -- "wywołuje skanery" --> ConnectScan["TCP Connect / banner-grabbing"]
       ScanThread -- "wywołuje" --> SynScan["TCP SYN (Scapy)"]
       ScanThread -- "wywołuje" --> UdpScan["UDP (Scapy)"]
       ScanThread -- "używa" --> Scapy["Scapy (opcjonalnie, raw sockets)"]
       UI -- "odczytuje/ustawia" --> Settings["UI Controls/Settings"]
       UI -- "zapisuje" --> FileIO["File Save (txt/csv/json)"]
       Scapy -- "interakcja" --> Network["Sieć / Stack OS"]

Opis
-----

* UI (klasa Ui_dialog) — interfejs graficzny zbudowany przy pomocy PySide6; inicjuje skanowanie, kontroluje pasek postępu oraz wyświetla wyniki w tabeli.
* ScanThread — wątek pracujący (QThread), który uruchamia ThreadPoolExecutor do wykonywania zadań skanowania w tle.
* ThreadPoolExecutor — pulę wątków służąca do równoległego przetwarzania skanów portów na wielu hostach.
* Scapy — biblioteka używana do wykonywania surowych pakietów (SYN, UDP i ping przez warstwę 2/3). Jest opcjonalna i wymagane są uprawnienia root/administrator.
* FileIO — moduły do zapisu wyników (txt, csv, json).

Uwagi dotyczące bezpieczeństwa i uprawnień
-----------------------------------------

Skanowanie przy użyciu operacji warstwy 2/3 wymaga uprawnień administratora (root) dla niektórych funkcji. Jeżeli Scapy nie jest dostępny, aplikacja wyłączy opcje raw-socket (TCP SYN/UDP) i wykorzysta technikę "TCP Connect" (sockety jądra).
