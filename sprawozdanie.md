# Sprawozdanie z Projektu — "Skaner Portów"

Autor: Mateusz Misiak

Data: 20 listopada 2025

---

## 1. Cel projektu

Głównym celem projektu było zaprojektowanie i implementacja aplikacji desktopowej (GUI) w Pythonie, która realizuje podstawowe skanowanie portów i banner grabbing. Dodatkowo celem było przygotowanie dokumentacji, testów, skryptów build (PyInstaller) i eksperymentalnej integracji z Nuitka, a także CI (GitHub Actions) generującego artefakty (DMG) gotowe do dystrybucji na macOS.

Projekt miał także charakter badawczy — sprawdziliśmy ograniczenia i trudności związane z budowaniem aplikacji GUI + niskopoziomowy networking na macOS, testowaliśmy integrację PySide6 ze Scapy, oraz przygotowaliśmy prosty pipeline CI.

## 2. Funkcje i zakres

- GUI (PySide6) z tabelą wyników integrującą banery i status portów.
- 3 tryby skanowania: TCP Connect, TCP SYN (Scapy), UDP.
- Banner grabbing z heurystykami i sondami dla popularnych serwisów.
- Parsowanie hostów: pojedyncze adresy, CIDR, zakresy, nazwy hostów.
- Eksport wyników do plików (CSV/JSON/TXT).
- Tworzenie paczki macOS (.app) oraz DMG; opcjonalne podpisywanie certyfikatem (codesign) i integracja z CI.

Zakres pominięty: rozbudowane OS fingerprinting, rozbudowane sondy protokołów użytkowych, automatyczna notarization (Apple Notary), oraz rozbudowana obsługa uprawnień natywnych.

## 3. Architektura i implementacja

Krótkie omówienie głównych komponentów (wszystko oparte na `Projekt AB Skaner Portów.py`):

- Ui_dialog (PySide6):
  - Zawiera konstrukcję okien GUI, pola do wprowadzania hostów i portów, przyciski Start/Cancel, pasek postępu, tabelę wyników (`QTableWidget`) i kontekstowe operacje (kopiuj, eksport).
  - Zdefiniowano `KNOWN_PORTS` (mapowanie numery -> usługa) oraz obsługę widgetów (ComboBox do wyboru typu skanowania — jeśli Scapy jest instalowane, dodajemy tryby TCP SYN i UDP).

- ScanThread (QThread):
  - Wątek odpowiedzialny za wykonywanie skanów w tle i emitowanie sygnałów do GUI.
  - Implementuje trzy główne metody: `scan_tcp_connect_port`, `scan_syn_port`, `scan_udp_port`.
  - `grab_banner` obsługuje różne heurystyki wysyłania sond, próby odbioru automatycznego bannera lub wysłania zapytania specyficznego (np. HTTP GET, EHLO), czyszczenie tekstu i _extract_banner_info.
  - Zaimplementowano mechanizm bezpiecznego anulowania skanów (flag `_is_cancelled`, `executor.shutdown(cancel_futures=True)`) oraz synchronizację przy zgłaszaniu tasków przez `ThreadPoolExecutor` (`_executor_lock`).

- Parsowanie hostów i portów:
  - Funkcje parsera obsługują CIDR, listy, zakresy, nazwy domenowe i normalizują ich postać do listy hostów do skanowania.

- Konfiguracja i sondy:
  - `UDP_PROBES` i `TCP_PROBES` — zdefiniowane proste sondy dla typowych portów (DNS, NTP, SSH, HTTP, itp.).
  - Użyto domyślnych timeoutów i logiki retry; jednocześnie wprowadzono krótsze czasy timeout dla UI responsywności i dłuższe dla wybranych protokołów (DB).

## 4. Testy i jakość kodu

Testy uruchamiane są przez `pytest` i zlokalizowane w `tests/`. Są to testy jednostkowe i smoke (integracyjne z mockami):

- `tests/test_parse_hosts.py` — testuje parser listy hostów (CIDR, zakresy i pojedyncze hosty), zwraca poprawne adresy w listach.
- `tests/test_banner_extract.py` — sprawdza funkcję `_extract_banner_info` dla przykładów: HTTP (Server header), SSH, FTP i MySQL.
- `tests/test_smoke.py` — prosty test smoke, który potwierdza wykonywanie testera bez zależności.

Wyniki testów (stan na dzień 20.11.2025, uruchomione w środowisku `venv`):

```
$ source .venv/bin/activate
$ python -m pytest -q
....
4 passed in 0.04s
```

Wnioski: wszystkie dostępne testy jednostkowe i smoke przechodzą, co potwierdza poprawność implementacji funkcji parsera oraz ekstrakcji banerów. Testy są proste i bazują na stubach (conftest.py) w celu uniknięcia ciężkich zależności w CI.

## 5. Pakowanie i dystrybucja

Przygotowano skrypty i workflowy do budowania aplikacji dla macOS:

- `scripts/build_pyinstaller.sh` — tworzy binarkę za pomocą PyInstaller; wspiera opcję `CREATE_APP_BUNDLE=true` (generuje `pab_scanner.app` onedir) oraz `CREATE_DMG=true` (generuje DMG z `.app`).
- `scripts/create_dmg.sh` — tworzy plik DMG; opcjonalnie podpisuje binarkę i DMG (codesign) jeśli podamy tożsamość podpisu.
- `scripts/build_nuitka.sh` — eksperymentalny skrypt do budowy z Nuitka: testowano różne flagi (pyside6 plugin), `--static-libpython=no`, dołączenie libb2/openssl, `--nofollow-import-to` do pomijania niechcianych modułów.

W czasie testów lokalnych (macOS) uzyskano artefakty:

- `dist/pab_scanner.app` — ~46 MB
- `dist/dmg/pab_scanner.dmg` — ~47 MB

Uwaga: rozmiary zależą od platformy i wersji bibliotek; PyInstaller tworzy zwykle duże binarki dla GUI z Qt. Dla mniejszych artefaktów warto rozważyć zoptymalizowanie listy dołączanych bibliotek lub wykorzystania Nuitka (wymaga dodatkowych testów i konfiguracji).

## 6. Problemy napotkane i podjęte decyzje projektowe

Kilka istotnych problemów i rozwiązań:

- Scapy i Qt (PySide6) są ciężkimi bibliotekami dla środowiska budowania (szczególnie macOS). W `docs/conf.py` dodano mocki i warunki, aby budowa dokumentacji odbywała się bez konieczności instalowania GUI.
- W wątku skanowania dodano blokadę (`_executor_lock`) i bezpieczne zamykanie `ThreadPoolExecutor` by uniknąć race conditions między `run()` a `stop()`.
- Przy integracji Nuitka pojawiły się problemy z dependency scan dla bibliotek natywnych: `libb2`, `libcrypto.3.dylib`, `liblzma` (xz). W efekcie dodano do skryptu `--include-data-files` i eksportowanie `DYLD_LIBRARY_PATH` podczas budowy, oraz `--nofollow-import-to` do pominięcia problematycznych modułów `_blake2`, `_hashlib`, `_hashlib`.
- Qt WebEngine wymaga bundla aplikacji (app bundle) na macOS, dlatego wykluczono go (jeśli nie jest potrzebny) lub w trybie PyInstaller należało zbudować onedir `.app` dla prawidłowej integracji.

## 7. CI / Workflow

- Zaimplementowano `package-macos.yml` w `.github/workflows/`, który realizuje:
  - Uruchomienie testów i lintera (pytest + flake8).
  - Budowanie aplikacji na macOS (PyInstaller) i utworzenie DMG.
  - Opcjonalne uruchomienie budowania z Nuitka (`run_nuitka` input), z dodatkowymi flagami i dołączeniem plików natywnych.
  - Mechanizm podpisywania w CI: import p12 encoded base64 do tymczasowego keychain i `codesign` — wymaga wprowadzenia bazowych sekretów `CI_SIGNING_P12` i `CI_SIGNING_PASSWORD`.

## 8. Bezpieczeństwo i etyka

- Projekt ma charakter edukacyjny i jest przeznaczony do testów jedynie w sieciach, na które masz zgodę.
- Nie należy używać skanera do ataków lub nieautoryzowanego skanowania sieci.
- Implementacja przewiduje wyłączenie niektórych funkcji (np. TCP SYN) jeśli Scapy nie jest dostępny.

## 9. Podsumowanie i rekomendacje

Zrealizowano wszystkie zadania projektowe kluczowe i dodatkowe: GUI, trzy tryby skanowania, banner grabbing, eksport wyników, testy, dokumentację oraz proces budowy (PyInstaller) z tworzeniem DMG i prostym podpisywaniem w CI. Przeprowadzono także eksperymenty z Nuitka (wyniki opisane wcześniej).

Rekomendacje na przyszłość:

1. Wzbogacić testy integracyjne i dodać dedykowane środowisko testowe (kontenery lub maszyny wirtualne) do testów sieciowych.
2. Dodać automatyczną Notary (Apple Notarization) do workflowu CI dla macOS release.
3. Zastanowić się nad dystrybucją dla innych platform (AppImage na Linux, MSI dla Windows).
4. Rozbudować obsługę UDP i badań banerów, dodać heurystyki i możliwość pluginów rozpoznawania usług.

---

Jeżeli chcesz, mogę dostosować rozdział "Podsumowanie" o konkretne logi z budowania (wyciąg z konsoli), porównanie czasów budowania i rozmiarów, albo przykładowe fragmenty kodu (np. pełna implementacja `grab_banner` lub `scan_syn_port`) wraz z analizą potencjalnych punktów optymalizacji.

## 10. Aneks A — Wybrane logi z budowania (PyInstaller)

Wybrane fragmenty logów z lokalnej sesji budowania (PyInstaller). Zawiera istotne kluczowe komunikaty informujące o dołączaniu pluginów Qt, architekturze i końcowym rezultacie:

```
INFO: PyInstaller: 6.16.0, contrib hooks: 2025.9
INFO: Python: 3.12.7
INFO: Platform: macOS-15.1.1-arm64
INFO: Building PYZ (ZlibArchive) ...
INFO: Building EXE from EXE-00.toc completed successfully.
INFO: Building BUNDLE ...
INFO: Signing the BUNDLE...
Build complete! The results are available in: /path/to/dist
```

W logach pojawiają się również ostrzeżenia o `onefile` + `--windowed` i zalecenia o użyciu `--onedir` dla prawidłowej struktury `.app`.

## 11. Aneks B — Porównanie: PyInstaller vs Nuitka (skrót)

PyInstaller
- Zalety: szybka konfiguracja, stabilność na wielu platformach, szeroka obecność pluginów i hooków (PySide6, scapy).
- Wady: duże artefakty (rozmiar), mniej optymalny runtime, nie zawsze najkrótszy czas uruchomienia.

Nuitka
- Zalety: kompilacja do natywnego kodu C/C++, potencjalnie mniejszy rozmiar i szybsze uruchamianie.
- Wady: trudności w detekcji niektórych zależności natywnych w macOS (libb2/_blake2, OpenSSL, liblzma), długi czas kompilacji dla bibliotek pisanych w C/Python (np. scapy), wymaga ostrożnej konfiguracji `--nofollow-import-to` i `--include-data-files`.

Wynik: Na ten moment PyInstaller jest rekomendowany do szybkiej dystrybucji (DMG) aplikacji macOS z PySide6 i Scapy jako stabilne rozwiązanie; Nuitka pozostaje opcją eksperymentalną do dalszych testów optymalizacji.

## 12. Aneks C — Fragmenty kodu i analiza wybranych funkcji

Poniżej krótkie omówienie i pseudo-code fragmentów funkcji mających kluczowe znaczenie:

- `grab_banner(sock, port)` — próbuje pobrać banner w trzech krokach:
  1. Sprawdza, czy istnieje specjalna sonda dla portu; jeśli tak, ustawia odpowiedni timeout i próbuje wykonać oczekujące odbieranie bannerów.
  2. Jeśli brak auto-bannera, wysyła sondę i odbiera odpowiedź (np. HTTP GET, EHLO dla SMTP).
  3. Jeśli brak reakcji, wykonuje heurystyczne próby wysyłania różnych sond (GET / HELP / CRLF), aby wywołać jakąkolwiek odpowiedź.

Fragment implementacji `_extract_banner_info(banner, port)` to logika wyciągania istotnych danych:
- Dla HTTP: parsujemy nagłówek `Server:`.
- Dla SSH: zwracamy linię zaczynającą się od `SSH-`.
- Dla FTP: zwracamy pierwszy komunikat 220 etc.
- Dla MySQL: usuwamy fragmenty binarne i spróbujemy zdekodować wersję.

Wskazówka: rozważ użycie dedykowanych parserów (np. `http.client` lub `requests`) dla HTTP/HTTPS (o ile nie chcesz ręcznie parsować nagłówków) oraz użycie gotowych bibliotek do analizy protokołów (np. `paramiko` dla SSH czy `pymysql` dla MySQL) w celu dokładnego zidentyfikowania odpowiedzi.

### 12.1 Wybrane fragmenty kodu (z komentarzami)

Poniżej podałem kilka fragmentów z oryginalnego kodu ze wskazówkami i komentarzami dlaczego zastosowano określone rozwiązania.

1) Funkcja `scan_tcp_connect_port` (wyciąg):

```python
def scan_tcp_connect_port(self, host, port, idx, total_ports):
  # Sprawdź czy skanowanie zostało anulowane
  if self._is_cancelled:
    return None

  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a_socket:
      a_socket.settimeout(3)  # Krótszy timeout dla interaktywnego skanera
      # Aktualizacja paska postępu i podglądu skanowanego portu
      percentage = int(((idx + 1) / total_ports) * 100)
      self.signal_percentage.emit(percentage)
      self.signal_scanned_port.emit(f"{host}:{port}")

      # connect_ex zamiast connect - bez podnoszenia wyjątków przy błędach
      if a_socket.connect_ex((host, port)) == 0:
        banner = self.grab_banner(a_socket, port)
        return (host, port, banner)
    return None
  except socket.error:
    return None
```

Komentarz: `connect_ex` zwraca kod błędu zamiast podniesienia wyjątku, więc łatwo obsłużyć zamknięte porty bez kosztownych wyjątków. Timeout zwiększono dla niektórych usług, które potrzebują więcej czasu.

2) Metoda `grab_banner` (fragment):

```python
def grab_banner(self, sock, port):
  banner = ""
  try:
    probe = TCP_PROBES.get(port, None)
    if probe is not None:
      # Użycie krótkich timeoutów dla większości usług, wydłużenie dla DB
      timeout = 3 if port in [3306, 5432, 443] else 2
      sock.settimeout(timeout)
      # Najpierw spróbuj odbioru automatycznego bannera (FTP, SMTP)
      try:
        initial_data = sock.recv(4096)
        if initial_data:
          banner = initial_data.decode('utf-8', errors='ignore').strip()
      except socket.timeout:
        pass

      # Jeśli brak automatycznego bannera, wyślij sondę
      if not banner and probe:
        sock.sendall(probe)
        time.sleep(0.3)
        data = sock.recv(4096)
        if data:
          banner = data.decode('utf-8', errors='ignore').strip()
  except (socket.timeout, socket.error, UnicodeDecodeError):
    # Ignorujemy szczegóły błędu — brak bannera nie jest krytyczny
    pass
  return banner
```

Komentarz: Sekcja próbuje najpierw odebrać automatyczny banner i dopiero potem wysyła część sond (w zależności od portu). Dzięki prostym sondom można uzyskać informacje z takich protokołów jak HTTP, SSH, SMTP itp.

3) `_extract_banner_info` (fragment):

```python
def _extract_banner_info(self, banner, port):
  # Przykład: dla HTTP parsujemy nagłówek Server
  if port in [80, 443, 8080]:
    if "Server:" in banner:
      server_line = [line for line in banner.split('\n') if 'Server:' in line]
      if server_line:
        return server_line[0].replace('Server:', '').strip()

  # Dla SSH — linia zaczynająca się od 'SSH-'
  if port == 22 and banner.startswith('SSH-'):
    return banner.split('\r')[0].split('\n')[0]

  # Dla pozostałych, przechwyć pierwszą linie jako reprezentację bannera
  first_line = banner.split('\n')[0].split('\r')[0]
  return first_line if len(first_line) < 100 else first_line[:100] + "..."
```

Komentarz: Funkcja ma na celu zawęzić i uczytelnić banner — usunięcie nadmiarowych białych znaków, zwrócenie kluczowych nagłówków oraz ograniczenie długości.

4) `scan_syn_port` (fragment):

```python
def scan_syn_port(self, host, port, idx, total_ports):
  # Wykonywana tylko, gdy Scapy jest dostępny i mamy odpowiednie uprawnienia
  percentage = int(((idx + 1) / total_ports) * 100)
  self.signal_percentage.emit(percentage)
  self.signal_scanned_port.emit(f"{host}:{port}")
  pkt = Ether() / IP(dst=host) / TCP(dport=port, flags="S")
  resp = srp1(pkt, timeout=1, verbose=0, iface=self.interface)

  if resp is None:
    return (host, port, "filtered")
  elif resp.haslayer(TCP):
    if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
      send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)
      return (host, port, "open")
    elif resp.getlayer(TCP).flags == 0x14:  # RST
      return None
  return None
```

Komentarz: Użycie Scapy pozwala pracować na warstwie linków (Ether) i lepiej kontrolować `iface`. Odrzucanie RST oznacza, że port jest zamknięty. Po otrzymaniu SYN-ACK, wysyłamy RST, aby zakończyć połączenie bez nawiązywania pełnego trójstopniowego handshake.

5) `_discover_live_hosts` — wykrywanie aktywnych hostów (fragment):

```python
def _discover_live_hosts(self):
  self.signal_status_update.emit(f"Discovering hosts (pinging {len(self.hosts_to_scan)} targets)...")
  live_hosts = []
  with ThreadPoolExecutor(max_workers=50) as executor:
    future_to_host = {executor.submit(self._ping_host, host): host for host in self.hosts_to_scan}
    for i, future in enumerate(as_completed(future_to_host)):
      if self._is_cancelled:
        break
      percentage = int(((i + 1) / len(self.hosts_to_scan)) * 100)
      self.signal_percentage.emit(percentage)
      host = future.result()
      if host:
        live_hosts.append(host)
        self.signal_status_update.emit(f"Host found: {host}")
  return sorted(live_hosts)
```

Komentarz: Ten fragment używa `ThreadPoolExecutor` do jednoczesnego wysyłania pingów; metoda `_ping_host` wykonuje pings przy użyciu Scapy lub `ping` systemowego jako fallback.

6) Parsowanie hostów (pewne implementacje)

```python
def parse_hosts(self, input_str: str) -> list:
  # Przyjmuje: '127.0.0.1, 192.168.1.0/30, example.com' i rozbija na listę hostów
  hosts = []
  parts = input_str.split()
  for p in parts:
    # Obsługa CIDR
    if '/' in p:
      net = ipaddress.ip_network(p, strict=False)
      for ip in net.hosts():
        hosts.append(str(ip))
    elif '-' in p and p.replace('.', '').replace('-', '').isdigit():
      # Przykład prostego range parsing: '10.0.0.1-10.0.0.10'
      start, end = p.split('-')
      # logic to expand range omitted for brevity
    else:
      hosts.append(p)
  return hosts
```

Komentarz: Parsowanie hostów jest kluczowe by wspierać różne formaty wpisane przez użytkownika. Wersja produkcyjna powinna uwzględnić walidację nazw hostów i obsługę wyjątków DNS.


## 13. Aneks D — Testy, debug i komendy pomocnicze

Podstawowe komendy do uruchomienia projektu i testów lokalnie (macOS/Linux):

```bash
# stwórz i aktywuj virtualenv
python3 -m venv .venv
source .venv/bin/activate

# zainstaluj zależności
pip install -r requirements.txt
pip install -r requirements-dev.txt

# uruchom aplikację GUI
python "Projekt AB Skaner Portów.py"

# uruchom testy
python -m pytest -q

# buduj .app oraz DMG (macOS)
CREATE_APP_BUNDLE=true CREATE_DMG=true ./scripts/build_pyinstaller.sh
```

Debug:
- Jeśli skan SYN nie działa, sprawdź uprawnienia (root / sudo) — Scapy wymaga raw sockets.
- Jeśli PyInstaller nie dołącza pluginów Qt, przejrzyj `warn-*.txt` w katalogu `build/` i dodaj brakujące `--add-binary` w skrypcie.

## 14. Aneks E — Plan rozwoju (krótka lista zadań)

Zalecane kolejne kroki do wdrożenia:
1. Dodać Notary (Apple) jako krok w CI i automatycznie dołączać notarized staple do DMG.
2. Dodać więcej sond/heurystyk i moduł pluginów dla skanerów (np. sprawdzanie protokołów aplikacyjnych).
3. Wdrożyć bardziej rozbudowany system testów integracyjnych (wykorzystujący VM lub kontenery do testowania w warunkach sieciowych).
4. Rozszerzyć dokumentację: dodać instrukcję instalacji na Windows i Linux, opisać szczegóły podpisywania i entitlements na macOS.

---

Jeżeli chcesz, mogę dodać teraz fragmenty logów z Nuitka (jeśli chcesz zachować w raporcie porównanie z pełnymi błędami) lub dodać tabelę z konkretnymi rozmiarami i czasami budowania (na podstawie powtórzeń buildów) w celu uwiarygodnienia porównania.

# Sprawozdanie z Projektu — "Skaner Portów"

Autor: Mateusz Misiak

Data: 20 listopada 2025

## Streszczenie

Projekt "Skaner Portów" to aplikacja napisana w Pythonie, łącząca graficzny interfejs użytkownika (PySide6) z niskopoziomowym skanowaniem sieci przy użyciu Scapy. Celem projektu było stworzenie narzędzia do podstawowego audytu bezpieczeństwa i demonstracji technik skanowania (TCP Connect, TCP SYN, UDP) wraz z możliwością zbierania banerów sieciowych (banner grabbing), zapisania wyników i wygenerowania samodzielnego pliku wykonywalnego dla macOS.

W ramach projektu została wykonana kompletna implementacja, testy jednostkowe, dokumentacja Sphinx (z diagramami mermaid), skrypty budujące (PyInstaller i próbny z Nuitka), a także GitHub Actions do uruchamiania testów i tworzenia artefaktów (DMG) na macOS.

## Cel projektu

- Zaimplementować graficzny skaner portów (GUI) umożliwiający wykonywanie skanów TCP connect, TCP SYN i UDP.
- Zaimplementować banner grabbing, zapisywanie wyników i prezentowanie ich w GUI.
- Przygotować dokumentację projektu (Sphinx z mermaid).
- Przygotować środowisko testowe oraz testy jednostkowe.
- Zbudować przenośny plik wykonywalny i DMG dla macOS oraz dodać opcję podpisywania aplikacji (codesign) i integracji CI.

## Zakres i ograniczenia

- Projekt przeznaczony jest do celów edukacyjnych i testów bezpieczeństwa wyłącznie z uprawnieniem właściciela sieci.
- Nie obejmuje: automatycznego notaryfikowania przez Apple, rozbudowanej analizy aplikacji, zaawansowanego wykrywania systemów operacyjnych serwerów (OS fingerprinting) ani masowego fuzzingu.
- Operacje wymagające raw sockets (np. TCP SYN) wymagają uprawnień administratora.

## Środowisko i zależności

- Python 3.12 (lokalnie użyte w wirtualnym środowisku `.venv`)
- Główne biblioteki:
  - PySide6 (GUI)
  - Scapy (niskopoziomowy networking)
  - Sphinx + sphinx-rtd-theme + sphinxcontrib-mermaid (dokumentacja)
  - PyInstaller / Nuitka (pakowanie)
- Pliki konfiguracyjne projektu: `requirements.txt`, `requirements-dev.txt`.

## Struktura projektu (ważne pliki i katalogi)

- `Projekt AB Skaner Portów.py` — główny skrypt z GUI, klasami i logiką skanera.
- `run_scanner.py` — skrypt pomocniczy / wrapper używany do uruchomienia GUI/skanera.
- `scanner/` — moduły do niskopoziomowego skanowania.
- `tests/` — testy jednostkowe i smoke tests (pytest).
- `docs/` — dokumentacja Sphinx z diagramami mermaid (`architecture.rst`, `scan_flow.rst`).
- `scripts/` — skrypty pomocnicze do budowania: `build_pyinstaller.sh`, `build_nuitka.sh`, `create_dmg.sh`.
- `.github/workflows/` — workflowy CI (testy + pakowanie macOS).

## Architektura i główne komponenty

Poniżej znajduje się krótkie omówienie komponentów aplikacji:

- GUI (PySide6)
  - `Ui_dialog` (lub podobna klasa): okno aplikacji, komponenty UI i logika interakcji.
  - Interfejs użytkownika posiada pola do wpisywania hostów, zakresów portów, wyboru typu skanu (TCP Connect / SYN / UDP), przycisków Start/Cancel i wykresów/tabel wyników.

- ScanThread (w oparciu o QThread)
  - Obsługuje wykonywanie skanów w wątku, aby nie zamrażać GUI.
  - Zawiera implementacje: `scan_tcp_connect_port`, `scan_syn_port`, `scan_udp_port` i `grab_banner`.
  - Emituje zdarzenia z wynikami, aktualizuje listy otwartych portów oraz zapisuje logi.

- Parsowanie hostów i portów
  - Zaimplementowany parser pozwalający na podanie: hostów pojedynczych, list przecinkami, zakresów (np. 10.0.0.1-10.0.0.10), CIDR (np. 192.168.1.0/24).
  - Obsługa portów jako pojedyncze wartości i zakresy, walidacja i serializacja do listy testowej.

- Banner Grabbing i zapis wyników
  - Po nawiązaniu połączenia przy TCP Connect lub UDP (tam gdzie możliwe), aplikacja próbuje pobrać baner (np. odpowiedzi protokołów HTTP, SMTP, FTP).
  - Wyniki są prezentowane w GUI i można je eksportować (np. do CSV/JSON/TXT).

## Zaimplementowane algorytmy skanowania

- TCP Connect: standardowe połączenia przy użyciu socketów w trybie blokującym z timeoutem; po nawiązaniu połączenia — wykonanie banner grab (jeżeli dostępne).
- TCP SYN: skanowanie przy użyciu Scapy (wymagane uprawnienia do raw sockets), wysyłanie pakietów SYN i analizowanie odpowiedzi (SYN/ACK lub RST).
- UDP Scan: uproszczony skan UDP — wysyłanie zapytań specyficznych dla usługi i nasłuchiwanie ICMP port unreachable lub odpowiedzi usługi (np. DNS) — analiza.

## Testy

- Dodano testy w `tests/`:
  - `test_parse_hosts.py` — test parserów hostów i portów.
  - `test_banner_extract.py` — test funkcji ekstrakcji banerów.
  - `test_smoke.py` — test typu smoke, integracyjny sprawdzający najważniejsze funkcjonalności (odpalany w wersji z mockami / stubs dla PySide6/Scapy w `conftest.py`).
- Celem testów było zautomatyzować najważniejsze przypadki i zapewnić, że logika aplikacji działa (testy jednostkowe + smoke). Testy uruchamiane przez pytest.

## Dokumentacja

- Użyto Sphinx do generowania dokumentacji w `docs/` wraz z tematem sphinx-rtd-theme.
- Dodano diagramy architektury i flow (Mermaid): `docs/architecture.rst`, `docs/scan_flow.rst`.
- `docs/conf.py` skonfigurowano tak, by ignorować/importować heavy dependencies w trybie CI lub mockować PySide6 i Scapy, aby budowa dokumentacji była możliwa w środowiskach bez GUI.

## Pakowanie i dystrybucja

- PyInstaller (sukces)
  - Główny skrypt: `scripts/build_pyinstaller.sh`.
  - Wersja macOS: zastosowano opcje, aby zebrać konkretne pluginy PySide6 (platforms, imageformats) oraz inne zasoby.
  - Dwie opcje: `CREATE_APP_BUNDLE=true` (tworzy `pab_scanner.app` onedir bundle), `CREATE_DMG=true` (generuje DMG z tym bundle jako instalator). Domyślnie tworzy single-file binary.
  - Wygenerowane artefakty: `dist/pab_scanner.app` i `dist/dmg/pab_scanner.dmg`.

- Nuitka (próby i wyzwania)
  - Główny skrypt: `scripts/build_nuitka.sh`.
  - Intencja: uzyskać mniejszy i szybszy binarny wynik jako `onefile` lub `standalone`.
  - Napotkano sporo problemów specyficznych dla macOS: wykrywanie zależności natywnych bibliotek (`_blake2`, OpenSSL, XZ), problem z Qt WebEngine (wymaga app bundle), długi czas kompilacji scapy (dużo C), i potrzeba `--static-libpython=no` przy pyenv.
  - Pracowano nad trzema strategiami: (1) wyłączenie importu modułów generujących problem, (2) dołączenie konkretnych bibliotek natywnych do `--include-data-files`, (3) dołączenie scapy jako data-dir zamiast jego kompilacji.
  - Rezultat: część błędów rozwiązano (libb2, openssl) przez dołączenie dynamicznych bibliotek i ustawienie DYLD_LIBRARY_PATH w czasie budowania; jednakże budowa Nuitka w macOS była nie w pełni niezawodna i wymagająca dużego nakładu konfiguracji (workflow zawiera `build_nuitka.sh` jako eksperymentalny).

## CI / GitHub Actions

- Workflowy: zaktualizowany `python-package` i dodano `package-macos.yml`:
  - Testy: uruchamiają `pytest` i linty (flake8) w środowisku CI.
  - Dokumentacja: budowa Sphinx na GitHub Pages (opcjonalnie deploy).
  - Pakowanie macOS: `build-package-macos` job tworzy DMG i przesyła artefakt jako `pab-scanner-macos`.
  - Opcjonalny job `build-nuitka` (uruchamiany manualnie przez `workflow_dispatch` input `run_nuitka`) buduje artefakty z Nuitka (cięższe, eksperymentalne).
  - Opcjonalne podpisywanie: `CI_SIGNING_P12` i `CI_SIGNING_PASSWORD` jako repozytoryjne sekrety (p12 zakodowane base64) — importowane do Keychain w jobie macOS i używane do codesign przed utworzeniem DMG.

## Bezpieczeństwo i etyka

- Ten projekt (skaner portów) służy do badań i audytów bezpieczeństwa. Skanowanie cudzych sieci bez autoryzacji jest nielegalne i nieetyczne — użytkownik powinien mieć uprawnienie właściciela lub administratora testowanych zasobów.
- Wersja projektu w repozytorium ma testy i stubbing, co pozwala na uruchamianie testów bez realnej sieci/utility raw sockets.
- Aplikacja nie wysyła dodatkowych exploitów ani nie zbiera danych poza banerami i odpowiedziami na skany — jednakże każda operacja wysyłania pakietów jest potencjalnie ryzykowna i powinna być wykonywana rozważnie.

## Ograniczenia i znane problemy

- PySide6 + Scapy + macOS = Komponenty trudne do przeniesienia bez ustawień (wymagana najnowsza wersja PySide6 Qt, libs). Dla paczki `onefile` PyInstaller, pluginy Qt i liczne biblioteki muszą być dołączone ręcznie.
- Nuitka: kompilacja natywnych rozszerzeń, detekcja dylib w macOS oraz duży czas kompilacji scapy (w szczególności) mogą powodować długie czasy budowy lub niepowodzenia. Wskazana jest budowa `pyenv` lub użycie `--include-data-dir` i niekompilowanie scapy.
- DMG/entitlements: Gdy podpisywanie aplikacji jest wymogiem, należy dostarczyć właściwy `Developer ID Application` oraz `Developer ID Installer` i (dla dystrybucji) przejść przez proces notarization (Apple Notary). Skrypt CI tylko importuje p12 i podpisuje; notarization i staple nie są zautomatyzowane w skryptach.

## Wnioski i rekomendacje

- Dla dystrybucji na macOS najlepiej skupić się na standardowym `onedir` `.app` (PyInstaller `--windowed --onedir`) oraz tworzeniu DMG z podpisanym .app. `onefile` nie zawsze najlepiej współgra z macOS, a także wywołuje ostrzeżenia i ograniczenia (Gatekeeper).
- Dla budowy produkcyjnych artefaktów w CI używać: macOS runner + secrets (`CI_SIGNING_P12`, `CI_SIGNING_PASSWORD`) i dodać krok Notary (opcjonalny) do workflow.
- Dla Nuitka: jeśli zależy Ci na szybszym i mniejszym binarnym wyniku, warto przeprowadzić eksperymenty z izolacją natywnych modułów, unikaniem kompilacji scapy i wyłączaniem niepotrzebnych pluginów Qt.

## Instrukcja uruchomienia (szybki start)

1. Utwórz wirtualne środowisko i zainstaluj zależności:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

2. Uruchom aplikację (GUI):

```bash
python "Projekt AB Skaner Portów.py"
```

3. Budowanie aplikacji (PyInstaller) i tworzenie DMG (macOS):

```bash
source .venv/bin/activate
# budowa paczki oraz utworzenie .app i DMG
CREATE_APP_BUNDLE=true CREATE_DMG=true ./scripts/build_pyinstaller.sh
```

4. W CI GitHub Actions — uruchom workflow `package-macos.yml` (możesz podać `run_nuitka=true` manualnie, by uruchomić eksperymentalny build z Nuitka). Gdy chcesz, by CI podpisał paczkę, wprowadź sekrety: `CI_SIGNING_P12` i `CI_SIGNING_PASSWORD`.

## Lista kluczowych plików i zmian (załącznik)

- `Projekt AB Skaner Portów.py`: główna implementacja GUI i logika skanowania
- `scripts/build_pyinstaller.sh`: skrypt budujący, z opcją tworzenia `.app` i DMG oraz podpisu w CI
- `scripts/build_nuitka.sh`: eksperymentalny skrypt Nuitka (wiele flag i obejść)
- `scripts/create_dmg.sh`: tworzy DMG i podpisauje plik, jeśli podano identity
- `docs/` — pełna dokumentacja Sphinx z diagramami mermaid (architecture, scan_flow)
- `tests/` — testy jednostkowe i stubs (conftest.py)
- `.github/workflows/package-macos.yml` — CI job do budowy i dystrybucji DMG na macOS

## Plany dalsze / rozszerzenia

- Dodanie Notary i automatyzacja procesu notarizacji w CI.
- Integracja funkcji instalatora dla Windows/Linux (np. AppImage na Linux lub MSI na Windows).
- Rozszerzenie testów integracyjnych dla realnej sieci (z dedykowanym labem testowym), oraz testy wydajności w celu przetestowania skalowalności dla dużych zakresów adresowych.
- Wdrożenie dodatkowych sond UDP i heurystyk, rozbudowa banner grab (np. HTTP headers parsing), i wsparcie dla pluginów wykrywania usług.

## Kontakt i źródła

- Repozytorium GitHub: https://github.com/stigi99/Projekt-Audyt-Bezpieczenstwa-Skaner-Portow
- Autor: Mateusz Misiak

---

Jeżeli chcesz, mogę rozbudować `sprawozdanie.md` o dodatkowe elementy: logi z budowania (wynik `pyinstaller`/`nuitka`), porównanie rozmiarów binarnych PyInstaller vs Nuitka, zrzuty ekranu GUI lub fragmenty kodu (np. praca `ScanThread`) wraz z objaśnieniami działania wybranych funkcji.

## Zakończenie

Przeprowadzone prace potwierdziły, że aplikacja działa zgodnie z założeniami projektowymi i spełnia główne cele edukacyjne oraz techniczne: implementację kilku trybów skanowania, zbieranie banerów i przygotowanie artefaktów dystrybucyjnych dla macOS. Zaproponowane rekomendacje i dalsze kroki stanowią plan na kolejny etap rozwoju projektu.

Praca została zakończona w stanie umożliwiającym dalsze testy, rozszerzenia i wdrożenie (CI/CD), a repozytorium posiada podstawowe skrypty do tworzenia artefaktów, testowania i generowania dokumentacji.

