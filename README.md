# (Tasks section moved)
# Projekt: Audyt Bezpieczeństwa — Skaner Portów

Lekki graficzny skaner portów napisany w Pythonie z wykorzystaniem PySide6 (GUI) oraz Scapy do niskopoziomowego skanowania sieci.

To narzędzie umożliwia podstawowe skanowanie TCP/UDP oraz zbieranie banerów dla usług (banner grabbing). Przeznaczone jest do użytku edukacyjnego i testów bezpieczeństwa tylko z uprawnieniem właściciela sieci.

## Wersja
- Stan projektu: wersja robocza / projekt dyplomowy

## Główne funkcje
- GUI oparte na PySide6 (Qt)
- TCP Connect scan (z banner grabbing)
- TCP SYN scan (wymaga uprawnień root/administrator i Scapy)
- UDP scan z sondowaniem specyficznym dla usługi (np. DNS)
- Autofilter wyników i zapis wyników do TXT/CSV/JSON
- Wybór interfejsu sieciowego i opcje opóźnienia między zapytaniami

## Wymagania
- Python 3.10+ (zalecane 3.11)
- PySide6 (GUI)
- Scapy (niskopoziomowe wysyłanie pakietów i sniffing)
- Dopuszczalnie: uprawnienia administratora/root do wykonywania skanów RAW (TCP SYN, UDP) przy użyciu Scapy

Zalecane zależności (plik `requirements.txt`):
```
PySide6>=6.5
scapy>=2.4.5
```

## Instalacja (szybki start)
1. Sklonuj repozytorium:

```bash
git clone https://github.com/stigi99/Projekt-Audyt-Bezpieczenstwa-Skaner-Portow.git
cd Projekt-Audyt-Bezpieczenstwa-Skaner-Portow/PROJEKT\ AB\ FINAL
```

2. Utwórz i aktywuj środowisko wirtualne (opcjonalne lecz zalecane):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Zainstaluj zależności:

```bash
python -m pip install -r requirements.txt
```

> Uwaga (macOS/Unix): aby Scapy mogło korzystać z surowych gniazd, do testów SYN/UDP może być konieczne uruchomienie aplikacji jako root (`sudo`) lub przyznanie uprawnień. Zamiast instalować pakiet globalne, użyj środowiska wirtualnego i jedynie uruchom skrypt z `sudo` jeśli chcesz wykonać skanowanie wymagające uprawnień.

## Uruchamianie

- GUI:
```bash
python "Projekt AB Skaner Portów.py"
```

- Opis zachowania:
  - `TCP Connect` — standardowe połączenia TCP, pobiera baner usługi (jeśli dostępny)
  - `TCP SYN Scan` — szybsze skanowanie, wymaga uprawnień administratora (raw sockets)
  - `UDP Scan` — skanowanie UDP wykorzystujące sondy specyficzne i interpretację ICMP

W GUI można: wybrać typ skanowania, wprowadzić hosty (lista, zakresy, CIDR), porty (pojedyncze, zakresy), interfejs, opóźnienie i zapisać wyniki.

## Screenshots

Przykładowe zrzuty ekranu interfejsu i wyników znajdują się w folderze dokumentacji:

- `docs/_static/screenshots/scan_gui.svg` — główne okno GUI z polami do wprowadzania hostów/portów
- `docs/_static/screenshots/scan_results.svg` — tabela wyników i podgląd banerów

Docs online: If GitHub Pages is enabled for this repository docs are available under `https://stigi99.github.io/Projekt-Audyt-Bezpieczenstwa-Skaner-Portow` (may take a few minutes after first push to `main` for the workflow to populate `gh-pages`).


Możesz zastąpić te pliki swoimi zrzutami ekranu (formatu SVG/PNG) w katalogu `docs/_static/screenshots`.

## Dokumentacja

Kompletna dokumentacja znajduje się w folderze `docs/` i jest budowana za pomocą Sphinx. Aby wygenerować HTML lokalnie:

```bash
cd docs
make html
```

Następnie otwórz `docs/_build/html/index.html` w przeglądarce.


## Uprawnienia i bezpieczeństwo
- Wykonywanie skanów sieci bez zgody właściciela jest nielegalne i nieetyczne. Używaj tego narzędzia wyłącznie w środowiskach testowych lub z explicitną zgodą.
- Do skanów TCP SYN/UDP Scapy wymagane są uprawnienia root/administrator. W systemach Unix uruchom program jako `sudo` lub ustaw odpowiednie uprawnienia.

## Debug i typowe problemy
- Jeśli VS Code nie wykrywa `PySide6` lub `scapy`, upewnij się, że wybrany interpreter to ten, w którym zainstalowałeś pakiety (`Python: Select Interpreter`).
- Na macOS sprawdź, czy masz zainstalowane narzędzia deweloperskie (Xcode Command Line Tools) — `xcode-select --install`.
- Jeśli skanowanie SYN/UDP nie działa, spróbuj uruchomić skrypt jako administrator:

```bash
sudo python "Projekt AB Skaner Portów.py"
```

## Jak zgłaszać błędy / wkład
- Otwarte zgłoszenia (Issues) na repozytorium GitHub
- Pull requesty z ulepszeniami, poprawkami i testami są mile widziane

## Dalsze prace / Pomysły
- Dodanie testów jednostkowych
- Rozszerzenie listy sond dla UDP/TCP
- Lepsza obsługa wykrywania interfejsów i uprawnień
- Eksport wyników do formatu JSON+schema

## Pakowanie / Tworzenie pliku wykonywalnego (PyInstaller / Nuitka)

W repozytorium znajdują się przykładowe skrypty budowania binarki:
- `scripts/build_pyinstaller.sh` — tworzy single-file executable przy użyciu PyInstaller.
- `scripts/build_nuitka.sh` — tworzy stand-alone executable przy użyciu Nuitka.

Przykładowe instrukcje (PyInstaller) — w `.venv`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
./scripts/build_pyinstaller.sh
```

Wyniki (binarka) znajdziesz w katalogu `dist/` (dla PyInstaller) lub `dist_nuitka/` (dla Nuitka).

Uwaga: PySide6 i Scapy to ciężkie biblioteki — PyInstaller może wymagać ręcznego dołączania pluginów Qt i dodatkowych zasobów (np. `--collect-all PySide6`). Na macOS możesz potrzebować również podpisać aplikację lub dodać entitlements, jeśli planujesz dystrybucję.

### Tworzenie DMG i podpisywanie (macOS)

Skrypty buildujące zawierają opcjonalne flagi do tworzenia DMG i podpisywania binarki:

- `CREATE_DMG=true` — utworzy plik .dmg (tylko macOS)
- `CI_SIGNING_P12` (& `CI_SIGNING_PASSWORD`) — przy dostarczeniu w formie sekretów (base64-encoded p12), skrypt zaimportuje certyfikat do tymczasowego Keychain i użyje go do podpisania binarki przed utworzeniem DMG

Przykład lokalnego użycia (macOS, bez podpisywania):

```bash
./scripts/build_pyinstaller.sh
CREATE_DMG=true ./scripts/build_pyinstaller.sh
```

Przykład uruchamiania w CI (GitHub Actions) — z importem certyfikatu p12 do Keychain i podpisaniem binarki:

1. Zaszyfruj/zakoduj plik p12 jako base64 (na lokalnej maszynie):

```bash
base64 my-codesign-cert.p12 > cert.p12.base64
```

2. Dodaj dwa sekrety do repozytorium na GitHub (`Settings > Secrets`):
  - `CI_SIGNING_P12` — skopiuj zawartość `cert.p12.base64`
  - `CI_SIGNING_PASSWORD` — hasło do pliku p12

3. Uruchom workflow/push do `main` — job na macOS zaimportuje p12 i podpisze binarkę/DMG jeśli flagi zostaną ustawione.

Uwaga: aby aplikacja działała poprawnie na macOS, warto też obejrzeć dokumentację Apple dot. entitlements, Notary i zapewnienia zgodności (gatekeeper). Ten projekt zawiera opcję podpisania binarki i DMG. Notary (Apple notarization) nie jest zautomatyzowana w tych skryptach (można rozszerzyć workflow o przesłanie do notarytool).

Jeśli chcesz, mogę sprawdzić i dostosować specyfikację PyInstaller (dodatkowe `--add-data` lub `--hidden-import`) do Twojej konfiguracji i platformy.

## Testy i uruchamianie testów w Visual Studio Code

Jeżeli chcesz uruchamiać testy bezpośrednio w VS Code (Test Explorer, debugowanie):

1. Upewnij się, że środowisko wirtualne jest aktywne i wybrany interpreter to `.venv`:

```bash
source .venv/bin/activate
```

W VS Code: Command Palette -> Python: Select Interpreter -> Wybierz `${workspaceFolder}/.venv/bin/python`.

2. Zainstaluj zależności deweloperskie:

```bash
python -m pip install -r requirements-dev.txt
```

3. Skonfiguruj testy w VS Code (jeżeli jeszcze nie wykryto):

- Otwórz Command Palette (Cmd+Shift+P) -> `Python: Configure Tests` -> wybierz `pytest` -> wskaż folder `tests/`.

4. Test Explorer (po prawej) będzie listował znalezione testy. Możesz uruchomić
  testy z poziomu Test Explorer lub pojedynczy test klikając prawym przyciskiem -> Run Test / Debug Test.

5. Automatyczne wykrywanie testów po zapisaniu pliku zostało włączone (`python.testing.autoTestDiscoverOnSaveEnabled=true`).

6. Debugowanie testów:

- Dla debugowania pojedynczego testu: w Test Explorer -> kliknij `Debug Test` w menu kontekstowym testu.
- Możesz też użyć przygotowanej konfiguracji w `.vscode/launch.json` („Python: Debug Current Test File (pytest)") — ustaw breakpointy i uruchom tę konfigurację.

7. W terminalu (alternatywnie) uruchom testy:

```bash
source .venv/bin/activate
python -m pytest -q
```

8. Jeśli testy nie są wykrywane / nie uruchamiają się, sprawdź ustawienia w `.vscode/settings.json` (interpreter i `pytestPath`) i upewnij się, że `tests/conftest.py` zawiera odpowiednie stuby dla PySide6/Scapy (to pozwala uruchamiać testy bez instalowania ciężkich bibliotek GUI/systemowych).

Zadania (Tasks):

- Dla szybkiego uruchamiania testów i lintera możesz skorzystać z zadań VS Code:
  - `Run tests (pytest)` — uruchamia wszystkie testy.
  - `Run linter (flake8)` — uruchamia linting projektu.
  Otwórz `Terminal -> Run Task...` i wybierz jedno z zadań.



