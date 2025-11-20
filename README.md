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

