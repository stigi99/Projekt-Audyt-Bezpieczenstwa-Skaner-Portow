import json
import csv
from PySide6.QtCore import (
    QThread,
    Signal,
    QLocale,
    QRect,
    Qt,
    QMetaObject,
    QCoreApplication,
)
from PySide6.QtGui import QFont, QCursor, QAction
from PySide6.QtWidgets import (
    QTabWidget,
    QLineEdit,
    QWidget,
    QLabel,
    QProgressBar,
    QCommandLinkButton,
    QTextEdit,
    QPushButton,
    QApplication,
    QDialog,
    QSpinBox,
    QMessageBox,
    QFileDialog,
    QComboBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMenu,
    QCheckBox,
)
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import socket
import webbrowser
import logging
import os
import ipaddress
import subprocess
import threading
from scapy.all import get_if_list, Ether

IS_ADMIN = False
try:
    IS_ADMIN = (os.getuid() == 0)
except AttributeError:  # Windows
    import ctypes
    IS_ADMIN = (ctypes.windll.shell32.IsUserAnAdmin() != 0)

# Wyłączenie gadatliwych logów Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import (
        send,
        IP,
        UDP,
        TCP,
        ICMP,
        srp1,
        DNS,
        DNSQR,
        NTP,
        SNMP,
        SNMPget,
        SNMPvarbind,
        ASN1_OID,
        NBNSQueryRequest,
    )
except ImportError:
    # Zmienna globalna informująca o braku Scapy
    SCAPY_AVAILABLE = False
else:
    SCAPY_AVAILABLE = True

UDP_PROBES = {
    53: DNS(rd=1, qd=DNSQR(qname="google.com")),  # Zapytanie DNS
    123: NTP(version=4, mode=3),  # Zapytanie NTP (klient)
    137: NBNSQueryRequest(QUESTION_NAME="*"),  # Zapytanie NetBIOS
    # Zapytanie SNMP
    161: SNMP(community="public", PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))]))
}

# NOWE: Sondy dla banner grabbingu TCP
TCP_PROBES = {
    21: b"",  # FTP - czekaj na banner
    22: b"SSH-2.0-OpenSSH_BannerGrab\r\n",  # SSH
    25: b"EHLO bannergrab.local\r\n",  # SMTP
    80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
    110: b"",  # POP3 - czekaj na banner
    143: b"",  # IMAP - czekaj na banner
    443: b"",  # HTTPS - tylko połączenie
    3306: b"",  # MySQL - czekaj na banner
    5432: b"",  # PostgreSQL - czekaj na banner
}


class ScanThread(QThread):
    signal_percentage = Signal(int)
    signal_scanned_port = Signal(str)
    signal_open_port = Signal(str, str, str)
    signal_end_scan = Signal(int)
    signal_status_update = Signal(str)  # NOWE: Sygnał do aktualizacji statusu

    def __init__(self, scan_type, hosts_to_scan, ports_to_scan, scan_delay_ms, interface, perform_discovery):
        super().__init__()
        self.executor = None
        # <<< BLOKADA: Nowa blokada do synchronizacji dostępu do puli
        self._executor_lock = threading.Lock()
        self.scan_type = scan_type
        self.hosts_to_scan = hosts_to_scan
        self.ports_to_scan = ports_to_scan
        self.scan_delay_ms = scan_delay_ms
        self.interface = interface
        self.perform_discovery = perform_discovery
        self._is_cancelled = False

    def scan_tcp_connect_port(self, host, port, idx, total_ports):
        """Skanuje pojedynczy port TCP Connect, pobiera banner i zwraca (port, banner) lub None."""
        if self._is_cancelled:
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as a_socket:
                # ZMIANA: Zwiększony timeout dla banner grabbingu
                a_socket.settimeout(3)
                percentage = int(((idx + 1) / total_ports) * 100)
                self.signal_percentage.emit(percentage)
                self.signal_scanned_port.emit(f"{host}:{port}")

                if a_socket.connect_ex((host, port)) == 0:
                    banner = self.grab_banner(a_socket, port)
                    return (host, port, banner)
            return None
        except socket.error:
            return None

    def grab_banner(self, sock, port):
        """
        Zaawansowany banner grabbing z obsługą różnych protokołów.
        Próbuje pobrać banner poprzez:
        1. Oczekiwanie na automatyczny banner (FTP, SMTP, POP3, itp.)
        2. Wysłanie specyficznego zapytania dla danej usługi
        3. Wieloetapowe podejście dla protokołów wymagających sekwencji (np. SMTP)
        """
        banner = ""

        try:
            # Sprawdź czy mamy specjalną sondę dla tego portu
            probe = TCP_PROBES.get(port, None)

            if probe is not None:
                # ZMIANA 1: Zwiększony timeout dla portów wymagających więcej czasu
                timeout = 3 if port in [3306, 5432, 443] else 2
                sock.settimeout(timeout)

                # ZMIANA 2: Najpierw spróbuj odebrać automatyczny banner
                try:
                    initial_data = sock.recv(4096)
                    if initial_data:
                        banner = initial_data.decode(
                            'utf-8', errors='ignore').strip()

                        # ZMIANA 3: Dla SMTP, wyślij EHLO i zbierz więcej informacji
                        if port == 25 and probe:
                            sock.sendall(probe)
                            time.sleep(0.3)
                            additional_data = sock.recv(4096)
                            if additional_data:
                                banner += " | " + \
                                    additional_data.decode(
                                        'utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass

                # Jeśli nie otrzymaliśmy automatycznego bannera i mamy sondę, wyślij ją
                if not banner and probe:
                    sock.sendall(probe)
                    time.sleep(0.3)
                    data = sock.recv(4096)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()

            else:
                # ZMIANA 4: Dla nieznanych portów - ulepszona strategia
                sock.settimeout(1.5)

                # Najpierw spróbuj odebrać automatyczny banner
                try:
                    data = sock.recv(2048)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    # ZMIANA 5: Spróbuj różnych sond w kolejności
                    probes_to_try = [
                        b"GET / HTTP/1.0\r\n\r\n",  # HTTP
                        b"\r\n\r\n",  # Ogólny separator
                        b"HELP\r\n",  # Niektóre usługi odpowiadają na HELP
                    ]

                    for test_probe in probes_to_try:
                        try:
                            sock.sendall(test_probe)
                            sock.settimeout(1)
                            data = sock.recv(2048)
                            if data:
                                banner = data.decode(
                                    'utf-8', errors='ignore').strip()
                                break
                        except (socket.timeout, socket.error):
                            continue

            # ZMIANA 6: Ulepszone czyszczenie bannera
            if banner:
                # Usuń nadmierne białe znaki i znaki sterujące
                banner = ' '.join(banner.split())

                # Ogranicz długość bannera do 200 znaków dla czytelności
                if len(banner) > 200:
                    banner = banner[:200] + "..."

                # ZMIANA 7: Wyodrębnij kluczowe informacje z bannerów
                banner = self._extract_banner_info(banner, port)

        except (socket.timeout, socket.error, UnicodeDecodeError) as e:
            logging.debug(f"Banner grab failed for port {port}: {e}")

        return banner

    def _extract_banner_info(self, banner, port):
        """
        Wyodrębnia najważniejsze informacje z bannera.
        """
        # Dla HTTP/HTTPS - wyodrębnij wersję serwera
        if port in [80, 443, 8080]:
            if "Server:" in banner:
                server_line = [line for line in banner.split(
                    '\n') if 'Server:' in line]
                if server_line:
                    return server_line[0].replace('Server:', '').strip()

        # Dla SSH - wyodrębnij wersję
        if port == 22 and banner.startswith('SSH-'):
            return banner.split('\r')[0].split('\n')[0]

        # Dla FTP - wyodrębnij pierwszą linię z kodem odpowiedzi
        if port == 21:
            first_line = banner.split('\n')[0].split('\r')[0]
            return first_line

        # Dla MySQL - wyodrębnij wersję z początkowego bannera
        if port == 3306:
            # MySQL banner zawiera wersję po kilku bajtach binarnych
            try:
                if '\x00' in banner:
                    parts = banner.split('\x00')
                    if len(parts) > 1:
                        return f"MySQL {parts[1]}"
            except Exception:
                # Niepowodzenie podczas parsowania bannera MySQL - ignoruj i zwróć domyślną wartość
                pass

        # Dla pozostałych - zwróć pierwszą linię lub pierwsze 100 znaków
        first_line = banner.split('\n')[0].split('\r')[0]
        return first_line if len(first_line) < 100 else first_line[:100] + "..."

    def _ping_host(self, host):
        """Wysyła pakiet ICMP Echo Request i zwraca hosta, jeśli odpowie."""
        if self._is_cancelled:
            return None

        # Metoda 1: Scapy (szybka, wymaga uprawnień roota)
        try:
            pkt = Ether() / IP(dst=host) / ICMP()
            resp = srp1(pkt, timeout=1, verbose=0, iface=self.interface)
            if resp:
                return host
        except Exception as e:
            # Jeśli Scapy zawiedzie (np. z powodu braku uprawnień), logujemy błąd
            # i przechodzimy do metody 2.
            logging.warning(f"Scapy ping failed for {host}: {e}")

        # Metoda 2: Systemowy ping (wolniejszy, ale nie wymaga roota)
        try:
            # Użyj polecenia ping odpowiedniego dla systemu operacyjnego
            param = '-n 1 -w 1000' if os.name == 'nt' else '-c 1 -W 1'
            command = f"ping {param} {host}"

            # Ukryj okno konsoli w systemie Windows
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # Uruchom polecenie i sprawdź kod wyjścia
            ret = subprocess.call(
                command.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=startupinfo,
            )
            if ret == 0:
                return host

        except Exception as e:
            logging.error(f"System ping failed for {host}: {e}")

        return None

    def _discover_live_hosts(self):
        """Odkrywa aktywne hosty za pomocą skanowania ping."""
        self.signal_status_update.emit(
            f"Discovering hosts (pinging {len(self.hosts_to_scan)} targets)...")
        live_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_host = {executor.submit(
                self._ping_host, host): host for host in self.hosts_to_scan}
            for i, future in enumerate(as_completed(future_to_host)):
                if self._is_cancelled:
                    break
                # Aktualizacja paska postępu dla fazy odkrywania
                percentage = int(((i + 1) / len(self.hosts_to_scan)) * 100)
                self.signal_percentage.emit(percentage)
                host = future.result()
                if host:
                    live_hosts.append(host)
                    self.signal_status_update.emit(f"Host found: {host}")
        return sorted(live_hosts)

    def scan_syn_port(self, host, port, idx, total_ports):
        """Skanuje port używając techniki TCP SYN (wymaga roota)."""
        if self._is_cancelled:
            return None

        percentage = int(((idx + 1) / total_ports) * 100)
        self.signal_percentage.emit(percentage)
        self.signal_scanned_port.emit(f"{host}:{port}")

        # ZMIANA: Użycie srp1 (warstwa 2) zamiast sr1 (warstwa 3) aby 'iface' działało
        # Scapy automatycznie rozwiąże adres MAC bramy dla hostów zdalnych
        pkt = Ether() / IP(dst=host) / TCP(dport=port, flags="S")
        resp = srp1(pkt, timeout=1, verbose=0, iface=self.interface)

        if resp is None:
            return (host, port, "filtered")
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                # Zamknij połączenie wysyłając RST
                send(IP(dst=host)/TCP(dport=port, flags="R"), verbose=0)
                return (host, port, "open")
            elif resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return None  # Port zamknięty
        return None

    def scan_udp_port(self, host, port, idx, total_ports):
        """Skanuje port UDP używając Scapy z sondowaniem specyficznym dla usługi."""
        if self._is_cancelled:
            return None

        percentage = int(((idx + 1) / total_ports) * 100)
        self.signal_percentage.emit(percentage)
        self.signal_scanned_port.emit(f"{host}:{port}")

        try:
            # KROK 1: Wybierz sondę (payload)
            # Jeśli port jest w naszym słowniku, użyj specyficznej sondy.
            # Jeśli nie, użyj pustego ładunku (domyślne zachowanie).
            payload = UDP_PROBES.get(port, "")

            # ZMIANA: Użycie srp1 (warstwa 2) zamiast sr1 (warstwa 3) aby 'iface' działało
            pkt = Ether() / IP(dst=host) / UDP(dport=port) / payload

            # Zmniejsz timeout, aby skanowanie szło szybciej.
            # 2 sekundy na 65535 portów to ponad 36 godzin!
            # Nmap używa tu zaawansowanej logiki, ale 1s to rozsądny kompromis.
            resp = srp1(pkt, timeout=1, verbose=0, iface=self.interface)

            # KROK 2: Zinterpretuj odpowiedź (NOWA LOGIKA)
            if resp is None:
                # BRAK ODPOWIEDZI (timeout)
                # To jest standardowe zachowanie dla portów OTWARTYCH
                # chronionych firewallem LUB po prostu otwartych, które
                # zignorowały naszą sondę.
                # To jest wynik, który dostaniesz dla większości portów z listy online.
                return (host, port, "open|filtered")

            elif resp.haslayer(UDP):
                # OTRZYMANO ODPOWIEDŹ UDP
                # Sukces! Wyspecjalizowana sonda (np. DNS) zadziałała.
                # To jest wynik, który teraz dostaniesz dla portu 53.
                return (host, port, "open")

            elif resp.haslayer(ICMP):
                icmp_type = resp.getlayer(ICMP).type
                icmp_code = resp.getlayer(ICMP).code

                # ICMP type 3, code 3 = Port Unreachable
                # To jest jedyny pewny sygnał, że port jest ZAMKNIĘTY.
                if icmp_type == 3 and icmp_code == 3:
                    return None

                # Inne błędy ICMP (np. 1, 2, 9, 10, 13) oznaczają filtrowanie.
                elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
                    return (host, port, "filtered")

            # Każdy inny dziwny przypadek
            return None

        except Exception:
            return None

    def run(self):
        # NOWE: Faza Host Discovery
        if self.perform_discovery and SCAPY_AVAILABLE:
            live_hosts = self._discover_live_hosts()
            if self._is_cancelled:
                self.signal_end_scan.emit(1)
                return
            self.hosts_to_scan = live_hosts
            self.signal_status_update.emit(
                f"Found {len(live_hosts)} live hosts. Starting port scan...")
        else:
            self.signal_status_update.emit("Starting port scan...")

        if not self.hosts_to_scan:
            self.signal_status_update.emit("No live hosts found to scan.")
            self.signal_percentage.emit(100)
            self.signal_end_scan.emit(1)
            return

        scan_function = self.scan_tcp_connect_port
        if self.scan_type == "TCP SYN Scan":
            scan_function = self.scan_syn_port
        elif self.scan_type == "UDP Scan":
            scan_function = self.scan_udp_port

        total_tasks = len(self.hosts_to_scan) * len(self.ports_to_scan)
        max_workers = min(100, total_tasks if total_tasks > 0 else 1)

        # <<< ZMIANA 1: Użycie blokady przy tworzeniu i ustawianiu executora
        with self._executor_lock:
            # Sprawdź, czy anulowanie nastąpiło zanim zdążyliśmy utworzyć executor (rzadki przypadek, ale bezpieczny)
            if self._is_cancelled:
                self.signal_end_scan.emit(1)
                return
            self.executor = ThreadPoolExecutor(max_workers=max_workers)

        tasks_submitted = 0
        futures = {}
        try:
            for host in self.hosts_to_scan:
                if self._is_cancelled:
                    break
                for port_str in self.ports_to_scan:
                    if self._is_cancelled:
                        break

                    # <<< ZMIANA 2: Użycie blokady przy dodawaniu zadania
                    # Sprawdzamy, czy executor nie został zamknięty przez stop()
                    with self._executor_lock:
                        if not self.executor:  # Jeśli stop() zamknął executor, przerywamy
                            self._is_cancelled = True
                            break

                        tasks_submitted += 1
                        future = self.executor.submit(scan_function, host, int(
                            port_str), tasks_submitted, total_tasks)
                        futures[future] = (host, port_str)

                    if self.scan_delay_ms > 0:
                        time.sleep(self.scan_delay_ms / 1000.0)

            # ZMIANA: Pętla do zbierania wyników, która działa nawet po anulowaniu
            for future in as_completed(futures):
                if self._is_cancelled and not future.done():
                    continue
                try:
                    # Nie blokuj w nieskończoność
                    result = future.result(timeout=0.1)
                    if result:
                        host_res, port_res, banner_res = result
                        self.signal_open_port.emit(
                            str(host_res), str(port_res), banner_res)
                except Exception:
                    # Ignoruj błędy (np. z anulowanych zadań)
                    pass

        finally:
            # <<< ZMIANA 3: Użycie blokady przy zamykaniu executora, aby uniknąć kolizji z stop()
            with self._executor_lock:
                if self.executor:
                    self.executor.shutdown(wait=False, cancel_futures=True)
                    self.executor = None

        if self._is_cancelled:
            self.signal_percentage.emit(0)

        self.signal_end_scan.emit(1)

    def stop(self):
        """Zatrzymuje skanowanie i zamyka pulę wątków."""
        self._is_cancelled = True

        # <<< ZMIANA 4: Użycie blokady do bezpiecznego dostępu i zamknięcia executora
        with self._executor_lock:
            if self.executor:
                # Anuluj przyszłe zadania, które jeszcze nie wystartowały.
                self.executor.shutdown(wait=False, cancel_futures=True)
                # Ustaw executor na None, aby run() nie próbował już dodawać zadań
                self.executor = None

        # Czekaj na zakończenie wątku QThread, ale z timeoutem
        self.wait(2000)


class Ui_dialog(object):
    # <<< ZMIANA 1: Słownik ze znanymi portami
    KNOWN_PORTS = {
        "20": "FTP (Data Transfer)",
        "21": "FTP (Command Control)",
        "22": "SSH (Secure Shell)",
        "23": "Telnet",
        "25": "SMTP (Simple Mail Transfer Protocol)",
        "53": "DNS (Domain Name System)",
        "80": "HTTP (Hypertext Transfer Protocol)",
        "110": "POP3 (Post Office Protocol v3)",
        "143": "IMAP (Internet Message Access Protocol)",
        "443": "HTTPS (HTTP Secure)",
        "465": "SMTPS (SMTP Secure)",
        "587": "SMTP (Mail Submission)",
        "993": "IMAPS (IMAP Secure)",
        "995": "POP3S (POP3 Secure)",
        "3306": "MySQL",
        "3389": "RDP (Remote Desktop Protocol)",
        "5432": "PostgreSQL",
        "5900": "VNC (Virtual Network Computing)",
        "8080": "HTTP Alternate (proxy)"
    }

    # ZMIANA: Przeniesienie globalnych zmiennych do klasy
    ALLOWED_PORT_CHARACTERS = set("0123456789- ")
    NOT_ALLOWED_PORT_PATTERNS = ["--", "---", "- ", " - "]

    def setupUi(self, dialog):
        dialog.setObjectName("dialog")
        dialog.setFixedSize(600, 540)
        font = QFont()
        font.setPointSize(14)
        dialog.setFont(font)
        dialog.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        dialog.setWhatsThis("")
        dialog.setAccessibleName("")
        dialog.setAutoFillBackground(False)
        dialog.setLocale(QLocale(QLocale.Language.English,
                         QLocale.Country.UnitedStates))
        dialog.setSizeGripEnabled(False)
        dialog.setModal(False)
        self.tabWidget = QTabWidget(dialog)
        self.tabWidget.setGeometry(QRect(-1, 0, 601, 536))
        self.tabWidget.setFont(font)
        self.tabWidget.setTabShape(QTabWidget.TabShape.Rounded)
        self.tabWidget.setUsesScrollButtons(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.ScannerTab = QWidget()
        self.ScannerTab.setObjectName("ScannerTab")

        # Dodanie ComboBox do wyboru typu skanowania
        self.ScanTypeLabel = QLabel(self.ScannerTab)
        self.ScanTypeLabel.setGeometry(QRect(420, 50, 100, 21))
        self.ScanTypeLabel.setObjectName("ScanTypeLabel")
        self.ScanTypeComboBox = QComboBox(self.ScannerTab)
        self.ScanTypeComboBox.setGeometry(QRect(420, 75, 171, 30))
        self.ScanTypeComboBox.setFont(font)
        self.ScanTypeComboBox.setObjectName("ScanTypeComboBox")
        self.ScanTypeComboBox.addItem("TCP Connect")
        if SCAPY_AVAILABLE:
            self.ScanTypeComboBox.addItem("TCP SYN Scan")
            self.ScanTypeComboBox.addItem("UDP Scan")
        self.ScanTypeComboBox.currentTextChanged.connect(
            self.on_scan_type_change)

        self.PortsInput = QLineEdit(self.ScannerTab)
        self.PortsInput.setGeometry(QRect(5, 75, 410, 30))
        self.PortsInput.setFont(font)
        self.PortsInput.setText("")
        self.PortsInput.setEchoMode(QLineEdit.EchoMode.Normal)
        self.PortsInput.setClearButtonEnabled(True)
        self.PortsInput.setObjectName("PortsInput")
        self.HostLabel = QLabel(self.ScannerTab)
        self.HostLabel.setGeometry(QRect(5, 0, 586, 21))
        self.HostLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.HostLabel.setObjectName("HostLabel")
        self.ScanButton = QPushButton(self.ScannerTab)
        self.ScanButton.setGeometry(QRect(190, 425, 100, 30))
        self.ScanButton.setCheckable(False)
        self.ScanButton.setAutoDefault(True)
        self.ScanButton.setDefault(False)
        self.ScanButton.setFlat(False)
        self.ScanButton.setObjectName("ScanButton")
        self.CancelButton = QPushButton(self.ScannerTab)
        self.CancelButton.setGeometry(QRect(190, 425, 100, 30))
        self.CancelButton.setCheckable(False)
        self.CancelButton.setAutoDefault(True)
        self.CancelButton.setDefault(False)
        self.CancelButton.setFlat(False)
        self.CancelButton.setObjectName("CancelButton")
        self.CancelButton.setVisible(False)
        self.ScannedLabel = QLabel(self.ScannerTab)
        self.ScannedLabel.setGeometry(QRect(5, 100, 281, 30))
        self.ScannedLabel.setTextFormat(Qt.TextFormat.PlainText)
        self.ScannedLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ScannedLabel.setObjectName("ScannedLabel")
        self.ScannedList = QTextEdit(self.ScannerTab)
        self.ScannedList.setEnabled(True)
        self.ScannedList.setGeometry(QRect(5, 130, 281, 291))
        self.ScannedList.setFont(font)
        self.ScannedList.setInputMethodHints(Qt.InputMethodHint.ImhNone)
        self.ScannedList.setReadOnly(True)
        self.ScannedList.setOverwriteMode(False)
        self.ScannedList.setAcceptRichText(False)
        self.ScannedList.setObjectName("ScannedList")

        # ZMIANA: Zamiana QTextEdit na QTableWidget dla otwartych portów
        self.OpenTable = QTableWidget(self.ScannerTab)
        self.OpenTable.setEnabled(True)
        self.OpenTable.setGeometry(QRect(295, 160, 296, 261))
        self.OpenTable.setFont(font)
        self.OpenTable.setObjectName("OpenTable")
        self.OpenTable.setColumnCount(5)
        self.OpenTable.setHorizontalHeaderLabels(
            ["Host", "Port", "Protocol", "Status", "Service/Banner"])
        self.OpenTable.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive)
        self.OpenTable.horizontalHeader().setStretchLastSection(True)
        self.OpenTable.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.OpenTable.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows)
        self.OpenTable.setSortingEnabled(True)
        self.OpenTable.setAlternatingRowColors(True)
        # Ustaw szerokości kolumn
        self.OpenTable.setColumnWidth(0, 100)  # Host
        self.OpenTable.setColumnWidth(1, 50)   # Port
        self.OpenTable.setColumnWidth(2, 60)   # Protocol
        self.OpenTable.setColumnWidth(3, 70)   # Status

        # NOWE: Włącz menu kontekstowe dla tabeli
        self.OpenTable.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.OpenTable.customContextMenuRequested.connect(
            self.show_table_context_menu)

        self.IpInput = QLineEdit(self.ScannerTab)
        self.IpInput.setGeometry(QRect(5, 20, 586, 30))
        self.DelayBox = QSpinBox(self.ScannerTab)
        self.DelayBox.setGeometry(QRect(6, 430, 66, 22))
        self.DelayBox.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.DelayBox.setMaximum(9999)
        self.DelayBox.setProperty("value", 1)
        self.DelayBox.setObjectName("DelayBox")
        self.DelayLabel = QLabel(self.ScannerTab)
        self.DelayLabel.setGeometry(QRect(75, 430, 146, 21))
        self.DelayLabel.setFont(font)
        self.DelayLabel.setTextFormat(Qt.TextFormat.PlainText)
        self.DelayLabel.setWordWrap(True)
        self.DelayLabel.setOpenExternalLinks(False)
        self.DelayLabel.setObjectName("DelayLabel")
        self.IpInput.setFont(font)
        self.IpInput.setInputMethodHints(Qt.InputMethodHint.ImhNone)
        self.IpInput.setText("")
        self.IpInput.setEchoMode(QLineEdit.EchoMode.Normal)
        self.IpInput.setDragEnabled(False)
        self.IpInput.setClearButtonEnabled(True)
        self.IpInput.setObjectName("IpInput")
        self.PortsToScanLabel = QLabel(self.ScannerTab)
        self.PortsToScanLabel.setGeometry(QRect(5, 55, 586, 21))
        self.PortsToScanLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.PortsToScanLabel.setObjectName("PortsToScanLabel")
        self.ProgressBar = QProgressBar(self.ScannerTab)
        self.ProgressBar.setEnabled(False)
        self.ProgressBar.setGeometry(QRect(5, 459, 586, 36))
        self.ProgressBar.setFont(font)
        self.ProgressBar.setDisabled(True)
        self.ProgressBar.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.ProgressBar.setAccessibleName("")
        self.ProgressBar.setAutoFillBackground(False)
        self.ProgressBar.setMaximum(100)
        self.ProgressBar.setProperty("value", 0)
        self.ProgressBar.setAlignment(
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        self.ProgressBar.setTextVisible(False)
        self.ProgressBar.setOrientation(Qt.Orientation.Horizontal)
        self.ProgressBar.setInvertedAppearance(False)
        self.ProgressBar.setTextDirection(QProgressBar.Direction.TopToBottom)
        self.ProgressBar.setObjectName("ProgressBar")
        self.OpenLabel = QLabel(self.ScannerTab)
        self.OpenLabel.setGeometry(QRect(295, 100, 296, 30))
        self.OpenLabel.setTextFormat(Qt.TextFormat.PlainText)
        self.OpenLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.OpenLabel.setObjectName("OpenLabel")
        # Dodaj przycisk Save Results
        self.SaveButton = QPushButton(self.ScannerTab)
        self.SaveButton.setGeometry(QRect(295, 425, 120, 30))
        self.SaveButton.setObjectName("SaveButton")
        self.SaveButton.setDisabled(True)

        # NOWE: Checkbox dla Host Discovery

        self.HostDiscoveryCheckBox = QCheckBox(
            "Host Discovery Admin", self.ScannerTab)
        self.HostDiscoveryCheckBox.setGeometry(QRect(420, 425, 200, 30))
        self.HostDiscoveryCheckBox.setFont(font)
        self.HostDiscoveryCheckBox.setChecked(True)
        self.HostDiscoveryCheckBox.setObjectName("HostDiscoveryCheckBox")
        if not IS_ADMIN:
            self.HostDiscoveryCheckBox.setDisabled(True)
            self.HostDiscoveryCheckBox.setChecked(False)
        if not SCAPY_AVAILABLE:

            self.HostDiscoveryCheckBox.setDisabled(True)
            self.HostDiscoveryCheckBox.setToolTip(
                "Scapy is required for this feature.")

        # DODANE: FilterLabel i FilterComboBox
        self.FilterLabel = QLabel(self.ScannerTab)
        self.FilterLabel.setGeometry(QRect(295, 105, 100, 25))
        self.FilterLabel.setObjectName("FilterLabel")

        self.FilterComboBox = QComboBox(self.ScannerTab)
        self.FilterComboBox.setGeometry(QRect(400, 105, 191, 25))
        self.FilterComboBox.setFont(font)
        self.FilterComboBox.setObjectName("FilterComboBox")
        self.FilterComboBox.addItem("All")
        self.FilterComboBox.addItem("open")
        self.FilterComboBox.addItem("filtered")
        self.FilterComboBox.addItem("open|filtered")
        self.FilterComboBox.setDisabled(True)

        # NOWE: ComboBox dla interfejsów sieciowych
        self.InterfaceLabel = QLabel(self.ScannerTab)
        self.InterfaceLabel.setGeometry(QRect(295, 130, 100, 25))
        self.InterfaceLabel.setObjectName("InterfaceLabel")

        self.InterfaceComboBox = QComboBox(self.ScannerTab)
        self.InterfaceComboBox.setGeometry(QRect(400, 130, 191, 25))
        self.InterfaceComboBox.setFont(font)
        self.InterfaceComboBox.setObjectName("InterfaceComboBox")
        self.InterfaceComboBox.setDisabled(True)

        if SCAPY_AVAILABLE:
            try:
                # Użyj get_if_list() do pobrania nazw interfejsów
                interfaces = get_if_list()
                self.InterfaceComboBox.addItems(interfaces)
            except Exception:
                self.InterfaceComboBox.addItem("Scapy Error")
        else:
            self.InterfaceComboBox.addItem("Scapy not found")

        self.tabWidget.addTab(self.ScannerTab, "")
        self.AboutTab = QWidget()
        self.AboutTab.setObjectName("AboutTab")
        self.AuthorLabel = QLabel(self.AboutTab)
        self.AuthorLabel.setGeometry(QRect(210, 185, 146, 66))
        self.AuthorLabel.setObjectName("AuthorLabel")
        self.ProjectLinkButton = QCommandLinkButton(self.AboutTab)
        self.ProjectLinkButton.setGeometry(QRect(100, 245, 350, 40))
        self.ProjectLinkButton.setObjectName("ProjectLinkButton")
        self.tabWidget.addTab(self.AboutTab, "")
        self.retranslateUi(dialog)
        self.tabWidget.setCurrentIndex(0)
        QMetaObject.connectSlotsByName(dialog)

        # <<< ZMIANA 2: Inicjalizacja listy na otwarte porty
        self.open_ports_list = []
        self.open_ports_data = []  # Lista słowników z danymi portów

        self.ScanButton.clicked.connect(self.start_scan)
        self.CancelButton.clicked.connect(self.cancel_scan)
        self.SaveButton.clicked.connect(self.save_results)
        self.ProjectLinkButton.clicked.connect(self.open_url)
        self.PortsInput.textChanged.connect(self.check_input_ports)
        self.DelayBox.valueChanged.connect(self.check_delay_value)
        self.FilterComboBox.currentTextChanged.connect(
            self.update_displayed_results)

    def on_scan_type_change(self, text):
        """Wyświetla ostrzeżenie, jeśli wybrano skanowanie wymagające uprawnień roota."""
        is_raw_scan = "TCP SYN" in text or "UDP Scan" in text

        # Włącz/wyłącz wybór interfejsu
        if SCAPY_AVAILABLE:
            self.InterfaceComboBox.setEnabled(is_raw_scan)

            if not IS_ADMIN and is_raw_scan:
                QMessageBox.warning(
                    None,
                    "Administrator Privileges Required",
                    f"{text} requires administrator/root privileges to create raw sockets. "
                    "The scan may fail. Please run the application as an administrator."
                )

    def check_delay_value(self):
        if self.DelayBox.value() == 0:
            warning_font = QFont()
            warning_font.setPointSize(12)
            delay_warning = QMessageBox()
            delay_warning.setIcon(QMessageBox.Icon.Warning)
            delay_warning.setFont(warning_font)
            delay_warning.setText('Delay between each port scan too low !!!')
            delay_warning.setInformativeText(
                "Some servers will drop some of the scans and some open ports won't be detected.")
            delay_warning.setWindowTitle("Warning")
            delay_warning.setStandardButtons(QMessageBox.StandardButton.Ok)
            delay_warning.exec()

    def check_input_ports(self):
        ports = self.PortsInput.text()
        original_ports = ports

        if ports.startswith("-") or ports.startswith(" "):
            ports = ports.lstrip(" -")

        # Usuń niedozwolone znaki
        ports = "".join(
            filter(self.ALLOWED_PORT_CHARACTERS.__contains__, ports))

        # Napraw wielokrotne myślniki i spacje wokół nich
        for pattern in self.NOT_ALLOWED_PORT_PATTERNS:
            ports = ports.replace(pattern, "-")

        # Usuń podwójne spacje
        ports = ' '.join(ports.split())

        if ports != original_ports:
            self.PortsInput.setText(ports)

    def open_url(self):
        webbrowser.open_new(self.ProjectLinkButton.text())

    def show_table_context_menu(self, position):
        """Wyświetla menu kontekstowe dla tabeli z opcjami kopiowania."""
        # Sprawdź czy są zaznaczone elementy
        selected_items = self.OpenTable.selectedItems()
        if not selected_items:
            return

        # Utwórz menu kontekstowe
        context_menu = QMenu(self.OpenTable)

        # Dodaj akcje
        copy_cell_action = QAction("Copy Cell", self.OpenTable)
        copy_cell_action.triggered.connect(self.copy_selected_cell)
        context_menu.addAction(copy_cell_action)

        copy_row_action = QAction("Copy Row", self.OpenTable)
        copy_row_action.triggered.connect(self.copy_selected_row)
        context_menu.addAction(copy_row_action)

        context_menu.addSeparator()

        copy_all_action = QAction("Copy All Visible Rows", self.OpenTable)
        copy_all_action.triggered.connect(self.copy_all_rows)
        context_menu.addAction(copy_all_action)

        # Wyświetl menu w pozycji kursora
        context_menu.exec(self.OpenTable.viewport().mapToGlobal(position))

    def copy_selected_cell(self):
        """Kopiuje zawartość wybranej komórki do schowka."""
        current_item = self.OpenTable.currentItem()
        if current_item:
            clipboard = QApplication.clipboard()
            clipboard.setText(current_item.text())

    def copy_selected_row(self):
        """Kopiuje cały wiersz (wszystkie kolumny) do schowka."""
        current_row = self.OpenTable.currentRow()
        if current_row >= 0:
            row_data = []
            for col in range(self.OpenTable.columnCount()):
                item = self.OpenTable.item(current_row, col)
                if item:
                    row_data.append(item.text())
                else:
                    row_data.append("")

            # Format: "Host | Port | Protocol | Status | Service/Banner"
            clipboard = QApplication.clipboard()
            clipboard.setText(" | ".join(row_data))

    def copy_all_rows(self):
        """Kopiuje wszystkie widocze wiersze do schowka w formacie tabelarycznym."""
        rows_data = []

        # Dodaj nagłówki
        headers = []
        for col in range(self.OpenTable.columnCount()):
            headers.append(self.OpenTable.horizontalHeaderItem(col).text())
        rows_data.append("\t".join(headers))

        # Dodaj wszystkie wiersze
        for row in range(self.OpenTable.rowCount()):
            row_data = []
            for col in range(self.OpenTable.columnCount()):
                item = self.OpenTable.item(row, col)
                if item:
                    row_data.append(item.text())
                else:
                    row_data.append("")
            rows_data.append("\t".join(row_data))

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(rows_data))

    def parse_hosts(self, host_input):
        """Parsuje wejście użytkownika, obsługując CIDR, zakresy i nazwy hostów."""
        targets = set()
        # Zastąp przecinki i średniki spacjami, a następnie podziel
        cleaned_input = host_input.replace(',', ' ').replace(';', ' ')
        parts = cleaned_input.split()

        for part in parts:
            if not part:
                continue
            try:
                # Sprawdź, czy to sieć CIDR lub pojedynczy adres IP
                network = ipaddress.ip_network(part, strict=False)
                for ip in network.hosts():
                    targets.add(str(ip))
                # Dodaj adres sieciowy, jeśli to nie jest pojedynczy host
                if network.num_addresses > 1:
                    targets.add(str(network.network_address))
            except ValueError:
                # Jeśli nie jest to adres IP/CIDR, potraktuj jako nazwę hosta
                targets.add(part)
        return sorted(list(targets))

    def start_scan(self):
        if not self.IpInput.text():
            QMessageBox.warning(self.ScannerTab, "Input Error",
                                "Host field cannot be empty.")
            return

        if not self.PortsInput.text():
            self.PortsInput.setText("1-65535")

        # Zablokuj UI
        self.ScanButton.setDisabled(True)
        self.ScanButton.setVisible(False)
        self.CancelButton.setDisabled(False)
        self.CancelButton.setVisible(True)
        self.IpInput.setDisabled(True)
        self.PortsInput.setDisabled(True)
        self.ScanTypeComboBox.setDisabled(True)
        self.ProgressBar.setDisabled(False)
        self.ProgressBar.setCursor(QCursor(Qt.CursorShape.WaitCursor))
        self.ProgressBar.setTextVisible(True)
        self.ProgressBar.setValue(0)
        self.DelayBox.setDisabled(True)
        self.SaveButton.setDisabled(True)
        self.FilterComboBox.setDisabled(True)
        self.InterfaceComboBox.setDisabled(True)

        # Wyczyść wyniki
        self.open_ports_list.clear()
        self.open_ports_data.clear()
        self.ScannedList.clear()
        self.OpenTable.setRowCount(0)

        # Parsuj hosty i porty
        hosts_to_scan = self.parse_hosts(self.IpInput.text())

        ports_text = ' '.join(self.PortsInput.text().split())
        port_list_str = ports_text.split()

        ports_to_scan = []
        for port in port_list_str:
            if "-" in str(port):
                port_parts = port.split("-")
                port1 = int(port_parts[0])
                port2 = int(port_parts[1]) + 1
                if port1 >= 65535:
                    port1 = 65535
                if port2 >= 65535:
                    port2 = 65535
                for port_r in range(port1, port2):
                    ports_to_scan.append(str(port_r))
            else:
                if int(port) >= 65535:
                    port = "65535"
                ports_to_scan.append(port)

        ports_to_scan = sorted(list(set(ports_to_scan)), key=int)

        # ZMIANA: Pobierz wartość opóźnienia
        scan_delay_value = self.DelayBox.value()
        # NOWE: Pobierz wybrany interfejs
        selected_interface = self.InterfaceComboBox.currentText()

        # Uruchom wątek skanujący z przekazaniem scan_delay i interfejsu
        scan_type = self.ScanTypeComboBox.currentText()
        self.scan = ScanThread(scan_type, hosts_to_scan,
                               ports_to_scan, scan_delay_value, selected_interface, self.HostDiscoveryCheckBox.isChecked())
        self.scan.signal_percentage.connect(self.update_progressbar)
        self.scan.signal_scanned_port.connect(self.update_scanned_ports)
        self.scan.signal_open_port.connect(self.update_open_ports)
        self.scan.signal_end_scan.connect(self.end_scan)
        self.scan.signal_status_update.connect(
            self.update_status_label)  # NOWE
        self.scan.start()

    def cancel_scan(self):
        """Anuluje skanowanie i natychmiast odblokowuje UI."""
        if hasattr(self, 'scan') and self.scan.isRunning():
            self.scan.stop()
            self.end_scan()

    def update_progressbar(self, percentage):
        self.ProgressBar.setValue(percentage)

    def update_status_label(self, text):
        """NOWE: Aktualizuje etykietę statusu pod paskiem postępu."""
        self.ProgressBar.setFormat(text)

    def update_scanned_ports(self, port):
        self.ScannedList.append(port)

    def update_displayed_results(self):
        """Filtruje i wyświetla wyniki na podstawie wyboru w ComboBox."""
        filter_text = self.FilterComboBox.currentText()

        # Wyłącz sortowanie podczas aktualizacji
        self.OpenTable.setSortingEnabled(False)
        self.OpenTable.setRowCount(0)

        # Filtruj dane
        if filter_text == "All":
            data_to_display = self.open_ports_data
        else:
            data_to_display = [
                item for item in self.open_ports_data
                if item['status'] == filter_text
            ]

        # Wypełnij tabelę
        for row_data in data_to_display:
            row_position = self.OpenTable.rowCount()
            self.OpenTable.insertRow(row_position)

            self.OpenTable.setItem(
                row_position, 0, QTableWidgetItem(row_data['host']))
            self.OpenTable.setItem(
                row_position, 1, QTableWidgetItem(row_data['port']))
            self.OpenTable.setItem(
                row_position, 2, QTableWidgetItem(row_data['protocol']))
            self.OpenTable.setItem(
                row_position, 3, QTableWidgetItem(row_data['status']))
            self.OpenTable.setItem(
                row_position, 4, QTableWidgetItem(row_data['service_banner']))

        # Włącz sortowanie z powrotem
        self.OpenTable.setSortingEnabled(True)

    # <<< ZMIANA 4: Całkowicie nowa, wydajniejsza funkcja
    def update_open_ports(self, host, port, banner):
        """Aktualizuje listę otwartych portów, dodając hosta, opis i banner."""
        description = self.KNOWN_PORTS.get(port, "")

        # Określ protokół na podstawie typu skanowania
        protocol = "TCP"
        if self.scan.scan_type == "UDP Scan":
            protocol = "UDP"

        # Określ status
        if self.scan.scan_type in ["TCP SYN Scan", "UDP Scan"]:
            status = banner  # "open", "filtered", "open|filtered"
        else:
            status = "open"

        # ZMIANA: Ulepszone przygotowanie pola Service/Banner
        service_banner = ""

        if description:
            service_banner = description

        # Dla TCP Connect - wyświetl banner jeśli został pobrany
        if banner and self.scan.scan_type == "TCP Connect":
            # Banner już jest oczyszczony w grab_banner()
            if service_banner:
                service_banner += f" | {banner}"
            else:
                service_banner = banner

        # Usuń stary wpis dla tego hosta:portu
        self.open_ports_data = [
            item for item in self.open_ports_data
            if not (item['host'] == host and item['port'] == port)
        ]

        # Dodaj nowy wpis
        port_data = {
            'host': host,
            'port': port,
            'protocol': protocol,
            'status': status,
            'service_banner': service_banner
        }
        self.open_ports_data.append(port_data)

        # ZMIANA: Bezpośrednia aktualizacja tabeli zamiast wywoływania update_displayed_results
        # To uniknie problemów z wielokrotnym przerysowywaniem
        filter_text = self.FilterComboBox.currentText()

        # Sprawdź czy wpis pasuje do filtru
        if filter_text == "All" or status == filter_text:
            # Wyłącz sortowanie przed dodaniem wiersza
            self.OpenTable.setSortingEnabled(False)

            row_position = self.OpenTable.rowCount()
            self.OpenTable.insertRow(row_position)

            self.OpenTable.setItem(row_position, 0, QTableWidgetItem(host))
            self.OpenTable.setItem(row_position, 1, QTableWidgetItem(port))
            self.OpenTable.setItem(row_position, 2, QTableWidgetItem(protocol))
            self.OpenTable.setItem(row_position, 3, QTableWidgetItem(status))
            self.OpenTable.setItem(
                row_position, 4, QTableWidgetItem(service_banner))

            # Włącz sortowanie z powrotem
            self.OpenTable.setSortingEnabled(True)

            # ZMIANA: Wymuś odświeżenie wizualne i przewiń do nowego wpisu
            self.OpenTable.scrollToBottom()
            QApplication.processEvents()

            # Jeśli mamy jakiekolwiek wyniki, zezwól na zapis (Save Results)
            try:
                if self.open_ports_data:
                    self.SaveButton.setDisabled(False)
                    # Włącz filtrowanie tylko dla skanów niskopoziomowych
                    if self.scan.scan_type in ["TCP SYN Scan", "UDP Scan"]:
                        self.FilterComboBox.setDisabled(False)
            except Exception:
                # W testach GUI mogą być zastępcze obiekty bez metod; ignoruj wtedy
                pass

    def end_scan(self):
        self.ScanButton.setVisible(True)
        self.ScanButton.setDisabled(False)
        self.IpInput.setDisabled(False)
        self.PortsInput.setDisabled(False)
        self.ScanTypeComboBox.setDisabled(False)
        self.CancelButton.setVisible(False)
        self.CancelButton.setDisabled(True)
        self.DelayBox.setDisabled(False)
        self.ProgressBar.setDisabled(True)
        self.ProgressBar.setCursor(QCursor(Qt.CursorShape.ArrowCursor))
        self.ProgressBar.setFormat("")  # Wyczyść tekst statusu

        # Włącz/wyłącz wybór interfejsu w zależności od typu skanowania
        is_raw_scan = self.scan.scan_type in ["TCP SYN Scan", "UDP Scan"]
        if SCAPY_AVAILABLE:
            self.InterfaceComboBox.setEnabled(is_raw_scan)

        # Aktywuj przycisk Save i filtrowanie, jeśli są wyniki
        if self.open_ports_data:
            self.SaveButton.setDisabled(False)
            if self.scan.scan_type in ["TCP SYN Scan", "UDP Scan"]:
                self.FilterComboBox.setDisabled(False)

    def save_results(self):
        """Zapisz wyniki skanowania do pliku tekstowego, CSV lub JSON"""
        if not self.open_ports_data:
            QMessageBox.information(
                None,
                "No Results",
                "There are no scan results to save."
            )
            return

        # Otwórz dialog zapisu pliku z opcjami formatu
        file_path, selected_filter = QFileDialog.getSaveFileName(
            None,
            "Save Scan Results",
            f"scan_results_{self.IpInput.text()}.txt",
            "Text Files (*.txt);;CSV Files (*.csv);;JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                # Określ format na podstawie rozszerzenia lub wybranego filtru
                if file_path.endswith('.csv') or 'CSV' in selected_filter:
                    self._save_as_csv(file_path)
                elif file_path.endswith('.json') or 'JSON' in selected_filter:
                    self._save_as_json(file_path)
                else:
                    self._save_as_txt(file_path)

                QMessageBox.information(
                    None,
                    "Success",
                    f"Results saved successfully to:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    None,
                    "Error",
                    f"Failed to save results:\n{str(e)}"
                )

    def _save_as_txt(self, file_path):
        """Zapisz wyniki jako zwykły tekst"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Port Scan Results\n")
            f.write(f"Host: {self.IpInput.text()}\n")
            f.write(f"Scanned Ports: {self.PortsInput.text()}\n")
            f.write(f"Scan Type: {self.scan.scan_type}\n")
            f.write(f"Filter: {self.FilterComboBox.currentText()}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"\n{'='*60}\n\n")
            f.write(
                f"{'Host':<20} {'Port':<8} {'Protocol':<10} {'Status':<15} {'Service/Banner'}\n")
            f.write(f"{'-'*20} {'-'*8} {'-'*10} {'-'*15} {'-'*30}\n")

            for row in range(self.OpenTable.rowCount()):
                host_val = self.OpenTable.item(row, 0).text()
                port_val = self.OpenTable.item(row, 1).text()
                protocol_val = self.OpenTable.item(row, 2).text()
                status_val = self.OpenTable.item(row, 3).text()
                service_val = self.OpenTable.item(row, 4).text()

                f.write(
                    f"{host_val:<20} {port_val:<8} {protocol_val:<10} {status_val:<15} {service_val}\n")

    def _save_as_csv(self, file_path):
        """Zapisz wyniki jako CSV"""

        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Nagłówek z metadanymi
            writer.writerow(['# Port Scan Results'])
            writer.writerow(['# Host:', self.IpInput.text()])
            writer.writerow(['# Scanned Ports:', self.PortsInput.text()])
            writer.writerow(['# Scan Type:', self.scan.scan_type])
            writer.writerow(['# Filter:', self.FilterComboBox.currentText()])
            writer.writerow(['# Date:', time.strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])

            # Nagłówki kolumn
            writer.writerow(['Host', 'Port', 'Protocol',
                            'Status', 'Service/Banner'])

            # Dane
            for row in range(self.OpenTable.rowCount()):
                row_data = [
                    self.OpenTable.item(row, col).text()
                    for col in range(self.OpenTable.columnCount())
                ]
                writer.writerow(row_data)

    def _save_as_json(self, file_path):
        """Zapisz wyniki jako JSON"""

        results = {
            'scan_info': {
                'host': self.IpInput.text(),
                'scanned_ports': self.PortsInput.text(),
                'scan_type': self.scan.scan_type,
                'filter': self.FilterComboBox.currentText(),
                'date': time.strftime('%Y-%m-%d %H:%M:%S')
            },
            'results': []
        }

        for row in range(self.OpenTable.rowCount()):
            port_entry = {
                'host': self.OpenTable.item(row, 0).text(),
                'port': self.OpenTable.item(row, 1).text(),
                'protocol': self.OpenTable.item(row, 2).text(),
                'status': self.OpenTable.item(row, 3).text(),
                'service_banner': self.OpenTable.item(row, 4).text()
            }
            results['results'].append(port_entry)

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    def retranslateUi(self, dialog):
        _translate = QCoreApplication.translate
        dialog.setWindowTitle(_translate(
            "dialog", "Open Port Scanner"))
        self.PortsInput.setPlaceholderText(_translate(
            "dialog", "20-25 80 443 100-200 | Empty = Scan all ports"))
        self.HostLabel.setText(_translate("dialog", "Host"))
        self.ScanButton.setText(_translate("dialog", "Scan"))
        self.CancelButton.setText(_translate("dialog", "Cancel"))
        self.SaveButton.setText(_translate("dialog", "Save Results"))
        self.ScannedLabel.setText(_translate("dialog", "Scanned Ports"))
        self.ScannedList.setPlaceholderText(_translate(
            "dialog", "Scanned ports will appear here."))
        self.IpInput.setPlaceholderText(_translate("dialog", "Domain or IP"))
        self.PortsToScanLabel.setText(_translate("dialog", "Ports to scan"))
        self.ScanTypeLabel.setText(_translate("dialog", "Scan Type"))
        self.FilterLabel.setText(_translate("dialog", "Filter results:"))
        self.InterfaceLabel.setText(_translate("dialog", "Interface:"))
        self.ProgressBar.setFormat(_translate("dialog", "%p%"))
        self.OpenLabel.setText(_translate("dialog", "Open ports"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(
            self.ScannerTab), _translate("dialog", "Scanner"))
        self.DelayLabel.setText(_translate("dialog", "Scan delay (ms)"))
        self.AuthorLabel.setText(_translate("dialog", "Mateusz Misiak 1IZ21A"))
        self.ProjectLinkButton.setText(_translate(
            "dialog", "https://github.com/stigi99"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(
            self.AboutTab), _translate("dialog", "About"))


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    dialog = QDialog()
    ui = Ui_dialog()
    ui.setupUi(dialog)
    dialog.show()
    sys.exit(app.exec())
