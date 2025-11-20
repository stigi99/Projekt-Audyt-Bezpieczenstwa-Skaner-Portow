import sys
import types

# Provide minimal PySide6 stubs to allow importing the GUI module in tests without installing PySide6
py = types.ModuleType("PySide6")
qtcore = types.ModuleType("PySide6.QtCore")
qtcore.QThread = type("QThread", (), {})
qtcore.Signal = lambda *args, **kwargs: None
qtcore.QLocale = type("QLocale", (), {})
qtcore.QRect = type("QRect", (), {})
qtcore.Qt = type("Qt", (), {"CursorShape": type("CursorShape", (), {}), "AlignmentFlag": type(
    "AlignmentFlag", (), {}), "TextFormat": type("TextFormat", (), {}), "Orientation": type("Orientation", (), {})})
qtcore.QMetaObject = type("QMetaObject", (), {})
qtcore.QCoreApplication = type("QCoreApplication", (), {})

qtgui = types.ModuleType("PySide6.QtGui")
qtgui.QFont = type("QFont", (), {})
qtgui.QCursor = type("QCursor", (), {})
qtgui.QAction = type("QAction", (), {})

qtwidgets = types.ModuleType("PySide6.QtWidgets")
for name in [
    "QTabWidget", "QLineEdit", "QWidget", "QLabel", "QProgressBar",
    "QCommandLinkButton", "QTextEdit", "QPushButton", "QApplication",
    "QDialog", "QSpinBox", "QMessageBox", "QFileDialog",
    "QComboBox", "QTableWidget", "QTableWidgetItem", "QHeaderView",
    "QMenu", "QCheckBox",
]:
    setattr(qtwidgets, name, type(name, (), {}))

# Insert into sys.modules so imports in the main file succeed
sys.modules.setdefault("PySide6", py)
sys.modules.setdefault("PySide6.QtCore", qtcore)
sys.modules.setdefault("PySide6.QtGui", qtgui)
sys.modules.setdefault("PySide6.QtWidgets", qtwidgets)

# Provide a minimal scapy stub so imports like 'from scapy.all import get_if_list, Ether' succeed
scapy = types.ModuleType("scapy")
scapy_all = types.ModuleType("scapy.all")


def get_if_list():
    return []


class Ether:
    pass


class IP:
    pass


class UDP:
    pass
class DNS:
    def __init__(self, **kwargs):
        pass
class DNSQR:
    def __init__(self, **kwargs):
        pass
class NTP:
    def __init__(self, **kwargs):
        pass
class SNMP:
    def __init__(self, **kwargs):
        pass
def SNMPget(*a, **k):
    return None
class SNMPvarbind:
    def __init__(self, **kwargs):
        pass
def ASN1_OID(x):
    return x
class NBNSQueryRequest:
    def __init__(self, **kwargs):
        pass


class TCP:
    pass


class ICMP:
    pass


def srp1(*a, **k):
    return None
def sr1(*a, **k):
    return None


def send(*a, **k):
    return None


scapy_all.get_if_list = get_if_list
scapy_all.Ether = Ether
scapy_all.IP = IP
scapy_all.UDP = UDP
scapy_all.TCP = TCP
scapy_all.ICMP = ICMP
scapy_all.srp1 = srp1
scapy_all.sr1 = sr1
scapy_all.send = send
scapy_all.DNS = DNS
scapy_all.DNSQR = DNSQR
scapy_all.NTP = NTP
scapy_all.SNMP = SNMP
scapy_all.SNMPget = SNMPget
scapy_all.SNMPvarbind = SNMPvarbind
scapy_all.ASN1_OID = ASN1_OID
scapy_all.NBNSQueryRequest = NBNSQueryRequest

sys.modules.setdefault("scapy", scapy)
sys.modules.setdefault("scapy.all", scapy_all)
