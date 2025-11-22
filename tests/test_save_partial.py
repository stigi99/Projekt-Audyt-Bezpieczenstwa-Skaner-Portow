import os
import importlib.util
import sys
import types


def load_main_module():
    root = os.path.abspath(os.path.dirname(__file__) + "/..")
    file_path = os.path.join(root, "Projekt AB Skaner Portów.py")
    spec = importlib.util.spec_from_file_location("main_module", file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DummyWidget:
    def __init__(self):
        self.disabled = None
        self.visible = None
        self.cursor = None
        self.format = None

    def setDisabled(self, v):
        self.disabled = v

    def setVisible(self, v):
        self.visible = v

    def setEnabled(self, v):
        self.disabled = not v

    def setCursor(self, v):
        self.cursor = v

    def setFormat(self, v):
        self.format = v

    def setText(self, v):
        self.text_val = v

    def text(self):
        return getattr(self, "text_val", "")


class DummyTable(DummyWidget):
    def __init__(self):
        super().__init__()
        self._rows = []

    def setSortingEnabled(self, v):
        self.sorting = v

    def insertRow(self, idx):
        self._rows.append([None]*5)

    def setItem(self, r, c, item):
        # QTableWidgetItem in tests may be a stub without text(); try to extract
        if hasattr(item, 'text') and callable(getattr(item, 'text')):
            self._rows[r][c] = item.text()
        elif hasattr(item, 'text'):
            self._rows[r][c] = item.text
        else:
            self._rows[r][c] = str(item)

    def rowCount(self):
        return len(self._rows)

    def scrollToBottom(self):
        pass


def test_enable_save_when_partial_results_present(monkeypatch):
    module = load_main_module()
    ui = module.Ui_dialog()

    # Provide minimal dummy widgets so end_scan() doesn't error
    ui.ScanButton = DummyWidget()
    ui.IpInput = DummyWidget()
    ui.PortsInput = DummyWidget()
    ui.ScanTypeComboBox = DummyWidget()
    ui.CancelButton = DummyWidget()
    ui.DelayBox = DummyWidget()
    ui.ProgressBar = DummyWidget()
    ui.InterfaceComboBox = DummyWidget()

    class DummyCombo(DummyWidget):
        def currentText(self):
            return "All"

    ui.FilterComboBox = DummyCombo()
    ui.SaveButton = DummyWidget()

    # Provide dummy scan info and partial results
    ui.open_ports_data = [{'host': '1.2.3.4', 'port': '80', 'protocol': 'TCP', 'status': 'open', 'service_banner': ''}]
    ui.scan = types.SimpleNamespace(scan_type='TCP Connect')

    # Ensure module has ArrowCursor attr and QCursor that accepts args to avoid attribute errors
    module.Qt.CursorShape.ArrowCursor = 1

    class DummyQCursor:
        def __init__(self, *a, **k):
            self.args = a

    module.QCursor = DummyQCursor

    # Call end_scan and check that SaveButton becomes enabled
    ui.end_scan()
    assert ui.SaveButton.disabled is False


def test_save_button_enabled_during_scan_update(monkeypatch):
    module = load_main_module()
    ui = module.Ui_dialog()

    # Provide minimal dummy widgets for update_open_ports
    ui.SaveButton = DummyWidget()

    class DummyCombo(DummyWidget):
        def currentText(self):
            return "All"

    ui.FilterComboBox = DummyCombo()
    ui.OpenTable = DummyTable()
    ui.open_ports_data = []
    ui.scan = types.SimpleNamespace(scan_type='TCP Connect')

    # monkeypatch QTableWidgetItem to accept text and provide text() method
    class DummyQTableWidgetItem:
        def __init__(self, t=''):
            self._t = str(t)

        def text(self):
            return self._t

    module.QTableWidgetItem = DummyQTableWidgetItem
    # Ensure QApplication.processEvents exists
    module.QApplication.processEvents = lambda *a, **k: None

    # Call update_open_ports to simulate a result coming in
    ui.update_open_ports('1.2.3.4', '22', 'SSH-2.0')
    assert ui.SaveButton.disabled is False
