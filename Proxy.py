import sys
import time
import socket
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional

import serial
from serial.tools import list_ports
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QComboBox,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QSpinBox,
    QLineEdit,
    QStackedWidget,
    QFormLayout,
    QGroupBox,
)
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QTextCursor


# --- Helpers -----------------------------------------------------------------

def hex_bytes(data: bytes) -> str:
    return data.hex(" ").upper()


def parse_hex_string(value: str) -> bytes:
    clean = value.replace(" ", "")
    if len(clean) % 2:
        clean = "0" + clean
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return b""


# --- Endpoint configs --------------------------------------------------------

@dataclass
class SerialConfig:
    port: str
    baudrate: int
    bytesize: int
    parity: str
    stopbits: float
    timeout: float = 0.05


@dataclass
class TcpConfig:
    host: str
    port: int
    timeout: float = 0.05


class SerialEndpoint:
    def __init__(self, cfg: SerialConfig):
        self.cfg = cfg
        self.ser: Optional[serial.Serial] = None

    def open(self):
        parity = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
            "M": serial.PARITY_MARK,
            "S": serial.PARITY_SPACE,
        }.get(self.cfg.parity, serial.PARITY_NONE)
        stop = {
            1: serial.STOPBITS_ONE,
            1.5: serial.STOPBITS_ONE_POINT_FIVE,
            2: serial.STOPBITS_TWO,
        }.get(self.cfg.stopbits, serial.STOPBITS_ONE)

        self.ser = serial.Serial(
            self.cfg.port,
            baudrate=self.cfg.baudrate,
            bytesize=self.cfg.bytesize,
            parity=parity,
            stopbits=stop,
            timeout=self.cfg.timeout,
        )

    def read(self, size=1024) -> bytes:
        if not self.ser:
            return b""
        try:
            return self.ser.read(size)
        except (serial.SerialException, OSError):
            return b""

    def write(self, data: bytes):
        if not self.ser:
            return
        try:
            self.ser.write(data)
        except (serial.SerialException, OSError):
            pass

    def close(self):
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except Exception:
                pass


class TcpEndpoint:
    def __init__(self, cfg: TcpConfig):
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.cfg.timeout)
        self.sock.connect((self.cfg.host, self.cfg.port))

    def read(self, size=1024) -> bytes:
        if not self.sock:
            return b""
        try:
            return self.sock.recv(size)
        except (socket.timeout, BlockingIOError):
            return b""
        except OSError:
            return b""

    def write(self, data: bytes):
        if not self.sock:
            return
        try:
            self.sock.sendall(data)
        except OSError:
            pass

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass


# --- Framers -----------------------------------------------------------------


class BaseFramer:
    def feed(self, data: bytes, now: float) -> List[bytes]:
        return [data] if data else []

    def flush(self) -> List[bytes]:
        return []


class SlipFramer(BaseFramer):
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes, now: float) -> List[bytes]:
        frames = []
        for b in data:
            if b == 0xC0:
                if self.buffer:
                    frames.append(bytes(self.buffer))
                self.buffer = bytearray([b])
            else:
                if self.buffer:
                    self.buffer.append(b)
        return frames

    def flush(self) -> List[bytes]:
        if self.buffer:
            f = bytes(self.buffer)
            self.buffer = bytearray()
            return [f]
        return []


class PauseFramer(BaseFramer):
    def __init__(self, pause_ms: int):
        self.buffer = bytearray()
        self.last_time: Optional[float] = None
        self.pause = pause_ms / 1000.0

    def feed(self, data: bytes, now: float) -> List[bytes]:
        frames = []
        for b in data:
            if self.last_time is not None and (now - self.last_time) > self.pause and self.buffer:
                frames.append(bytes(self.buffer))
                self.buffer = bytearray()
            self.buffer.append(b)
            self.last_time = now
        return frames

    def flush(self) -> List[bytes]:
        if self.buffer:
            f = bytes(self.buffer)
            self.buffer = bytearray()
            return [f]
        return []


class ModbusRtuFramer(PauseFramer):
    def __init__(self, baudrate: int, databits: int, parity: str, stopbits: float):
        # Character time: start + data bits + parity + stop bits
        parity_bits = 1 if parity != "N" else 0
        bits_per_char = 1 + databits + parity_bits + stopbits
        char_time = bits_per_char / float(baudrate)
        pause_ms = int(3.5 * char_time * 1000)
        pause_ms = max(pause_ms, 2)
        super().__init__(pause_ms)


class AsciiFramer(BaseFramer):
    def __init__(self, start: bytes = b":", end: bytes = b"\r\n"):
        self.buffer = bytearray()
        self.start = start or b":"
        self.end = end or b"\r\n"
        self.matching = False

    def feed(self, data: bytes, now: float) -> List[bytes]:
        frames = []
        for b in data:
            if not self.matching:
                if bytes([b]) == self.start:
                    self.buffer = bytearray([b])
                    self.matching = True
                continue
            else:
                self.buffer.append(b)
                if self.buffer.endswith(self.end):
                    frames.append(bytes(self.buffer))
                    self.buffer = bytearray()
                    self.matching = False
        return frames

    def flush(self) -> List[bytes]:
        if self.buffer:
            f = bytes(self.buffer)
            self.buffer = bytearray()
            self.matching = False
            return [f]
        return []


class MarkerFramer(BaseFramer):
    def __init__(self, start: bytes, end: bytes):
        self.start = start
        self.end = end or start
        self.buffer = bytearray()
        self.in_frame = False

    def feed(self, data: bytes, now: float) -> List[bytes]:
        frames = []
        i = 0
        while i < len(data):
            if not self.in_frame:
                if self.start and data[i : i + len(self.start)] == self.start:
                    self.buffer = bytearray(self.start)
                    self.in_frame = True
                    i += len(self.start)
                    continue
                elif not self.start:
                    self.buffer = bytearray()
                    self.in_frame = True
            else:
                self.buffer.append(data[i])
                if self.end and len(self.buffer) >= len(self.end):
                    if self.buffer[-len(self.end) :] == self.end:
                        frames.append(bytes(self.buffer))
                        self.buffer = bytearray()
                        self.in_frame = False
            i += 1
        return frames

    def flush(self) -> List[bytes]:
        if self.buffer:
            f = bytes(self.buffer)
            self.buffer = bytearray()
            self.in_frame = False
            return [f]
        return []


class RawFramer(BaseFramer):
    def feed(self, data: bytes, now: float) -> List[bytes]:
        return [data] if data else []


def make_framer(kind: str, params: dict, serial_ctx: Optional[SerialConfig]) -> BaseFramer:
    if kind == "SLIP":
        return SlipFramer()
    if kind == "Modbus RTU":
        baud = serial_ctx.baudrate if serial_ctx else 9600
        return ModbusRtuFramer(baud, params.get("databits", 8), params.get("parity", "N"), params.get("stopbits", 1))
    if kind == "ASCII":
        start = parse_hex_string(params.get("start", "3A")) or b":"
        end = parse_hex_string(params.get("end", "0D0A")) or b"\r\n"
        return AsciiFramer(start=start, end=end)
    if kind == "Pause":
        return PauseFramer(params.get("pause_ms", 20))
    if kind == "Marker":
        start = parse_hex_string(params.get("start", ""))
        end = parse_hex_string(params.get("end", ""))
        return MarkerFramer(start=start, end=end)
    return RawFramer()


# --- Worker thread -----------------------------------------------------------


class SnifferThread(threading.Thread):
    def __init__(
        self,
        source,
        target,
        framer_kind: str,
        framer_params: dict,
        log_callback: Callable[[str, str], None],
        serial_ctx_out: Optional[SerialConfig],
        serial_ctx_in: Optional[SerialConfig],
    ):
        super().__init__(daemon=True)
        self.source = source
        self.target = target
        self.log = log_callback
        self.framer_kind = framer_kind
        self.framer_params = framer_params
        self.serial_ctx_out = serial_ctx_out
        self.serial_ctx_in = serial_ctx_in
        self.running = False

    def stop(self):
        self.running = False

    def run(self):
        start_time = time.time()
        out_framer = make_framer(self.framer_kind, self.framer_params, self.serial_ctx_out)
        in_framer = make_framer(self.framer_kind, self.framer_params, self.serial_ctx_in)
        try:
            self.source.open()
            self.target.open()
        except Exception as e:
            self.log("out", self._ts(start_time) + f" ERROR open: {e}")
            return

        self.running = True
        self.log("out", self._ts(start_time) + " Sniffer started")
        while self.running:
            now = time.time()

            data = self.source.read(1024)
            if data:
                frames = out_framer.feed(data, now)
                for frame in frames:
                    self.log("out", self._ts(start_time) + f" OUT→ {hex_bytes(frame)}")
                    self.target.write(frame)

            resp = self.target.read(1024)
            if resp:
                frames = in_framer.feed(resp, now)
                for frame in frames:
                    self.log("in", self._ts(start_time) + f" ←IN {hex_bytes(frame)}")

            time.sleep(0.002)

        # flush pending frames
        for frame in out_framer.flush():
            self.log("out", self._ts(start_time) + f" OUT→ {hex_bytes(frame)}")
            self.target.write(frame)
        for frame in in_framer.flush():
            self.log("in", self._ts(start_time) + f" ←IN {hex_bytes(frame)}")

        try:
            self.source.close()
            self.target.close()
        except Exception:
            pass
        self.log("out", self._ts(start_time) + " Sniffer stopped")

    def _ts(self, start, now=None):
        if now is None:
            now = time.time()
        t = now - start
        return f"[{int(t):03}.{int((t-int(t))*1000):03}] "


# --- GUI ---------------------------------------------------------------------


class ProxyGUI(QWidget):
    log_signal = pyqtSignal(str, str)  # (target, message)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("COM/TCP Sniffer")
        self.resize(1200, 600)

        # Controls
        self.src_type = QComboBox()
        self.src_type.addItems(["Serial", "TCP"])
        self.dst_type = QComboBox()
        self.dst_type.addItems(["Serial", "TCP"])

        # Serial controls
        self.src_port = QComboBox()
        self.dst_port = QComboBox()
        self.src_baud = QComboBox()
        self.dst_baud = QComboBox()
        self.src_baud.setEditable(True)
        self.dst_baud.setEditable(True)
        baud_list = [str(b) for b in serial.Serial.BAUDRATES if b >= 300]
        for box in (self.src_baud, self.dst_baud):
            box.addItems(baud_list)
            box.setCurrentText("9600")

        self.src_data_bits = QComboBox()
        self.dst_data_bits = QComboBox()
        for box in (self.src_data_bits, self.dst_data_bits):
            box.addItems(["5", "6", "7", "8"])
            box.setCurrentText("8")

        self.src_parity = QComboBox()
        self.dst_parity = QComboBox()
        for box in (self.src_parity, self.dst_parity):
            box.addItems(["N", "E", "O", "M", "S"])
            box.setCurrentText("N")

        self.src_stop = QComboBox()
        self.dst_stop = QComboBox()
        for box in (self.src_stop, self.dst_stop):
            box.addItems(["1", "1.5", "2"])
            box.setCurrentText("1")

        # TCP controls
        self.src_host = QLineEdit("127.0.0.1")
        self.src_port_tcp = QSpinBox()
        self.src_port_tcp.setRange(1, 65535)
        self.src_port_tcp.setValue(502)
        self.dst_host = QLineEdit("127.0.0.1")
        self.dst_port_tcp = QSpinBox()
        self.dst_port_tcp.setRange(1, 65535)
        self.dst_port_tcp.setValue(502)

        # Framer selection
        self.framer_box = QComboBox()
        self.framer_box.addItems(["SLIP", "Modbus RTU", "ASCII", "Pause", "Marker", "Raw/TCP"])

        self.pause_spin = QSpinBox()
        self.pause_spin.setRange(1, 5000)
        self.pause_spin.setValue(20)
        self.marker_start = QLineEdit("")
        self.marker_end = QLineEdit("")
        self.ascii_start = QLineEdit("3A")  # ':'
        self.ascii_end = QLineEdit("0D0A")  # CRLF

        self.params_stack = QStackedWidget()
        self.params_stack.addWidget(QWidget())  # SLIP
        self.params_stack.addWidget(QWidget())  # Modbus RTU uses serial ctx

        pause_page = QWidget()
        pause_layout = QFormLayout(pause_page)
        pause_layout.addRow("Pause, ms", self.pause_spin)
        self.params_stack.addWidget(pause_page)

        marker_page = QWidget()
        marker_layout = QFormLayout(marker_page)
        marker_layout.addRow("Start (hex)", self.marker_start)
        marker_layout.addRow("End (hex)", self.marker_end)
        self.params_stack.addWidget(marker_page)

        ascii_page = QWidget()
        ascii_layout = QFormLayout(ascii_page)
        ascii_layout.addRow("Start (hex)", self.ascii_start)
        ascii_layout.addRow("End (hex)", self.ascii_end)
        self.params_stack.addWidget(ascii_page)

        self.params_stack.addWidget(QWidget())  # Raw/TCP

        # Logs
        self.out_log = QTextEdit()
        self.out_log.setReadOnly(True)
        self.out_log.setPlaceholderText("OUT→")
        self.in_log = QTextEdit()
        self.in_log.setReadOnly(True)
        self.in_log.setPlaceholderText("←IN")

        # Buttons
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)

        # Layouts
        top_layout = QHBoxLayout()
        top_layout.addWidget(self._build_endpoint_group("Source", self.src_type, self.src_port, self.src_baud, self.src_data_bits, self.src_parity, self.src_stop, self.src_host, self.src_port_tcp))
        top_layout.addWidget(self._build_endpoint_group("Target", self.dst_type, self.dst_port, self.dst_baud, self.dst_data_bits, self.dst_parity, self.dst_stop, self.dst_host, self.dst_port_tcp))

        framer_group = QGroupBox("Framing")
        fg_layout = QHBoxLayout(framer_group)
        fg_layout.addWidget(QLabel("Strategy:"))
        fg_layout.addWidget(self.framer_box)
        fg_layout.addWidget(self.params_stack)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addStretch()

        logs_layout = QHBoxLayout()
        logs_layout.addWidget(self.out_log)
        logs_layout.addWidget(self.in_log)

        layout = QVBoxLayout()
        layout.addLayout(top_layout)
        layout.addWidget(framer_group)
        layout.addLayout(button_layout)
        layout.addLayout(logs_layout)
        self.setLayout(layout)

        # State
        self.thread: Optional[SnifferThread] = None

        # Signals
        self.start_button.clicked.connect(self.start_sniffer)
        self.stop_button.clicked.connect(self.stop_sniffer)
        self.framer_box.currentIndexChanged.connect(self._on_framer_changed)
        self.src_type.currentIndexChanged.connect(self._toggle_src_view)
        self.dst_type.currentIndexChanged.connect(self._toggle_dst_view)
        self.log_signal.connect(self._log)

        # Timers
        self.last_ports: List[str] = []
        self.auto_update_timer = QTimer(self)
        self.auto_update_timer.timeout.connect(self.detect_ports)
        self.auto_update_timer.start(1000)
        self.detect_ports()
        self._on_framer_changed(0)
        self._toggle_src_view()
        self._toggle_dst_view()

    # UI builders ---------------------------------------------------------
    def _build_endpoint_group(self, title, type_box, port_box, baud_box, data_box, parity_box, stop_box, host_edit, port_spin):
        group = QGroupBox(title)
        layout = QFormLayout(group)
        layout.addRow("Type", type_box)
        layout.addRow("Port", port_box)
        layout.addRow("Baud", baud_box)
        layout.addRow("Data bits", data_box)
        layout.addRow("Parity", parity_box)
        layout.addRow("Stop bits", stop_box)
        layout.addRow("Host", host_edit)
        layout.addRow("TCP Port", port_spin)
        return group

    # Slots ----------------------------------------------------------------
    def detect_ports(self):
        ports = [port.device for port in list_ports.comports()]
        if ports != self.last_ports:
            current_src = self.src_port.currentText()
            current_dst = self.dst_port.currentText()
            self.src_port.clear()
            self.dst_port.clear()
            self.src_port.addItems(ports)
            self.dst_port.addItems(ports)
            if current_src in ports:
                self.src_port.setCurrentText(current_src)
            if current_dst in ports:
                self.dst_port.setCurrentText(current_dst)
            self.last_ports = ports

    def _toggle_src_view(self):
        is_serial = self.src_type.currentText() == "Serial"
        for w in [self.src_port, self.src_baud, self.src_data_bits, self.src_parity, self.src_stop]:
            w.setEnabled(is_serial)
        for w in [self.src_host, self.src_port_tcp]:
            w.setEnabled(not is_serial)

    def _toggle_dst_view(self):
        is_serial = self.dst_type.currentText() == "Serial"
        for w in [self.dst_port, self.dst_baud, self.dst_data_bits, self.dst_parity, self.dst_stop]:
            w.setEnabled(is_serial)
        for w in [self.dst_host, self.dst_port_tcp]:
            w.setEnabled(not is_serial)

    def _on_framer_changed(self, idx):
        # Align stack index with framer order
        mapping = {
            "SLIP": 0,
            "Modbus RTU": 1,
            "ASCII": 4,
            "Pause": 2,
            "Marker": 3,
            "Raw/TCP": 5,
        }
        name = self.framer_box.currentText()
        self.params_stack.setCurrentIndex(mapping.get(name, 0))

    def _log(self, target: str, message: str):
        if target == "out":
            self.out_log.append(message)
            self.out_log.moveCursor(QTextCursor.End)
        else:
            self.in_log.append(message)
            self.in_log.moveCursor(QTextCursor.End)

    # Actions --------------------------------------------------------------
    def start_sniffer(self):
        if self.thread:
            return
        try:
            src_cfg, dst_cfg = self._build_endpoints()
            framer_params = self._collect_framer_params()
        except ValueError as e:
            self.log_signal.emit("out", f"Config error: {e}")
            return

        serial_ctx_out = src_cfg if isinstance(src_cfg, SerialConfig) else None
        serial_ctx_in = dst_cfg if isinstance(dst_cfg, SerialConfig) else None

        self.thread = SnifferThread(
            self._make_endpoint(src_cfg),
            self._make_endpoint(dst_cfg),
            self.framer_box.currentText(),
            framer_params,
            self.log_signal.emit,
            serial_ctx_out,
            serial_ctx_in,
        )
        self.thread.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_sniffer(self):
        if self.thread:
            self.thread.stop()
            self.thread.join()
            self.thread = None
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    # Builders -------------------------------------------------------------
    def _build_endpoints(self):
        src_type = self.src_type.currentText()
        dst_type = self.dst_type.currentText()

        if src_type == "Serial":
            src_cfg = SerialConfig(
                port=self.src_port.currentText(),
                baudrate=int(self.src_baud.currentText()),
                bytesize=int(self.src_data_bits.currentText()),
                parity=self.src_parity.currentText(),
                stopbits=float(self.src_stop.currentText()),
            )
        else:
            src_cfg = TcpConfig(
                host=self.src_host.text().strip() or "127.0.0.1",
                port=int(self.src_port_tcp.value()),
            )

        if dst_type == "Serial":
            dst_cfg = SerialConfig(
                port=self.dst_port.currentText(),
                baudrate=int(self.dst_baud.currentText()),
                bytesize=int(self.dst_data_bits.currentText()),
                parity=self.dst_parity.currentText(),
                stopbits=float(self.dst_stop.currentText()),
            )
        else:
            dst_cfg = TcpConfig(
                host=self.dst_host.text().strip() or "127.0.0.1",
                port=int(self.dst_port_tcp.value()),
            )
        return src_cfg, dst_cfg

    def _make_endpoint(self, cfg):
        if isinstance(cfg, SerialConfig):
            return SerialEndpoint(cfg)
        return TcpEndpoint(cfg)

    def _collect_framer_params(self):
        name = self.framer_box.currentText()
        if name == "Pause":
            return {"pause_ms": self.pause_spin.value()}
        if name == "Marker":
            return {"start": self.marker_start.text(), "end": self.marker_end.text()}
        if name == "ASCII":
            return {"start": self.ascii_start.text(), "end": self.ascii_end.text()}
        if name == "Modbus RTU":
            return {
                "databits": int(self.src_data_bits.currentText()),
                "parity": self.src_parity.currentText(),
                "stopbits": float(self.src_stop.currentText()),
            }
        return {}


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ProxyGUI()
    window.show()
    sys.exit(app.exec_())
