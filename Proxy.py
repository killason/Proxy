import struct
import sys
import time
import socket
import threading
from dataclasses import dataclass
from typing import Callable, List, Optional
from pathlib import Path
from sniffer import (
    SerialConfig,
    TcpConfig,
    SerialEndpoint,
    TcpEndpoint,
    SnifferThread,
    make_framer,
)

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
    QSizePolicy,
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


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def crc16_modbus_bytes(data: bytes) -> bytes:
    return struct.pack("<H", crc16_modbus(data))


# --- Endpoint configs --------------------------------------------------------

# @dataclass
# class SerialConfig:
#     port: str
#     baudrate: int
#     bytesize: int
#     parity: str
#     stopbits: float
#     timeout: float = 0


# @dataclass
# class TcpConfig:
#     host: str
#     port: int
#     timeout: float = 0.05


# class SerialEndpoint:
#     def __init__(self, cfg: SerialConfig):
#         self.cfg = cfg
#         self.ser: Optional[serial.Serial] = None

#     def open(self):
#         parity = {
#             "N": serial.PARITY_NONE,
#             "E": serial.PARITY_EVEN,
#             "O": serial.PARITY_ODD,
#             "M": serial.PARITY_MARK,
#             "S": serial.PARITY_SPACE,
#         }.get(self.cfg.parity, serial.PARITY_NONE)

#         stop = {
#             1: serial.STOPBITS_ONE,
#             1.5: serial.STOPBITS_ONE_POINT_FIVE,
#             2: serial.STOPBITS_TWO,
#         }.get(self.cfg.stopbits, serial.STOPBITS_ONE)

#         self.ser = serial.Serial(
#             port=self.cfg.port,
#             baudrate=self.cfg.baudrate,
#             bytesize=self.cfg.bytesize,
#             parity=parity,
#             stopbits=stop,
#             timeout=0,
#             write_timeout=0.2,
#             inter_byte_timeout=None,
#             exclusive=True,
#         )

#         self.ser.reset_input_buffer()
#         self.ser.reset_output_buffer()

#     def read(self, size=1024) -> bytes:
#         if not self.ser or not self.ser.is_open:
#             return b""

#         try:
#             waiting = self.ser.in_waiting

#             if waiting == 0:
#                 return b""

#             return self.ser.read(waiting)

#         except (serial.SerialException, OSError, TypeError, ValueError):
#             return b""

#     def write(self, data: bytes):
#         if not self.ser or not self.ser.is_open:
#             return

#         if not data:
#             return

#         try:
#             view = memoryview(data)

#             while view:
#                 written = self.ser.write(view)

#                 if written is None:
#                     break

#                 if written == 0:
#                     break

#                 view = view[written:]

#         except (
#             serial.SerialTimeoutException,
#             serial.SerialException,
#             OSError,
#             TypeError,
#             ValueError,
#         ):
#             pass

#     def close(self):
#         ser = self.ser
#         self.ser = None
#         if ser and ser.is_open:
#             try:
#                 ser.cancel_read()
#             except Exception:
#                 pass
#             try:
#                 ser.close()
#             except Exception:
#                 pass


# class TcpEndpoint:
#     def __init__(self, cfg: TcpConfig):
#         self.cfg = cfg
#         self.sock: Optional[socket.socket] = None

#     def open(self):
#         self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.sock.settimeout(self.cfg.timeout)
#         self.sock.connect((self.cfg.host, self.cfg.port))

#     def read(self, size=1024) -> bytes:
#         if not self.sock:
#             return b""
#         try:
#             return self.sock.recv(size)
#         except (socket.timeout, BlockingIOError):
#             return b""
#         except OSError:
#             return b""

#     def write(self, data: bytes):
#         if not self.sock:
#             return
#         try:
#             self.sock.sendall(data)
#         except OSError:
#             pass

#     def close(self):
#         if self.sock:
#             try:
#                 self.sock.close()
#             except Exception:
#                 pass


# --- Framers -----------------------------------------------------------------


# class BaseFramer:
#     def feed(self, data: bytes, now: float) -> List[bytes]:
#         return [data] if data else []

#     def flush(self, now: Optional[float] = None) -> List[bytes]:
#         return []


# class SlipFramer(BaseFramer):
#     def __init__(self):
#         self.buffer = bytearray()
#         self.in_frame = False
#         self.escaped = False

#     def feed(self, data: bytes, now: float) -> List[bytes]:
#         frames = []
#         if not data:
#             return frames

#         for b in data:
#             if self.escaped:
#                 if b == 0xDC:
#                     self.buffer.append(0xC0)
#                 elif b == 0xDD:
#                     self.buffer.append(0xDB)
#                 else:
#                     self.buffer.append(b)
#                 self.escaped = False
#                 continue

#             if b == 0xDB:
#                 self.escaped = True
#                 continue

#             if b == 0xC0:
#                 if self.in_frame:
#                     if self.buffer:
#                         frames.append(bytes(self.buffer))
#                     self.buffer = bytearray()
#                     self.in_frame = False
#                 else:
#                     self.buffer = bytearray()
#                     self.in_frame = True
#                 continue

#             if self.in_frame:
#                 self.buffer.append(b)

#         return frames

#     def flush(self, now: Optional[float] = None) -> List[bytes]:
#         if self.buffer and not self.in_frame:
#             f = bytes(self.buffer)
#             self.buffer = bytearray()
#             self.escaped = False
#             return [f] if f else []
#         return []


# class PauseFramer(BaseFramer):
#     def __init__(self, pause_ms: int):
#         self.pause = max(pause_ms / 1000.0, 0.001)
#         self.buffer = bytearray()
#         self.last_rx = None

#     def feed(self, data: bytes, now: float) -> list[bytes]:
#         if not data:
#             return []

#         self.buffer.extend(data)
#         self.last_rx = now
#         print("FEED", len(self.buffer), round(now, 3))

#         return []

#     def flush(self, now: float | None = None) -> list[bytes]:
#         if not self.buffer:
#             return []

#         if self.last_rx is None:
#             return []

#         if now is None:
#             now = time.monotonic()

#         dt = now - self.last_rx

#         print(
#             "DT",
#             round(dt, 3),
#             "PAUSE",
#             round(self.pause, 3),
#             "BUF",
#             len(self.buffer),
#         )

#         if dt < self.pause:
#             return []

#         frame = bytes(self.buffer)

#         self.buffer.clear()
#         self.last_rx = None

#         print("EMIT", len(frame))

#         return [frame]


# class ModbusRtuFramer(PauseFramer):
#     def __init__(self, baudrate: int, databits: int, parity: str, stopbits: float):
#         parity_bits = 0 if parity == "N" else 1
#         bits_per_char = 1 + databits + parity_bits + stopbits

#         char_time = bits_per_char / float(baudrate)
#         pause_ms = max(int(char_time * 3.5 * 1000), 1)

#         super().__init__(pause_ms)


# class AsciiFramer(BaseFramer):
#     def __init__(self, start: bytes = b":", end: bytes = b"\r\n"):
#         self.buffer = bytearray()
#         self.start = start or b":"
#         self.end = end or b"\r\n"
#         self.matching = False

#     def feed(self, data: bytes, now: float) -> List[bytes]:
#         frames = []
#         for b in data:
#             if not self.matching:
#                 if bytes([b]) == self.start:
#                     self.buffer = bytearray([b])
#                     self.matching = True
#                 continue
#             else:
#                 self.buffer.append(b)
#                 if self.buffer.endswith(self.end):
#                     frames.append(bytes(self.buffer))
#                     self.buffer = bytearray()
#                     self.matching = False
#         return frames

#     def flush(self, now: Optional[float] = None) -> List[bytes]:
#         if self.buffer and now is None:
#             f = bytes(self.buffer)
#             self.buffer = bytearray()
#             self.matching = False
#             return [f]
#         return []


# class MarkerFramer(BaseFramer):
#     def __init__(self, start: bytes, end: bytes):
#         self.start = start
#         self.end = end or start
#         self.buffer = bytearray()
#         self.in_frame = False

#     def feed(self, data: bytes, now: float) -> List[bytes]:
#         frames = []
#         if not data:
#             return frames

#         self.buffer.extend(data)

#         while True:
#             if not self.in_frame:
#                 if self.start:
#                     idx = self.buffer.find(self.start)
#                     if idx < 0:
#                         self.buffer = bytearray()
#                         break
#                     self.buffer = self.buffer[idx + len(self.start) :]
#                     self.in_frame = True
#                 else:
#                     self.in_frame = True

#             if not self.end:
#                 frames.append(bytes(self.buffer))
#                 self.buffer = bytearray()
#                 self.in_frame = False
#                 break

#             idx = self.buffer.find(self.end)
#             if idx < 0:
#                 break

#             frame = bytes(self.buffer[:idx])
#             if frame:
#                 frames.append(frame)
#             self.buffer = self.buffer[idx + len(self.end) :]
#             self.in_frame = False

#         return frames

#     def flush(self, now: Optional[float] = None) -> List[bytes]:
#         if self.buffer and now is None:
#             f = bytes(self.buffer)
#             self.buffer = bytearray()
#             self.in_frame = False
#             return [f]
#         return []


# class RawFramer(BaseFramer):
#     def feed(self, data: bytes, now: float) -> List[bytes]:
#         return [data] if data else []


# def make_framer(kind: str, params: dict, serial_ctx: Optional[SerialConfig]) -> BaseFramer:
#     if kind == "SLIP":
#         return SlipFramer()
#     if kind == "Modbus RTU":
#         baud = serial_ctx.baudrate if serial_ctx else 9600
#         return ModbusRtuFramer(baud, params.get("databits", 8), params.get("parity", "N"), params.get("stopbits", 1))
#     if kind == "ASCII":
#         start = parse_hex_string(params.get("start", "3A")) or b":"
#         end = parse_hex_string(params.get("end", "0D0A")) or b"\r\n"
#         return AsciiFramer(start=start, end=end)
#     if kind == "Pause":
#         return PauseFramer(params.get("pause_ms", 20))
#     if kind == "Marker":
#         start = parse_hex_string(params.get("start", ""))
#         end = parse_hex_string(params.get("end", ""))
#         return MarkerFramer(start=start, end=end)
#     return RawFramer()


# --- Worker thread -----------------------------------------------------------


# class SnifferThread(threading.Thread):
#     def __init__(
#         self,
#         source,
#         target,
#         framer_kind: str,
#         framer_params: dict,
#         log_callback: Callable[[str, str], None],
#         serial_ctx_out: Optional[SerialConfig],
#         serial_ctx_in: Optional[SerialConfig],
#     ):
#         super().__init__(daemon=True)

#         self.source = source
#         self.target = target

#         self.log = log_callback

#         self.framer_kind = framer_kind
#         self.framer_params = framer_params

#         self.serial_ctx_out = serial_ctx_out
#         self.serial_ctx_in = serial_ctx_in

#         self.running = False

#         self._threads = []

#     def stop(self):
#         self.running = False

#         for t in self._threads:
#             try:
#                 t.join(timeout=0.5)
#             except Exception:
#                 pass

#         try:
#             self.source.close()
#         except Exception:
#             pass

#         try:
#             self.target.close()
#         except Exception:
#             pass

#     def run(self):

#         start_time = time.time()

#         try:
#             self.source.open()
#             self.target.open()
#         except Exception as e:
#             self.log("out", self._ts(start_time) + f" ERROR open: {e}")
#             return

#         self.running = True

#         self.log("out", self._ts(start_time) + " Sniffer started")

#         out_framer = make_framer(
#             self.framer_kind,
#             self.framer_params,
#             self.serial_ctx_out,
#         )

#         in_framer = make_framer(
#             self.framer_kind,
#             self.framer_params,
#             self.serial_ctx_in,
#         )

#         t1 = threading.Thread(
#             target=self._forward,
#             daemon=True,
#             args=(
#                 self.source,
#                 self.target,
#                 out_framer,
#                 "out",
#                 start_time,
#                 " OUT→ ",
#             ),
#         )

#         t2 = threading.Thread(
#             target=self._forward,
#             daemon=True,
#             args=(
#                 self.target,
#                 self.source,
#                 in_framer,
#                 "in",
#                 start_time,
#                 " ←IN ",
#             ),
#         )

#         self._threads = [t1, t2]

#         t1.start()
#         t2.start()

#         while self.running:

#             if not t1.is_alive():
#                 break

#             if not t2.is_alive():
#                 break

#             time.sleep(0.05)

#         self.running = False

#     def _forward(
#         self,
#         rx,
#         tx,
#         framer,
#         log_target,
#         start_time,
#         prefix,
#     ):
#         while self.running:

#             try:
#                 data = rx.read(4096)
#             except Exception:
#                 break

#             if data:

#                 # Передача всегда сразу.
#                 try:
#                     tx.write(data)
#                 except Exception:
#                     pass

#                 now = time.monotonic()

#                 #
#                 # RAW / ASCII / MARKER / SLIP могут вернуть кадры сразу.
#                 #
#                 frames = framer.feed(data, now)

#                 if frames:
#                     for frame in frames:
#                         self.log(
#                             log_target,
#                             self._ts(start_time)
#                             + prefix
#                             + hex_bytes(frame),
#                         )

#             #
#             # Для режимов, работающих по таймауту
#             # (Pause, Modbus RTU), проверяем окончание кадра
#             # каждый проход цикла.
#             #
#             now = time.monotonic()

#             frames = framer.flush(now)

#             if frames:
#                 for frame in frames:
#                     self.log(
#                         log_target,
#                         self._ts(start_time)
#                         + prefix
#                         + hex_bytes(frame),
#                     )

#             #
#             # Не грузим процессор.
#             #
#             time.sleep(0.001)


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
        self.framer_box.setMinimumWidth(140)
        self.framer_box.setMaximumWidth(140)
        self.framer_box.setSizeAdjustPolicy(QComboBox.AdjustToContents)

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
        pause_layout = QHBoxLayout(pause_page)
        pause_layout.setContentsMargins(0, 0, 0, 0)
        pause_layout.setSpacing(6)
        pause_layout.addWidget(QLabel("Pause, ms"))
        pause_layout.addWidget(self.pause_spin)
        self.params_stack.addWidget(pause_page)

        marker_page = QWidget()
        marker_layout = QHBoxLayout(marker_page)
        marker_layout.setContentsMargins(0, 0, 0, 0)
        marker_layout.setSpacing(6)
        marker_layout.addWidget(QLabel("Start"))
        marker_layout.addWidget(self.marker_start)
        marker_layout.addWidget(QLabel("End"))
        marker_layout.addWidget(self.marker_end)
        self.params_stack.addWidget(marker_page)

        ascii_page = QWidget()
        ascii_layout = QHBoxLayout(ascii_page)
        ascii_layout.setContentsMargins(0, 0, 0, 0)
        ascii_layout.setSpacing(6)
        ascii_layout.addWidget(QLabel("Start"))
        ascii_layout.addWidget(self.ascii_start)
        ascii_layout.addWidget(QLabel("End"))
        ascii_layout.addWidget(self.ascii_end)
        self.params_stack.addWidget(ascii_page)

        self.params_stack.addWidget(QWidget())  # Raw/TCP
        self.params_stack.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.params_stack.setFixedHeight(32)

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
        fg_layout.setContentsMargins(8, 8, 8, 8)
        fg_layout.setSpacing(8)
        fg_layout.addWidget(QLabel("Strategy:"), 0, Qt.AlignLeft)
        fg_layout.addWidget(self.framer_box, 0, Qt.AlignLeft)
        fg_layout.addWidget(self.params_stack, 0, Qt.AlignLeft)
        fg_layout.addStretch(1)
        framer_group.setMaximumHeight(90)

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
        self._sync_scroll = False

        self.out_log.verticalScrollBar().valueChanged.connect(
            self._sync_from_out
        )

        self.in_log.verticalScrollBar().valueChanged.connect(
            self._sync_from_in
        )

        self._connect_validation_signals()

        # Timers
        self.last_ports: List[str] = []
        self.auto_update_timer = QTimer(self)
        self.auto_update_timer.timeout.connect(self.detect_ports)
        self.auto_update_timer.start(1000)
        self.detect_ports()
        self._on_framer_changed(0)
        self._toggle_src_view()
        self._toggle_dst_view()

    def _sync_from_out(self, value):

        if self._sync_scroll:
            return

        self._sync_scroll = True

        self.in_log.verticalScrollBar().setValue(value)

        self._sync_scroll = False


    def _sync_from_in(self, value):

        if self._sync_scroll:
            return

        self._sync_scroll = True

        self.out_log.verticalScrollBar().setValue(value)

        self._sync_scroll = False

    def _connect_validation_signals(self):
        for widget in [
            self.src_type,
            self.dst_type,
            self.src_port,
            self.dst_port,
            self.src_baud,
            self.dst_baud,
            self.src_data_bits,
            self.dst_data_bits,
            self.src_parity,
            self.dst_parity,
            self.src_stop,
            self.dst_stop,
            self.src_host,
            self.dst_host,
            self.src_port_tcp,
            self.dst_port_tcp,
        ]:
            if isinstance(widget, QComboBox):
                widget.currentIndexChanged.connect(self._validate_current_configuration)
            elif isinstance(widget, QLineEdit):
                widget.textChanged.connect(self._validate_current_configuration)
            elif isinstance(widget, QSpinBox):
                widget.valueChanged.connect(self._validate_current_configuration)

    def _validate_serial_endpoint(self, label: str, cfg: SerialConfig) -> bool:
        try:
            endpoint = SerialEndpoint(cfg)
            endpoint.open()
            endpoint.close()
            return True
        except Exception as e:
            self.log_signal.emit("info", f"{label} config check: {e}")
            return False

    def _validate_current_configuration(self):
        try:
            src_cfg, dst_cfg = self._build_endpoints()
        except ValueError as e:
            self.log_signal.emit("info", f"Config error: {e}")
            return False

        if isinstance(src_cfg, SerialConfig) and not self._validate_serial_endpoint("Source", src_cfg):
            return False
        if isinstance(dst_cfg, SerialConfig) and not self._validate_serial_endpoint("Target", dst_cfg):
            return False
        return True

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

        # Добавляем tty0tty
        for p in sorted(Path("/dev").glob("tnt*")):
            if p.is_char_device():
                ports.append(str(p))

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
            self.in_log.append("")

            self.out_log.moveCursor(QTextCursor.End)
            self.in_log.moveCursor(QTextCursor.End)

        elif target == "in":

            self.out_log.append("")
            self.in_log.append(message)

            self.out_log.moveCursor(QTextCursor.End)
            self.in_log.moveCursor(QTextCursor.End)

        else:

            self.out_log.append(message)
            self.in_log.append(message)

            self.out_log.moveCursor(QTextCursor.End)
            self.in_log.moveCursor(QTextCursor.End)

    # Actions --------------------------------------------------------------
    def start_sniffer(self):
        if self.thread:
            return
        try:
            src_cfg, dst_cfg = self._build_endpoints()
            framer_params = self._collect_framer_params()
        except ValueError as e:
            self.log_signal.emit("info", f"Config error: {e}")
            return

        if not self._validate_current_configuration():
            self.log_signal.emit("info", "Start aborted: serial port could not be opened")
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
            self.thread.join(timeout=1.0)
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
