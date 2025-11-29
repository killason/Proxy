import sys
import time
import serial
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QComboBox, QTextEdit, QVBoxLayout, QHBoxLayout, QSpinBox, QCheckBox, QSplitter
from PyQt5.QtCore import pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QTextCursor
from serial.tools import list_ports

def filter_duplicate(packet: bytes, last_packet: bytes) -> bool:
    return packet != last_packet

class ProxyGUI(QWidget):
    log_signal = pyqtSignal(str, str)  # (target, message)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SLIP Proxy для МТЗП")
        self.resize(1200, 500)

        self.input_box = QComboBox()
        self.output_box = QComboBox()
        self.baud_box = QComboBox()
        self.delay_spin = QSpinBox()
        self.dup_filter_box = QCheckBox("Фильтровать дубликаты")
        self.dup_filter_box.setChecked(True)
        self.start_button = QPushButton("Старт")
        self.stop_button = QPushButton("Стоп")

        self.baud_box.addItems(["9600", "19200", "38400", "57600", "115200"])
        self.delay_spin.setRange(0, 1000)
        self.delay_spin.setValue(300)

        # Три текстовых окна
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setPlaceholderText("RAW и PACKET")
        self.send_text = QTextEdit()
        self.send_text.setReadOnly(True)
        self.send_text.setPlaceholderText("SEND")
        self.recv_text = QTextEdit()
        self.recv_text.setReadOnly(True)
        self.recv_text.setPlaceholderText("RECV (от устройства)")

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.raw_text)
        splitter.addWidget(self.send_text)
        splitter.addWidget(self.recv_text)
        splitter.setSizes([400, 400, 400])

        layout = QVBoxLayout()
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("COM от программы:"))
        h1.addWidget(self.input_box)
        h1.addWidget(QLabel("→ к МТЗП:"))
        h1.addWidget(self.output_box)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Скорость:"))
        h2.addWidget(self.baud_box)
        h2.addWidget(QLabel("Задержка (мс):"))
        h2.addWidget(self.delay_spin)
        h2.addWidget(self.dup_filter_box)

        h3 = QHBoxLayout()
        h3.addWidget(self.start_button)
        h3.addWidget(self.stop_button)

        layout.addLayout(h1)
        layout.addLayout(h2)
        layout.addLayout(h3)
        layout.addWidget(splitter)

        self.setLayout(layout)

        self.thread = None
        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button.clicked.connect(self.stop_proxy)

        self.log_signal.connect(self.log)

        self.last_ports = []
        self.auto_update_timer = QTimer(self)
        self.auto_update_timer.timeout.connect(self.auto_update_ports)
        self.auto_update_timer.start(1000)
        self.detect_ports()

    def detect_ports(self):
        ports = [port.device for port in list_ports.comports()]
        self.input_box.blockSignals(True)
        self.output_box.blockSignals(True)
        self.input_box.clear()
        self.output_box.clear()
        self.input_box.addItems(ports)
        self.output_box.addItems(ports)
        self.input_box.blockSignals(False)
        self.output_box.blockSignals(False)
        self.last_ports = ports

    def auto_update_ports(self):
        ports = [port.device for port in list_ports.comports()]
        if ports != self.last_ports:
            current_in = self.input_box.currentText()
            current_out = self.output_box.currentText()
            self.detect_ports()
            idx_in = self.input_box.findText(current_in)
            if idx_in >= 0:
                self.input_box.setCurrentIndex(idx_in)
            idx_out = self.output_box.findText(current_out)
            if idx_out >= 0:
                self.output_box.setCurrentIndex(idx_out)

    def log(self, target, message):
        if target == "raw":
            self.raw_text.append(message)
            self.raw_text.moveCursor(QTextCursor.End)
        elif target == "send":
            self.send_text.append(message)
            self.send_text.moveCursor(QTextCursor.End)
        elif target == "recv":
            self.recv_text.append(message)
            self.recv_text.moveCursor(QTextCursor.End)

    def start_proxy(self):
        in_port = self.input_box.currentText()
        out_port = self.output_box.currentText()
        if in_port == out_port:
            self.log("raw", "Ошибка: выберите разные COM-порты!")
            return
        baud = int(self.baud_box.currentText())
        delay = self.delay_spin.value()
        dup_filter = self.dup_filter_box.isChecked()
        self.thread = ProxyThread(in_port, out_port, baud, delay, self.log_signal.emit, dup_filter)
        self.thread.start()

    def stop_proxy(self):
        if self.thread:
            self.thread.stop()
            self.thread.join()
            self.thread = None

class ProxyThread(threading.Thread):
    def __init__(self, input_port, output_port, baudrate, delay_ms, log_callback, dup_filter):
        super().__init__()
        self.input_port = input_port
        self.output_port = output_port
        self.baudrate = baudrate
        self.delay = delay_ms / 1000.0
        self.log = log_callback
        self.dup_filter = dup_filter
        self.running = False
        self.last_packet = b""
        self.current_packet = b""
        self.collecting = False

    def stop(self):
        self.running = False

    def run(self):
        ser_in = None
        ser_out = None
        recv_packet = b""
        start_time = time.time()
        last_send_time = 0
        try:
            ser_in = serial.Serial(self.input_port, self.baudrate, timeout=0.01)
            ser_out = serial.Serial(self.output_port, self.baudrate, timeout=0.01)
            self.running = True
            self.log("raw", self._ts(start_time, start_time) + " Прокси запущен")

            while self.running:
                # --- Основное направление ---
                try:
                    data = ser_in.read(ser_in.in_waiting or 1)
                except serial.SerialException as e:
                    self.log("raw", self._ts(start_time) + f" Ошибка чтения из {self.input_port}: {e}")
                    break
                except OSError as e:
                    self.log("raw", self._ts(start_time) + f" Устройство {self.input_port} отключено: {e}")
                    break

                for b in data:
                    byte = bytes([b])
                    if byte == b"\xC0":
                        if self.current_packet:
                            self.log("raw", self._ts(start_time) + f" ▶ RAW: {self.current_packet.hex(' ').upper()}")
                            if (not self.dup_filter) or filter_duplicate(self.current_packet, self.last_packet):
                                self.log("raw", self._ts(start_time) + f" ▶ PACKET: {self.current_packet.hex(' ').upper()}")
                                now = time.time()
                                elapsed = now - last_send_time
                                if elapsed < self.delay:
                                    time.sleep(self.delay - elapsed)
                                try:
                                    ser_out.write(self.current_packet)
                                    self.log("send", self._ts(start_time) + f" ➡ SEND: {self.current_packet.hex(' ').upper()}")
                                except (serial.SerialException, OSError) as e:
                                    self.log("raw", self._ts(start_time) + f" Ошибка записи в {self.output_port}: {e}")
                                    break
                                self.last_packet = self.current_packet
                                last_send_time = time.time()
                        self.current_packet = byte
                    else:
                        if self.current_packet:
                            self.current_packet += byte

                # --- Обратное направление ---
                try:
                    response = ser_out.read(ser_out.in_waiting or 1)
                except (serial.SerialException, OSError) as e:
                    self.log("recv", self._ts(start_time) + f" Ошибка чтения из {self.output_port}: {e}")
                    break

                for b in response:
                    byte = bytes([b])
                    if byte == b"\xC0":
                        if recv_packet:
                            self.log("recv", self._ts(start_time) + f" ◀ RAW: {recv_packet.hex(' ').upper()}")
                            try:
                                ser_in.write(recv_packet)
                                self.log("recv", self._ts(start_time) + f" ◀ RECV: {recv_packet.hex(' ').upper()}")
                            except (serial.SerialException, OSError) as e:
                                self.log("recv", self._ts(start_time) + f" Ошибка записи в {self.input_port}: {e}")
                                break
                        recv_packet = byte
                    else:
                        if recv_packet:
                            recv_packet += byte

                time.sleep(0.001)

            # Обработка висячих пакетов при завершении
            if self.current_packet:
                self.log("raw", self._ts(start_time) + f" ▶ RAW: {self.current_packet.hex(' ').upper()}")
                if (not self.dup_filter) or filter_duplicate(self.current_packet, self.last_packet):
                    self.log("raw", self._ts(start_time) + f" ▶ PACKET: {self.current_packet.hex(' ').upper()}")
                    try:
                        ser_out.write(self.current_packet)
                        self.log("send", self._ts(start_time) + f" ➡ SEND: {self.current_packet.hex(' ').upper()}")
                    except Exception:
                        pass
            if recv_packet:
                self.log("recv", self._ts(start_time) + f" ◀ RAW: {recv_packet.hex(' ').upper()}")
                try:
                    ser_in.write(recv_packet)
                    self.log("recv", self._ts(start_time) + f" ◀ RECV: {recv_packet.hex(' ').upper()}")
                except Exception:
                    pass

        except (serial.SerialException, OSError) as e:
            self.log("raw", self._ts(start_time) + f" Ошибка открытия порта: {e}")
        except Exception as e:
            self.log("raw", self._ts(start_time) + f" Ошибка: {e}")
        finally:
            try:
                if ser_in and ser_in.is_open:
                    ser_in.close()
                if ser_out and ser_out.is_open:
                    ser_out.close()
            except Exception as close_err:
                self.log("raw", self._ts(start_time) + f" Ошибка при закрытии порта: {close_err}")
            self.log("raw", self._ts(start_time) + " Прокси остановлен")

    def _ts(self, start_time, now=None):
        if now is None:
            now = time.time()
        t = now - start_time
        return f"[{int(t):03}.{int((t-int(t))*1000):03}]"

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ProxyGUI()
    window.show()
    sys.exit(app.exec_())
