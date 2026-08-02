import time
import socket
import serial
import threading

from typing import Optional, Callable
from dataclasses import dataclass
from abc import ABC, abstractmethod

def hex_bytes(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)

@dataclass
class SerialConfig:
    port: str
    baudrate: int
    bytesize: int
    parity: str
    stopbits: float

@dataclass
class TcpConfig:
    host: str
    port: int

class Endpoint(ABC):

    @abstractmethod
    def open(self):
        ...

    @abstractmethod
    def close(self):
        ...

    @abstractmethod
    def read(self, size=4096) -> bytes:
        ...

    @abstractmethod
    def write(self, data: bytes):
        ...

class SerialEndpoint(Endpoint):

    def __init__(self, cfg: SerialConfig):
        self.cfg = cfg
        self.ser: Optional[serial.Serial] = None

    def open(self):

        if self.ser and self.ser.is_open:
            return

        parity = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
            "M": serial.PARITY_MARK,
            "S": serial.PARITY_SPACE,
        }.get(self.cfg.parity, serial.PARITY_NONE)

        stopbits = {
            1: serial.STOPBITS_ONE,
            1.5: serial.STOPBITS_ONE_POINT_FIVE,
            2: serial.STOPBITS_TWO,
        }.get(self.cfg.stopbits, serial.STOPBITS_ONE)

        self.ser = serial.Serial(
            port=self.cfg.port,
            baudrate=self.cfg.baudrate,
            bytesize=self.cfg.bytesize,
            parity=parity,
            stopbits=stopbits,
            timeout=0,
            write_timeout=0.2,
        )

    def close(self):

        if self.ser:

            try:
                self.ser.close()
            except Exception:
                pass

            self.ser = None

    def read(self, size=4096) -> bytes:

        if not self.ser:
            return b""

        if not self.ser.is_open:
            return b""

        try:

            waiting = self.ser.in_waiting

            if waiting <= 0:
                return b""

            return self.ser.read(waiting)

        except (
            serial.SerialException,
            serial.SerialTimeoutException,
            OSError,
            ValueError,
            TypeError,
        ):
            return b""

    def write(self, data: bytes):

        if not data:
            return

        if not self.ser:
            return

        if not self.ser.is_open:
            return

        try:

            view = memoryview(data)

            while len(view):

                written = self.ser.write(view)

                if written is None:
                    break

                if written <= 0:
                    break

                view = view[written:]

        except (
            serial.SerialException,
            serial.SerialTimeoutException,
            OSError,
            ValueError,
            TypeError,
        ):
            pass

class TcpEndpoint(Endpoint):

    def __init__(self, cfg: TcpConfig):
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None

    def open(self):

        if self.sock:
            return

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.setblocking(False)

        try:
            self.sock.connect((self.cfg.host, self.cfg.port))
        except BlockingIOError:
            pass

    def close(self):

        if self.sock:

            try:
                self.sock.close()
            except Exception:
                pass

            self.sock = None

    def read(self, size=4096) -> bytes:

        if not self.sock:
            return b""

        try:
            data = self.sock.recv(size)

            if not data:
                return b""

            return data
        
        except (
            BlockingIOError,
            InterruptedError,
        ):
            return b""
        
        except OSError:
            return b""

    def write(self, data: bytes):

        if not data:
            return

        if not self.sock:
            return

        try:

            view = memoryview(data)

            while len(view):

                written = self.sock.send(view)

                if written <= 0:
                    break

                view = view[written:]

        except (
            BlockingIOError,
            InterruptedError,
            OSError,
        ):
            pass

class BaseFramer:

    def feed(self, data: bytes, now: float) -> list[bytes]:
        return []

    def flush(self, now: float | None = None) -> list[bytes]:
        return []

class RawFramer(BaseFramer):

    def feed(self, data: bytes, now: float) -> list[bytes]:

        if not data:
            return []

        return [bytes(data)]

class PauseFramer(BaseFramer):

    def __init__(self, pause_ms: int):

        self.pause = pause_ms / 1000.0

        self.buffer = bytearray()

        self.last_rx = None

    def feed(self, data: bytes, now: float) -> list[bytes]:

        if not data:
            return []

        self.buffer.extend(data)

        self.last_rx = now

        return []

    def flush(self, now: float | None = None) -> list[bytes]:

        if not self.buffer:
            return []

        if self.last_rx is None:
            return []

        if now is None:
            now = time.monotonic()

        if (now - self.last_rx) < self.pause:
            return []

        frame = bytes(self.buffer)

        self.buffer.clear()

        self.last_rx = None

        return [frame]

class MarkerFramer(BaseFramer):

    def __init__(self, marker: bytes, include_marker: bool):

        self.marker = marker
        self.include_marker = include_marker
        self.buffer = bytearray()

    def feed(self, data: bytes, now: float) -> list[bytes]:

        if not data:
            return []

        self.buffer.extend(data)

        frames = []

        while True:

            pos = self.buffer.find(self.marker)

            if pos < 0:
                break

            if self.include_marker:

                frame = bytes(self.buffer[:pos + len(self.marker)])

                del self.buffer[:pos + len(self.marker)]

            else:

                if pos == 0:
                    break

                frame = bytes(self.buffer[:pos])

                del self.buffer[:pos]

            frames.append(frame)

        return frames

    def flush(self, now=None):

        if not self.buffer:
            return []

        frame = bytes(self.buffer)

        self.buffer.clear()

        return [frame]
    
class AsciiLineFramer(BaseFramer):

    def __init__(self):

        self.buffer = bytearray()

    def feed(self, data: bytes, now: float) -> list[bytes]:

        if not data:
            return []

        self.buffer.extend(data)

        frames = []

        while True:

            pos = self.buffer.find(b"\n")

            if pos < 0:
                break

            frames.append(bytes(self.buffer[:pos + 1]))

            del self.buffer[:pos + 1]

        return frames

    def flush(self, now=None):

        if not self.buffer:
            return []

        frame = bytes(self.buffer)

        self.buffer.clear()

        return [frame]

class SlipFramer(BaseFramer):

    END = 0xC0
    ESC = 0xDB
    ESC_END = 0xDC
    ESC_ESC = 0xDD

    def __init__(self):

        self.buffer = bytearray()
        self.escape = False

    def feed(self, data: bytes, now: float) -> list[bytes]:

        frames = []

        for b in data:

            if self.escape:

                self.escape = False

                if b == self.ESC_END:
                    self.buffer.append(self.END)

                elif b == self.ESC_ESC:
                    self.buffer.append(self.ESC)

                else:
                    self.buffer.append(b)

                continue

            if b == self.ESC:
                self.escape = True
                continue

            if b == self.END:

                if self.buffer:
                    frames.append(bytes(self.buffer))
                    self.buffer.clear()

                continue

            self.buffer.append(b)

        return frames

    def flush(self, now=None):

        if not self.buffer:
            return []

        frame = bytes(self.buffer)

        self.buffer.clear()

        self.escape = False

        return [frame]

class ModbusRtuFramer(BaseFramer):

    def __init__(self, serial_cfg: Optional[SerialConfig]):

        if serial_cfg:

            bits = (
                1 +                          # start
                serial_cfg.bytesize +
                (0 if serial_cfg.parity == "N" else 1) +
                int(serial_cfg.stopbits)
            )

            char_time = bits / serial_cfg.baudrate

            #
            # Стандарт RTU — 3.5 символа.
            #
            self.pause = max(0.001, char_time * 3.5)

        else:

            #
            # Если скорость неизвестна.
            #
            self.pause = 0.005

        self.buffer = bytearray()

        self.last_rx = None

    def feed(self, data: bytes, now: float) -> list[bytes]:

        if not data:
            return []

        #
        # Если между кусками уже была пауза —
        # предыдущий кадр закончился.
        #

        if (
            self.buffer and
            self.last_rx is not None and
            (now - self.last_rx) >= self.pause
        ):

            frame = bytes(self.buffer)

            self.buffer.clear()

            self.buffer.extend(data)

            self.last_rx = now

            return [frame]

        self.buffer.extend(data)

        self.last_rx = now

        return []

    def flush(self, now: float | None = None) -> list[bytes]:

        if not self.buffer:
            return []

        if self.last_rx is None:
            return []

        if now is None:
            now = time.monotonic()

        if (now - self.last_rx) < self.pause:
            return []

        frame = bytes(self.buffer)

        self.buffer.clear()

        self.last_rx = None

        return [frame]

def make_framer(
    kind: str,
    params: dict,
    serial_cfg: Optional[SerialConfig] = None,
):

    kind = kind.lower()

    if kind == "raw":
        return RawFramer()

    if kind == "pause":
        return PauseFramer(
            params.get("pause_ms", 5)
        )

    if kind == "modbus":
        return ModbusRtuFramer(
            serial_cfg
        )

    if kind == "marker":

        marker = params.get("marker", b"")

        if isinstance(marker, str):
            marker = marker.encode()

        return MarkerFramer(
            marker,
            params.get("include_marker", False),
        )

    if kind == "ascii":
        return AsciiLineFramer()

    if kind == "slip":
        return SlipFramer()

    return RawFramer()

class SnifferThread(threading.Thread):

    def __init__(
        self,
        source: Endpoint,
        target: Endpoint,
        framer_kind: str,
        framer_params: dict,
        log_callback: Callable[[str, str], None],
        serial_ctx_out: Optional[SerialConfig] = None,
        serial_ctx_in: Optional[SerialConfig] = None,
    ):

        super().__init__(daemon=True)

        self.source = source
        self.target = target

        self.framer_kind = framer_kind
        self.framer_params = framer_params

        self.serial_ctx_out = serial_ctx_out
        self.serial_ctx_in = serial_ctx_in

        self.log = log_callback

        self.running = False

        self.tx_thread = None
        self.rx_thread = None

    def stop(self):

        self.running = False

        try:
            self.source.close()
        except Exception:
            pass

        try:
            self.target.close()
        except Exception:
            pass

    def run(self):

        start_time = time.time()

        try:

            self.source.open()
            self.target.open()

        except Exception as e:

            self.log(
                "out",
                self._ts(start_time) + f"ERROR: {e}"
            )

            return

        self.running = True

        self.log(
            "out",
            self._ts(start_time) + "Sniffer started"
        )

        out_framer = make_framer(
            self.framer_kind,
            self.framer_params,
            self.serial_ctx_out,
        )

        in_framer = make_framer(
            self.framer_kind,
            self.framer_params,
            self.serial_ctx_in,
        )

        self.tx_thread = threading.Thread(
            target=self._pipe,
            daemon=True,
            args=(
                self.source,
                self.target,
                out_framer,
                "out",
                " OUT→ ",
                start_time,
            ),
        )

        self.rx_thread = threading.Thread(
            target=self._pipe,
            daemon=True,
            args=(
                self.target,
                self.source,
                in_framer,
                "in",
                " ←IN ",
                start_time,
            ),
        )

        self.tx_thread.start()
        self.rx_thread.start()

        self.tx_thread.join()
        self.rx_thread.join()

        self.running = False

    def _pipe(
        self,
        rx: Endpoint,
        tx: Endpoint,
        framer: BaseFramer,
        log_target: str,
        prefix: str,
        start_time: float,
    ):

        while self.running:

            #
            # 1. Читаем все доступные байты.
            #
            try:
                data = rx.read(4096)
            except Exception:
                self.running = False
                break

            #
            # 2. Если пришли данные —
            #    СРАЗУ пересылаем.
            #
            if data:

                try:
                    tx.write(data)
                except Exception:
                    pass

                #
                # Только копию отправляем
                # во фреймер.
                #
                now = time.monotonic()

                frames = framer.feed(data, now)

                for frame in frames:

                    self.log(
                        log_target,
                        self._ts(start_time) + prefix + hex_bytes(frame),
                    )

            #
            # 3. Для Pause/RTU постоянно
            #    проверяем окончание кадра.
            #
            now = time.monotonic()

            frames = framer.flush(now)

            for frame in frames:

                self.log(
                    log_target,
                    self._ts(start_time) + prefix + hex_bytes(frame),
                )

            #
            # 4. Небольшая задержка.
            #
            time.sleep(0.001)

    def _ts(self, start_time: float) -> str:

        dt = time.time() - start_time

        sec = int(dt)

        ms = int((dt - sec) * 1000)

        return f"[{sec:05}.{ms:03}] "

    def __del__(self):

        try:
            self.stop()
        except Exception:
            pass