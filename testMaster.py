#!/usr/bin/env python3
import argparse
import struct
import sys
import time
from pathlib import Path

import serial
from serial.tools import list_ports


def crc16_modbus(data: bytes) -> bytes:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return struct.pack("<H", crc & 0xFFFF)


def build_read_holding_registers(slave_id: int, start_register: int, quantity: int) -> bytes:
    if not 1 <= slave_id <= 247:
        raise ValueError("slave_id must be between 1 and 247")
    if not 0 <= start_register <= 0xFFFF:
        raise ValueError("start_register must be between 0 and 65535")
    if not 1 <= quantity <= 125:
        raise ValueError("quantity must be between 1 and 125")

    request = bytes([
        slave_id,
        0x03,
        (start_register >> 8) & 0xFF,
        start_register & 0xFF,
        (quantity >> 8) & 0xFF,
        quantity & 0xFF,
    ])
    return request + crc16_modbus(request)


def parse_read_holding_registers(frame: bytes):
    if len(frame) < 5:
        raise ValueError("response too short")

    slave_id = frame[0]
    function_code = frame[1]
    byte_count = frame[2]
    data_bytes = frame[3:-2]
    received_crc = frame[-2:]

    if len(frame) != 5 + byte_count:
        raise ValueError(f"unexpected frame length: {len(frame)}")

    if function_code != 0x03:
        raise ValueError(f"unexpected function code: 0x{function_code:02X}")

    expected_crc = crc16_modbus(frame[:-2])
    if received_crc != expected_crc:
        raise ValueError("CRC mismatch")

    values = []
    for i in range(0, len(data_bytes), 2):
        values.append(int.from_bytes(data_bytes[i:i+2], byteorder="big", signed=False))

    return {
        "slave_id": slave_id,
        "function_code": function_code,
        "values": values,
        "byte_count": byte_count,
    }


def discover_ports() -> list[str]:
    ports = [port.device for port in list_ports.comports()]

    # Добавляем tty0tty-like ports on Linux
    try:
        for path in sorted(Path("/dev").glob("tnt*")):
            if path.is_char_device():
                ports.append(str(path))
    except OSError:
        pass

    return sorted(set(ports))


def probe_port(port_name: str, baudrate: int, timeout: float) -> bool:
    try:
        with serial.Serial(
            port=port_name,
            baudrate=baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=timeout,
        ) as probe:
            return probe.is_open
    except (serial.SerialException, OSError, ValueError):
        return False


def resolve_port(requested_port: str | None, baudrate: int, timeout: float) -> str:
    if requested_port and requested_port != "auto":
        return requested_port

    ports = discover_ports()
    if not ports:
        raise RuntimeError("No serial ports found")

    print("Trying to find a usable serial port...")
    for port_name in ports:
        if probe_port(port_name, baudrate, timeout):
            print(f"Using port: {port_name}")
            return port_name

    raise RuntimeError("No usable serial port found")


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple Modbus RTU master for polling holding registers")
    parser.add_argument("--port", default=None, help="serial port, e.g. /dev/ttyUSB0 or COM3; default: auto-detect the first available port")
    parser.add_argument("--list-ports", action="store_true", help="print available serial ports and exit")
    parser.add_argument("--baudrate", type=int, default=9600, help="baud rate")
    parser.add_argument("--slave-id", type=int, default=3, help="Modbus slave address")
    parser.add_argument("--start-register", type=int, default=0, help="starting register address")
    parser.add_argument("--quantity", type=int, default=4, help="number of registers to read")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument("--timeout", type=float, default=1.0, help="serial timeout in seconds")
    parser.add_argument("--count", type=int, default=0, help="stop after N requests (0 = unlimited)")
    args = parser.parse_args()

    if args.list_ports:
        ports = discover_ports()
        if ports:
            print("Available serial ports:")
            for port in ports:
                print(f"  - {port}")
        else:
            print("No serial ports found")
        return 0

    try:
        port_name = resolve_port(args.port, args.baudrate, args.timeout)
        ser = serial.Serial(
            port=port_name,
            baudrate=args.baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=args.timeout,
        )
    except (serial.SerialException, OSError, RuntimeError) as exc:
        print(f"Cannot open serial port {args.port}: {exc}", file=sys.stderr)
        return 1

    try:
        request_number = 0
        while True:
            try:
                request = build_read_holding_registers(args.slave_id, args.start_register, args.quantity)
                ser.write(request)
                print(f"[{request_number + 1}] -> {port_name} slave={args.slave_id} func=0x03 start={args.start_register} qty={args.quantity}")
            except serial.SerialException as exc:
                print(f"write error: {exc}")
                time.sleep(args.interval)
                continue

            try:
                response = ser.read(256)
            except serial.SerialException as exc:
                print(f"read error: {exc}")
                response = b""

            if response:
                try:
                    parsed = parse_read_holding_registers(response)
                    print(f"    response: values={parsed['values']}")
                except ValueError as exc:
                    print(f"    parse error: {exc}")
                    print(f"    raw: {response.hex()}")
            else:
                print("    no response")

            request_number += 1
            if args.count and request_number >= args.count:
                break

            time.sleep(args.interval)
    finally:
        ser.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nstopped")
        sys.exit(0)
