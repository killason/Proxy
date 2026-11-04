#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import threading
from datetime import datetime

import serial
import serial.tools.list_ports


BAUDRATE = 9600
POLL_DELAY = 0.1


# ============================================================
# ПАКЕТЫ
# ============================================================

PACKETS = {
    "modbus": {
        "request": bytes.fromhex("01 03 00 00 00 02 C4 0B"),
        "response": bytes.fromhex("01 03 04 00 01 00 02 2A 32"),
    },

    "ascii": {
        "request": b":010300000002FA\r\n",
        "response": b":01030400010002F5\r\n",
    },

    "slip": {
        "request": bytes([0xC0, 0x01, 0x02, 0x03, 0xC0]),
        "response": bytes([0xC0, 0x10, 0x20, 0x30, 0xC0]),
    },
}


# ============================================================
# ВРЕМЯ
# ============================================================

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


# ============================================================
# ПОИСК ПОРТОВ
# ============================================================

def get_ports():

    ports = []

    # То, что видит pyserial
    for p in serial.tools.list_ports.comports():
        ports.append(p.device)

    # Linux: дополнительно ищем tty0tty и обычные tty
    if os.name != "nt":

        try:
            for dev in os.listdir("/dev"):

                if dev.startswith("tnt"):
                    ports.append("/dev/" + dev)

                elif dev.startswith("ttyUSB"):
                    ports.append("/dev/" + dev)

                elif dev.startswith("ttyACM"):
                    ports.append("/dev/" + dev)

        except OSError:
            pass

    return sorted(set(ports))


# ============================================================
# ФИЛЬТРАЦИЯ tty0tty
#
# tnt0 <-> tnt1
# tnt2 <-> tnt3
# tnt4 <-> tnt5
# ...
# ============================================================

def same_tty_pair(a, b):

    if "tnt" not in a or "tnt" not in b:
        return False

    try:
        na = int(a.split("tnt")[-1])
        nb = int(b.split("tnt")[-1])
    except ValueError:
        return False

    return (na // 2) == (nb // 2)


# ============================================================
# ФИЛЬТРАЦИЯ com0com
#
# Принято наше упрощённое правило:
# COM5 <-> COM6
# COM7 <-> COM8
# и т.д.
# ============================================================

def same_com_pair(a, b):

    if not a.upper().startswith("COM"):
        return False

    if not b.upper().startswith("COM"):
        return False

    try:
        na = int(a[3:])
        nb = int(b[3:])
    except ValueError:
        return False

    return abs(na - nb) == 1 and min(na, nb) % 2 == 1


# ============================================================
# ВЫБОР ДВУХ НЕЗАВИСИМЫХ ПОРТОВ
# ============================================================

def select_ports():

    ports = get_ports()

    print("Найдены порты:")

    for p in ports:
        print(" ", p)

    print()

    if len(ports) < 2:
        raise RuntimeError("Найдено меньше двух портов")

    for i in range(len(ports)):

        for j in range(i + 1, len(ports)):

            p1 = ports[i]
            p2 = ports[j]

            # Не берём два конца одной tty0tty пары
            if same_tty_pair(p1, p2):
                continue

            # Не берём два конца одной com0com пары
            if same_com_pair(p1, p2):
                continue

            return p1, p2

    raise RuntimeError(
        "Не удалось найти два независимых порта"
    )


# ============================================================
# MODBUS CRC16
# ============================================================

def crc16(data):

    crc = 0xFFFF

    for byte in data:

        crc ^= byte

        for _ in range(8):

            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    return crc


# ============================================================
# ПРОВЕРКА MODBUS RTU
# ============================================================

def check_modbus(packet):

    if len(packet) < 4:
        return False

    body = packet[:-2]

    received_crc = (
        packet[-2] |
        (packet[-1] << 8)
    )

    calculated_crc = crc16(body)

    return received_crc == calculated_crc


# ============================================================
# ASCII LRC
# ============================================================

def lrc(data):

    return (-sum(data)) & 0xFF


# ============================================================
# ПРОВЕРКА ASCII
# ============================================================

def check_ascii(packet):

    try:

        text = packet.decode("ascii")

        if not text.startswith(":"):
            return False

        if not text.endswith("\r\n"):
            return False

        frame = text[1:-2]

        # Должно быть целое число HEX-байтов
        if len(frame) < 4 or len(frame) % 2 != 0:
            return False

        raw = bytes.fromhex(frame)

        if len(raw) < 2:
            return False

        data = raw[:-1]
        received_lrc = raw[-1]

        return received_lrc == lrc(data)

    except (UnicodeDecodeError, ValueError):
        return False


# ============================================================
# ПРОВЕРКА SLIP
# ============================================================

def check_slip(packet):

    END = 0xC0
    ESC = 0xDB
    ESC_END = 0xDC
    ESC_ESC = 0xDD

    if len(packet) < 2:
        return False

    if packet[0] != END:
        return False

    if packet[-1] != END:
        return False

    escaped = False

    for byte in packet[1:-1]:

        if escaped:

            if byte not in (ESC_END, ESC_ESC):
                return False

            escaped = False
            continue

        if byte == ESC:
            escaped = True

        elif byte == END:
            return False

    return not escaped


# ============================================================
# ОБЩАЯ ПРОВЕРКА
# ============================================================

def validate(packet):

    if protocol == "modbus":
        return check_modbus(packet)

    if protocol == "ascii":
        return check_ascii(packet)

    if protocol == "slip":
        return check_slip(packet)

    return False


# ============================================================
# MASTER
# ============================================================

def master_thread():

    global slave_rx_result
    global slave_tx_done

    while True:

        slave_rx_result = ""
        slave_tx_done = False

        t = ts()

        master_port.write(REQUEST)
        master_port.flush()

        while master_port.in_waiting == 0:
            time.sleep(0.001)

        data = master_port.read_all()

        if validate(data):
            master_result = "OK"
        else:
            master_result = "FAIL"

        while not slave_tx_done:
            time.sleep(0.001)

        print(
            f"[{t}] "
            f"MASTER отправил | "
            f"SLAVE принял {slave_rx_result} | "
            f"SLAVE отправил | "
            f"MASTER принял {master_result}"
        )

        time.sleep(POLL_DELAY)

# ============================================================
# SLAVE
# ============================================================

def slave_thread():

    global slave_rx_result
    global slave_tx_done

    while True:

        while slave_port.in_waiting == 0:
            time.sleep(0.001)

        data = slave_port.read_all()

        if validate(data):
            slave_rx_result = "OK"
        else:
            slave_rx_result = "FAIL"

        slave_port.write(RESPONSE)
        slave_port.flush()

        slave_tx_done = True


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        master_name, slave_name = select_ports()

        master_port = serial.Serial(
            port=master_name,
            baudrate=BAUDRATE,
            timeout=0
        )

        slave_port = serial.Serial(
            port=slave_name,
            baudrate=BAUDRATE,
            timeout=0
        )

        print("=" * 50)
        print(f"MASTER подключён: {master_name}")
        print(f"SLAVE  подключён: {slave_name}")
        print("=" * 50)
        print()

        print("Выберите режим:")
        print("1 - Modbus RTU")
        print("2 - ASCII")
        print("3 - SLIP")
        print()

        choice = input("> ").strip()

        if choice == "1":
            protocol = "modbus"

        elif choice == "2":
            protocol = "ascii"

        elif choice == "3":
            protocol = "slip"

        else:
            print("Неверный режим")
            sys.exit(1)

        REQUEST = PACKETS[protocol]["request"]
        RESPONSE = PACKETS[protocol]["response"]

        print()
        print(f"Режим: {protocol.upper()}")
        print(f"Скорость: {BAUDRATE} бод")
        print()

        master = threading.Thread(
            target=master_thread,
            daemon=True
        )

        slave = threading.Thread(
            target=slave_thread,
            daemon=True
        )

        slave.start()

        # SLAVE уже слушает порт перед первым запросом
        master.start()

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print()
        print("Остановка...")

    except Exception as e:

        print()
        print("Ошибка:", e)

    finally:

        if "master_port" in globals():
            if master_port.is_open:
                master_port.close()

        if "slave_port" in globals():
            if slave_port.is_open:
                slave_port.close()
