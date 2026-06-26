#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Local PZEM-004T Modbus/TCP-style socket simulator for phone smoke tests.

This is a development utility for Android/Termux validation. It presents the
same byte-stream shape consumed by ``UsbSerialAdapter`` when ``device_path`` is
configured as ``socket://127.0.0.1:PORT``.
"""

from __future__ import annotations

import argparse
import socket
import struct
from collections.abc import Mapping

_FC_READ_HOLDING = 0x03

# Matches ori.hal.usb_serial_adapter._SENSOR_MAP.
_REGISTER_SCALE: dict[int, tuple[str, float]] = {
    0x0000: ("voltage", 0.1),
    0x0008: ("current", 0.01),
    0x0012: ("power", 0.1),
    0x0046: ("frequency", 0.1),
    0x0100: ("energy", 0.01),
}


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def build_response(request: bytes, values: Mapping[str, float]) -> bytes:
    if len(request) < 8:
        raise ValueError("request is too short")

    payload = request[:-2]
    received_crc = struct.unpack("<H", request[-2:])[0]
    expected_crc = crc16(payload)
    if received_crc != expected_crc:
        raise ValueError(
            f"request CRC mismatch: got 0x{received_crc:04X}, expected 0x{expected_crc:04X}"
        )

    slave_id, function, register, count = struct.unpack(">BBHH", payload)
    if function != _FC_READ_HOLDING:
        raise ValueError(f"unsupported Modbus function: {function}")
    if register not in _REGISTER_SCALE:
        raise ValueError(f"unsupported PZEM register: 0x{register:04X}")

    key, scale = _REGISTER_SCALE[register]
    raw_value = int(round(float(values[key]) / scale))
    if count == 1:
        data = struct.pack(">H", raw_value)
    elif count == 2:
        data = struct.pack(">I", raw_value)
    else:
        raise ValueError(f"unsupported register count: {count}")

    response_payload = struct.pack(">BBB", slave_id, function, len(data)) + data
    return response_payload + struct.pack("<H", crc16(response_payload))


def serve(port: int, values: Mapping[str, float]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(1)
        print(f"PZEM simulator listening on 127.0.0.1:{port}", flush=True)
        print(f"values={dict(values)}", flush=True)

        while True:
            conn, addr = server.accept()
            with conn:
                print(f"client connected: {addr}", flush=True)
                while True:
                    request = conn.recv(8)
                    if not request:
                        break
                    try:
                        slave_id, function, register, count = struct.unpack(
                            ">BBHH", request[:-2]
                        )
                        print(
                            "request "
                            f"slave={slave_id} function={function} "
                            f"register=0x{register:04X} count={count}",
                            flush=True,
                        )
                        response = build_response(request, values)
                    except Exception as exc:
                        print(f"bad request: {exc}", flush=True)
                        break
                    conn.sendall(response)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local PZEM socket simulator for Ori phone testing."
    )
    parser.add_argument("--port", type=int, default=7000)
    parser.add_argument("--voltage", type=float, default=230.0)
    parser.add_argument("--current", type=float, default=3.7)
    parser.add_argument("--power", type=float, default=850.0)
    parser.add_argument("--frequency", type=float, default=50.0)
    parser.add_argument("--energy", type=float, default=12.34)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    values = {
        "voltage": args.voltage,
        "current": args.current,
        "power": args.power,
        "frequency": args.frequency,
        "energy": args.energy,
    }
    serve(args.port, values)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
