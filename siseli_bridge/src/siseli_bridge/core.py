# Local telemetry extensions for PowMr/Siseli bridges.
import base64
import json
import logging
import os
import signal
import socket
import threading
import time
import warnings
from typing import Optional

from scapy.all import ARP, Ether, IP, Raw, TCP, UDP, AsyncSniffer, getmacbyip, sendp  # type: ignore

from .config import *
from .loggers import log, log_kv, json_log, log_payload_preview, printable_text_preview, hex_preview
from .sensors import SENSORS, get_grouped_sensor_keys
from . import state as _state
from .mqtt import (
    client,
    start_mqtt,
    publish_discovery,
    publish_sensor_discovery,
    publish_grouped_state,
    set_local_telemetry_available,
    set_temperature_telemetry_available,
    RUNNING,
    availability_topic_for_group,
)
from .parsers import SolarParser, extract_publish_payload, append_stream_data, mqtt_type_name, SEEN_MQTT_TOPICS

warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    return mac.strip().lower().replace("-", ":")

def send_layer2(frame, iface: Optional[str] = None) -> None:
    if iface:
        sendp(frame, verbose=False, iface=iface)
    else:
        sendp(frame, verbose=False)

INV_MAC: Optional[str] = None
RTR_MAC: Optional[str] = None
sniffer: Optional[AsyncSniffer] = None

from .config import STATE_CACHE_FILE
    
try:
    if os.path.exists(STATE_CACHE_FILE):
        with open(STATE_CACHE_FILE, "r") as f:
            _state.LAST_STATE.update(json.load(f))
except Exception as e:
    log(f"[CACHE] Error loading state: {e}", level="error")

KNOWN_INVERTER_MACS = set()
KNOWN_ROUTER_MACS = set()
LAST_PACKET_TS = 0.0
MODBUS_REGISTER_CACHE_FILE = "/data/modbus_registers.json"
PENDING_MODBUS: dict[str, dict] = {}
MODBUS_REGISTERS: dict[str, dict] = {}


def publish_powmr_live_block(address: int, values: list[int]) -> None:
    """Publish the two passive live-data blocks used by PowMr Wi-Fi dongles.

    These are ordinary Modbus replies initiated by the real Siseli cloud.  The
    bridge never sends a request; it merely translates a complete observed
    reply when the cloud asks for one of the well-known live blocks.
    """
    state_update: dict[str, object] = {}

    # Siseli may request these same live registers individually instead of in
    # the contiguous block below.  This is the pattern observed from the
    # ECO/MAX-730 cloud session, so accept one-register reads too.
    individual_live_registers = {
        4502: ("grid_v", 0.1),
        4503: ("grid_hz", 0.1),
        4504: ("pv_v", 0.1),
        4505: ("pv_w", 1.0),
        4506: ("bat_v", 0.1),
        4507: ("bat_cap", 1.0),
        4508: ("bat_charge_current", 1.0),
        4509: ("dischg_current", 1.0),
        4510: ("out_v", 0.1),
        4511: ("out_hz", 0.1),
        4512: ("apparent_va", 1.0),
        4513: ("load_w", 1.0),
        4514: ("load_pct", 1.0),
        4530: ("status_code", 1.0),
        4557: ("inverter_temperature_c", 1.0),
    }
    if len(values) == 1 and address in individual_live_registers:
        key, multiplier = individual_live_registers[address]
        value = values[0] * multiplier
        state_update = {key: int(value) if multiplier == 1.0 else value}

    # POW-HVM3.6M family: FC03, unit 5, 45 registers from 4501.
    # Register names/scales are corroborated by the PowMr Wi-Fi bridge protocol
    # and the ESPHome PowMr register map.  Do not decode partial/different
    # blocks as this model family has variant-specific holding registers.
    elif address == 4501 and len(values) == 45:
        settings_flags = values[34]
        pv_voltage = values[3] / 10.0
        pv_power = values[4]
        load_power = values[12]
        state_update = {
            "grid_v": values[1] / 10.0,
            "grid_hz": values[2] / 10.0,
            "pv_v": pv_voltage,
            "pv_w": pv_power,
            # This model exposes PV voltage and power but no PV-current
            # register in its live block. Make the derived nature explicit in
            # discovery while still providing the useful electrical value.
            "pv_current_a": round(pv_power / pv_voltage, 2) if pv_voltage > 0 else 0.0,
            "pv_surplus_w": max(pv_power - load_power, 0),
            "pv_generating": bool(pv_power > 0),
            "bat_v": values[5] / 10.0,
            "bat_cap": values[6],
            "bat_charge_current": values[7],
            "dischg_current": values[8],
            "out_v": values[9] / 10.0,
            "out_hz": values[10] / 10.0,
            # This inverter reports apparent power at 4512 and active power at
            # 4513. Multiple natural-load samples confirmed the labels are
            # reversed from some published PowMr maps (W must not exceed VA).
            "apparent_va": values[11],
            "load_w": load_power,
            "load_pct": values[13],
            "overload_flag_raw": values[15],
            # Published maps express the mask in wire-byte order. This bridge
            # has already decoded the low-byte-first word, so 0x0100 becomes 1.
            "overload_active": bool(values[15] & 0x0001),
            "status_code": values[29],
            # Read-only mirrors of the inverter LCD P-program menu. The flags
            # use masks byte-swapped from the published raw-wire register map.
            "settings_flags_4535_raw": settings_flags,
            "overload_restart_function": "On" if settings_flags & 0x0008 else "Off",
            "over_temperature_restart_function": "On" if settings_flags & 0x0010 else "Off",
            "buzzer_function": "On" if settings_flags & 0x0001 else "Off",
            "automatic_return_to_first_page": "On" if settings_flags & 0x0040 else "Off",
            "lcd_back_lighting": "On" if settings_flags & 0x0004 else "Off",
            "beep_on_primary_source_fail": "On" if settings_flags & 0x0020 else "Off",
            "overload_to_bypass_function": "On" if settings_flags & 0x0080 else "Off",
            "record_fault_code": "On" if settings_flags & 0x0100 else "Off",
            "battery_equalization_mode": "Enable" if settings_flags & 0x0200 else "Disable",
            "battery_equalization_immediate": "On" if settings_flags & 0x0400 else "Off",
            # POW-LVM3.6M P16 has three charger-source choices. This model's
            # live register 4536 value 2 was confirmed against LCD code OSO.
            "charging_priority_order": {
                0: "Solar first (CSO)",
                1: "Solar and Utility (SNU)",
                2: "Only Solar (OSO)",
            }.get(values[35], f"Code {values[35]} (variant)"),
            "working_mode": {
                0: "Utility first (USB)", 1: "Solar first (SUB)", 2: "SBU priority",
            }.get(values[36], f"Code {values[36]} (variant)"),
            "mains_input_range": {
                0: "Appliances (90-280 VAC)", 1: "UPS (170-280 VAC)",
            }.get(values[37], f"Code {values[37]} (variant)"),
            "battery_type": {
                0: "AGM/Sealed", 1: "Flooded", 2: "User-defined",
            }.get(values[38], f"Code {values[38]} (variant)"),
            "output_set_frequency": {0: 50, 1: 60}.get(values[39], values[39]),
            "maximum_total_charging_current_a": values[40],
            "output_set_voltage": values[41],
            "max_utility_charge_current_a": values[42],
            "return_to_mains_mode_voltage_v": values[43] / 10.0,
            "return_to_battery_mode_voltage_v": values[44] / 10.0,
        }
        if values[11] > 0:
            state_update["load_power_factor"] = round(100.0 * values[12] / values[11], 1)
        if values[9] > 0:
            state_update["load_current_a"] = round(values[11] / (values[9] / 10.0), 2)
    # Read-only companion status block used by the original PowMr dongle.
    # Retain the strict block length so setting reads cannot be misclassified.
    elif address == 4546 and len(values) == 16:
        flags_4553 = values[7]
        flags_4554 = values[8]
        state_update = {
            # Community masks are written for the raw big-endian view. Swap
            # those masks because values here are already low-byte-first words.
            "grid_active": bool(flags_4554 & (0x0001 | 0x0080)),
            "on_battery": bool(flags_4554 & 0x0100),
            "load_enabled": bool(flags_4553 & 0x0040),
            "charger_status": {0: "Off", 1: "Idle", 2: "Active"}.get(values[9], f"Code {values[9]} (variant)"),
            "charger_status_raw": values[9],
            "status_flags_4553_raw": flags_4553,
            "status_flags_4554_raw": flags_4554,
            "inverter_temperature_c": values[11],
            "strong_charging_voltage_v": values[0] / 10.0,
            "float_charging_voltage_v": values[1] / 10.0,
            "low_electric_lock_voltage_v": values[2] / 10.0,
            "battery_equalization_voltage_v": values[3] / 10.0,
            "equalization_time": f"{values[4]} min",
            "equalization_overtime": f"{values[5]} min",
            "equalization_interval": f"{values[6]} days",
        }

    if not state_update:
        return

    _state.LAST_STATE.update(state_update)
    try:
        os.makedirs(os.path.dirname(STATE_CACHE_FILE), exist_ok=True)
        with open(STATE_CACHE_FILE, "w") as file:
            json.dump(dict(_state.LAST_STATE), file)
    except OSError as exc:
        log(f"[STATE CACHE ERROR] {exc}", level="error")

    for key in state_update:
        if key in SENSORS and key not in _state.PUBLISHED_SENSOR_KEYS:
            publish_sensor_discovery(key)
    publish_grouped_state(state_update)
    log_kv("[MODBUS LIVE TELEMETRY]", address=address, values=state_update)


def _siseli_json(payload: bytes) -> Optional[dict]:
    """Decode a Siseli MQTT payload, which may have a leading NUL byte."""
    start = payload.find(b"{")
    end = payload.rfind(b"}")
    if start < 0 or end < start:
        return None
    try:
        value = json.loads(payload[start:end + 1].decode("utf-8"))
        return value if isinstance(value, dict) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _modbus_crc(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def _valid_modbus_frame(frame: bytes) -> bool:
    return len(frame) >= 4 and _modbus_crc(frame[:-2]) == int.from_bytes(frame[-2:], "little")


def _decode_live_register(data: bytes) -> int:
    """Decode the ECO/MAX-730's low-byte-first 16-bit response words."""
    if len(data) != 2:
        raise ValueError("a register must contain exactly two bytes")
    return int.from_bytes(data, "little")


def _persist_modbus_registers() -> None:
    try:
        with open(MODBUS_REGISTER_CACHE_FILE, "w") as file:
            json.dump(MODBUS_REGISTERS, file, sort_keys=True)
    except OSError as exc:
        log(f"[MODBUS CACHE ERROR] {exc}", level="error")


def record_modbus_request(payload: bytes) -> None:
    """Remember a cloud Modbus read request; this is passive observation only."""
    message = _siseli_json(payload)
    if not message:
        return
    encoded = message.get("b", {}).get("ci") if isinstance(message.get("b"), dict) else None
    transaction = message.get("t")
    if not isinstance(encoded, str) or not isinstance(transaction, str):
        return
    try:
        frame = base64.b64decode(encoded, validate=True)
    except Exception:
        return
    if len(frame) != 8 or not _valid_modbus_frame(frame) or frame[1] not in {3, 4}:
        return

    # Bound the short-lived correlation map in case a device disconnects mid-RPC.
    if len(PENDING_MODBUS) >= 128:
        oldest = min(PENDING_MODBUS, key=lambda key: PENDING_MODBUS[key]["seen"])
        PENDING_MODBUS.pop(oldest, None)
    request = {
        "unit": frame[0],
        "function": frame[1],
        "address": int.from_bytes(frame[2:4], "big"),
        "count": int.from_bytes(frame[4:6], "big"),
        "seen": time.time(),
    }
    PENDING_MODBUS[transaction] = request
    log_kv("[MODBUS REQUEST]", transaction=transaction, **request)


def record_modbus_response(payload: bytes) -> None:
    """Match a dongle reply to a cloud read request and record raw registers."""
    message = _siseli_json(payload)
    if not message:
        return
    encoded = message.get("b", {}).get("co") if isinstance(message.get("b"), dict) else None
    transaction = message.get("t")
    if not isinstance(encoded, str) or not isinstance(transaction, str):
        return
    request = PENDING_MODBUS.pop(transaction, None)
    if request is None:
        return
    try:
        frame = base64.b64decode(encoded, validate=True)
    except Exception:
        log_kv("[MODBUS RESPONSE INVALID]", transaction=transaction, reason="invalid_base64")
        return
    if not _valid_modbus_frame(frame):
        log_kv("[MODBUS RESPONSE INVALID]", transaction=transaction, reason="bad_crc", frame=frame.hex())
        return
    if len(frame) < 5 or frame[0] != request["unit"] or frame[1] != request["function"]:
        log_kv("[MODBUS RESPONSE INVALID]", transaction=transaction, reason="request_response_mismatch", frame=frame.hex())
        return

    byte_count = frame[2]
    data = frame[3:-2]
    if byte_count != len(data) or byte_count != request["count"] * 2:
        log_kv("[MODBUS RESPONSE INVALID]", transaction=transaction, reason="unexpected_length", frame=frame.hex())
        return

    now = time.time()
    register_values: list[int] = []
    for offset in range(request["count"]):
        address = request["address"] + offset
        value = _decode_live_register(data[offset * 2:(offset + 1) * 2])
        register_values.append(value)
        key = f"0x{address:04X}"
        prior = MODBUS_REGISTERS.get(key, {})
        MODBUS_REGISTERS[key] = {
            "value": value,
            "unit": request["unit"],
            "function": request["function"],
            "samples": int(prior.get("samples", 0)) + 1,
            "updated": now,
        }
        log_kv("[MODBUS REGISTER]", transaction=transaction, address=key, value=value)
    _persist_modbus_registers()
    publish_powmr_live_block(request["address"], register_values)


def accept_local_telemetry_datagram(payload: bytes, source_ip: str) -> bool:
    """Validate a read-only frame from the dedicated PowMr gateway."""
    if source_ip != LOCAL_TELEMETRY_SOURCE:
        return False
    try:
        message = json.loads(payload.decode("utf-8"))
        if not isinstance(message, dict):
            return False
        if message.get("kind") == "status":
            if message.get("available") is not False:
                return False
            channel = message.get("channel", "live")
            if channel in {"live", "all"}:
                set_local_telemetry_available(False)
            if channel in {"temperature", "all"}:
                set_temperature_telemetry_available(False)
            if channel not in {"live", "temperature", "all"}:
                return False
            log_kv("[LOCAL TELEMETRY OFFLINE]", source=source_ip, channel=channel)
            return True
        transaction = message["transaction"]
        address = message["address"]
        frame = base64.b64decode(message["frame"], validate=True)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    frame_spec = {
        4501: (95, b"\x05\x03\x5a", range(3, 93, 2)),
        4546: (37, b"\x05\x03\x20", range(3, 35, 2)),
    }.get(address)
    if (
        not isinstance(transaction, str)
        or not transaction.isalnum()
        or not 1 <= len(transaction) <= 32
        or frame_spec is None
        or len(frame) != frame_spec[0]
        or frame[:3] != frame_spec[1]
        or not _valid_modbus_frame(frame)
    ):
        return False
    registers = [
        _decode_live_register(frame[offset:offset + 2])
        for offset in frame_spec[2]
    ]
    publish_powmr_live_block(address, registers)
    if address == 4501:
        set_local_telemetry_available(True)
    else:
        set_temperature_telemetry_available(True)
    log_kv("[LOCAL TELEMETRY]", source=source_ip, address=address, registers=len(registers))
    return True


def local_telemetry_listener() -> None:
    """Receive independently validated telemetry frames; never inverter commands."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", LOCAL_TELEMETRY_PORT))
        listener.settimeout(1.0)
        log(
            f"[LOCAL TELEMETRY] Listening on UDP {LOCAL_TELEMETRY_PORT} "
            f"for {LOCAL_TELEMETRY_SOURCE}",
            level="info",
        )
        while RUNNING:
            try:
                payload, peer = listener.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError as exc:
                if RUNNING:
                    log(f"[LOCAL TELEMETRY ERROR] {exc}", level="error")
                return
            if not accept_local_telemetry_datagram(payload, peer[0]):
                log_kv("[LOCAL TELEMETRY REJECTED]", source=peer[0], bytes=len(payload))

class ArpSpoofer:
    def resolve_macs(self) -> None:
        global INV_MAC, RTR_MAC

        INV_MAC = norm_mac(INVERTER_MAC_CFG) or INV_MAC
        RTR_MAC = norm_mac(ROUTER_MAC_CFG) or RTR_MAC

        while RUNNING and (not INV_MAC or not RTR_MAC):
            if not INV_MAC:
                INV_MAC = norm_mac(getmacbyip(INVERTER_IP))
            if not RTR_MAC:
                RTR_MAC = norm_mac(getmacbyip(ROUTER_IP))

            if not INV_MAC or not RTR_MAC:
                log("[ARP] Waiting for MAC addresses...", level="info")
                time.sleep(2)

        if RUNNING:
            log(f"[ARP] Inverter MAC: {INV_MAC}", level="info")
            log(f"[ARP] Router MAC:   {RTR_MAC}", level="info")

    def run(self) -> None:
        self.resolve_macs()
        if not RUNNING:
            return

        log(f"[ARP] Interception ACTIVE: {INVERTER_IP} <-> {ROUTER_IP}", level="info")

        while RUNNING:
            try:
                send_layer2(Ether(dst=INV_MAC) / ARP(op=2, pdst=INVERTER_IP, psrc=ROUTER_IP, hwdst=INV_MAC), SNIFF_IFACE)
                send_layer2(Ether(dst=RTR_MAC) / ARP(op=2, pdst=ROUTER_IP, psrc=INVERTER_IP, hwdst=RTR_MAC), SNIFF_IFACE)
            except Exception as exc:
                log(f"[ARP ERROR] {exc}", level="error")

            time.sleep(2)


arp_spoofer = ArpSpoofer()


def handle_inverter_tcp_packet(pkt) -> None:
    if Raw not in pkt:
        return

    payload = bytes(pkt[Raw].load)
    if not payload:
        return

    flow_key = (pkt[IP].src, int(pkt[TCP].sport), pkt[IP].dst, int(pkt[TCP].dport))
    seq = int(pkt[TCP].seq)

    packets = append_stream_data(flow_key, seq, payload)

    if not packets:
        return

    for packet in packets:
        if LOG_VERBOSE:
            ptype = mqtt_type_name(packet[0])
            log(
                f"[MQTT PACKET] {pkt[IP].src}:{int(pkt[TCP].sport)} -> "
                f"{pkt[IP].dst}:{int(pkt[TCP].dport)} type={ptype} len={len(packet)} "
                f"first16={packet[:16].hex()}"
            )

        if ((packet[0] >> 4) & 0x0F) == 3:
            topic, publish_payload = extract_publish_payload(packet)
            if topic is not None:
                count = SEEN_MQTT_TOPICS.get(topic, 0) + 1
                SEEN_MQTT_TOPICS[topic] = count
                if LOG_MQTT_TOPICS:
                    log_kv("[MQTT TOPIC]", topic=topic, seen_count=count, payload_len=len(publish_payload or b""))
            if LOG_VERBOSE and topic is not None:
                log(f"[MQTT PUBLISH] topic={topic} payload_len={len(publish_payload or b'')}")
            if publish_payload and LOG_MQTT_PAYLOAD_PREVIEW:
                log_payload_preview("[MQTT PAYLOAD]", publish_payload, topic=topic)
            if publish_payload:
                record_modbus_response(publish_payload)
                parsed_ok = SolarParser.parse_payload(publish_payload, source_topic=topic)
                if not parsed_ok and LOG_UNPARSED_PUBLISH:
                    log_payload_preview("[MQTT PAYLOAD NOT PARSED]", publish_payload, topic=topic)


def handle_cloud_tcp_packet(pkt) -> None:
    """Log cloud-originated MQTT packets without treating them as HA telemetry.

    The bridge is deliberately passive: this only makes the RPC request that
    precedes a dongle reply observable during diagnostics.  It must never feed
    cloud packets into ``SolarParser`` or publish them to Home Assistant.
    """
    if Raw not in pkt:
        return

    payload = bytes(pkt[Raw].load)
    if not payload:
        return

    flow_key = (pkt[IP].src, int(pkt[TCP].sport), pkt[IP].dst, int(pkt[TCP].dport))
    seq = int(pkt[TCP].seq)
    packets = append_stream_data(flow_key, seq, payload)

    for packet in packets:
        if LOG_VERBOSE:
            ptype = mqtt_type_name(packet[0])
            log(
                f"[MQTT CLOUD PACKET] {pkt[IP].src}:{int(pkt[TCP].sport)} -> "
                f"{pkt[IP].dst}:{int(pkt[TCP].dport)} type={ptype} len={len(packet)} "
                f"first16={packet[:16].hex()}"
            )

        if ((packet[0] >> 4) & 0x0F) == 3:
            topic, publish_payload = extract_publish_payload(packet)
            if LOG_VERBOSE and topic is not None:
                log(f"[MQTT CLOUD PUBLISH] topic={topic} payload_len={len(publish_payload or b'')}")
            if publish_payload and LOG_MQTT_PAYLOAD_PREVIEW:
                log_payload_preview("[MQTT CLOUD PAYLOAD]", publish_payload, topic=topic)
            if publish_payload:
                record_modbus_request(publish_payload)


def packet_callback(pkt) -> None:
    global INV_MAC, RTR_MAC, LAST_PACKET_TS

    LAST_PACKET_TS = time.time()

    if IP not in pkt or Ether not in pkt:
        return

    src_mac = norm_mac(pkt[Ether].src)
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    if src_ip == INVERTER_IP and not INV_MAC:
        INV_MAC = src_mac
    if dst_ip == INVERTER_IP and not RTR_MAC:
        RTR_MAC = src_mac

    if src_ip == INVERTER_IP and src_mac:
        KNOWN_INVERTER_MACS.add(src_mac)
    if dst_ip == INVERTER_IP and src_mac:
        KNOWN_ROUTER_MACS.add(src_mac)

    if LOG_VERBOSE and (src_ip == INVERTER_IP or dst_ip == INVERTER_IP):
        proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        port = f":{pkt[TCP].dport}" if TCP in pkt else ""
        log(f"[X-RAY] {src_ip} ({src_mac}) -> {dst_ip}{port} [{proto}]")

    if src_ip == INVERTER_IP:
        if INV_MAC and src_mac != INV_MAC:
            return

        if TCP in pkt and dst_ip == TARGET_HOST and int(pkt[TCP].dport) == TARGET_PORT:
            try:
                handle_inverter_tcp_packet(pkt)
            except Exception as exc:
                log(f"[TCP PARSE ERROR] {exc}", level="error")

        if AUTO_INTERCEPT and RTR_MAC:
            try:
                fwd_pkt = Ether(dst=RTR_MAC) / pkt[IP]
                send_layer2(fwd_pkt, SNIFF_IFACE)
            except Exception as exc:
                log(f"[FWD ERROR] inverter->router {exc}", level="error")
        return

    if dst_ip == INVERTER_IP:
        if RTR_MAC and src_mac != RTR_MAC:
            return

        if TCP in pkt and src_ip == TARGET_HOST and int(pkt[TCP].sport) == TARGET_PORT:
            try:
                handle_cloud_tcp_packet(pkt)
            except Exception as exc:
                log(f"[CLOUD TCP PARSE ERROR] {exc}", level="error")

        if AUTO_INTERCEPT and INV_MAC:
            try:
                fwd_pkt = Ether(dst=INV_MAC) / pkt[IP]
                send_layer2(fwd_pkt, SNIFF_IFACE)
            except Exception as exc:
                log(f"[FWD ERROR] router->inverter {exc}", level="error")


def health_logger() -> None:
    while RUNNING:
        time.sleep(30)
        age = time.time() - LAST_PACKET_TS if LAST_PACKET_TS else -1
        if age < 0:
            log("[HEALTH] No packets captured yet", level="info")
        else:
            inv_list = sorted(x for x in KNOWN_INVERTER_MACS if x)
            rtr_list = sorted(x for x in KNOWN_ROUTER_MACS if x)
            log(
                f"[HEALTH] Last packet seen {int(age)}s ago; inverter_macs={inv_list}; router_macs={rtr_list}",
                level="info",
            )


def shutdown(*_args) -> None:
    global RUNNING, sniffer

    if not RUNNING:
        return

    RUNNING = False

    try:
        if sniffer is not None:
            sniffer.stop()
    except Exception:
        pass

    try:
        set_local_telemetry_available(False)
        set_temperature_telemetry_available(False)
        for group in get_grouped_sensor_keys():
            client.publish(availability_topic_for_group(group), "offline", retain=True)
        client.disconnect()
        client.loop_stop()
    except Exception:
        pass

    log("[Bridge] Stopped")


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

VERSION = "2.5.25"  # Keep in sync with siseli_bridge/config.yaml


if __name__ == "__main__":
    from .config import validate_config
    validate_config()
    log(f"--- Siseli Inverter Bridge {VERSION} ---")
    log(f"[Config] INVERTER_IP={INVERTER_IP} ROUTER_IP={ROUTER_IP}")
    log(f"[Config] TARGET={TARGET_HOST}:{TARGET_PORT} MQTT={MQTT_HOST}:{MQTT_PORT}")
    log(f"[Config] AUTO_INTERCEPT={AUTO_INTERCEPT} LISTEN_PORT={LISTEN_PORT}")
    log(f"[Config] INVERTER_COUNT={INVERTER_COUNT}")
    log(f"[Config] BATTERY_COUNT={BATTERY_COUNT} BATTERY_CAPACITY_PER_BATTERY_AH={BATTERY_CAPACITY_PER_BATTERY_AH}")
    log(f"[Config] DEVICE_NAME={DEVICE_NAME} MANUFACTURER={MANUFACTURER}")
    log(f"[Config] STATE_TOPIC={STATE_TOPIC}")
    log(f"[Config] SNIFF_IFACE={SNIFF_IFACE or 'auto'}")
    log(f"[Config] DEBUG_FLAGS verbose={LOG_VERBOSE} blocks={LOG_BLOCKS} state_diff={LOG_STATE_DIFF} state_snapshot={LOG_STATE_SNAPSHOT} raw_json={LOG_RAW_JSON} clean_state={LOG_CLEAN_STATE} mqtt_topics={LOG_MQTT_TOPICS} payload_preview={LOG_MQTT_PAYLOAD_PREVIEW} unparsed={LOG_UNPARSED_PUBLISH} stream_events={LOG_STREAM_EVENTS} null_targets={LOG_NULL_TARGETS}")

    for key in SENSORS.keys():
        _state.LAST_STATE.setdefault(key, None)

    start_mqtt()
    threading.Thread(target=local_telemetry_listener, daemon=True).start()

    if AUTO_INTERCEPT:
        threading.Thread(target=arp_spoofer.run, daemon=True).start()
        wait_start = time.time()
        while RUNNING and time.time() - wait_start < 15 and (not INV_MAC or not RTR_MAC):
            time.sleep(1)
    else:
        INV_MAC = norm_mac(INVERTER_MAC_CFG)
        RTR_MAC = norm_mac(ROUTER_MAC_CFG)
        log("[ARP] AUTO_INTERCEPT disabled; relying on existing network redirection")

    threading.Thread(target=health_logger, daemon=True).start()

    sniff_kwargs = {
        "filter": f"ip host {INVERTER_IP}",
        "prn": packet_callback,
        "store": False,
    }
    if SNIFF_IFACE:
        sniff_kwargs["iface"] = SNIFF_IFACE

    sniffer = AsyncSniffer(**sniff_kwargs)
    sniffer.start()
    log("[Bridge] Sniffer started", level="info")

    try:
        while RUNNING:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        shutdown()
