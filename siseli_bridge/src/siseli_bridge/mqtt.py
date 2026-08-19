# Local telemetry extensions for PowMr/Siseli bridges.
import json
from typing import Dict

import paho.mqtt.client as mqtt

from . import state as _state
from .config import *
from .loggers import log
from .sensors import SENSORS, get_group_title, get_grouped_sensor_keys, get_sensor_group

RUNNING = True
LOCAL_TELEMETRY_AVAILABLE = False
TEMPERATURE_TELEMETRY_AVAILABLE = False

LOCAL_LIVE_SENSOR_KEYS = {
    "grid_v", "grid_hz", "pv_v", "pv_w", "bat_v", "bat_cap",
    "bat_charge_current", "dischg_current", "out_v", "out_hz",
    "load_w", "apparent_va", "load_pct", "status_code",
    "load_current_a", "load_power_factor", "overload_flag_raw", "overload_active",
    "settings_flags_4535_raw", "overload_restart_function",
    "over_temperature_restart_function", "buzzer_function",
    "automatic_return_to_first_page", "lcd_back_lighting",
    "beep_on_primary_source_fail", "overload_to_bypass_function",
    "record_fault_code", "battery_equalization_mode",
    "battery_equalization_immediate", "charging_priority_order", "working_mode",
    "mains_input_range", "battery_type", "output_set_frequency",
    "maximum_total_charging_current_a", "output_set_voltage",
    "max_utility_charge_current_a", "return_to_mains_mode_voltage_v",
    "return_to_battery_mode_voltage_v",
}
TEMPERATURE_SENSOR_KEYS = {
    "inverter_temperature_c", "charger_status", "grid_active", "on_battery",
    "load_enabled", "charger_status_raw", "status_flags_4553_raw",
    "status_flags_4554_raw",
    "strong_charging_voltage_v", "float_charging_voltage_v",
    "low_electric_lock_voltage_v", "battery_equalization_voltage_v",
    "equalization_time", "equalization_overtime", "equalization_interval",
}

_SECTION_PREFIXES = (
    "Device Info - ",
    "Battery Status - ",
    "BMS Status - ",
    "Grid Status - ",
    "Load Status - ",
    "PV Panel Status - ",
    "Settings - ",
)


def _trim_section_prefix(name: str) -> str:
    for prefix in _SECTION_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def display_sensor_name(base_name: str) -> str:
    trimmed = _trim_section_prefix(base_name)
    return f"{ENTITY_PREFIX} {trimmed}".strip() if ENTITY_PREFIX else trimmed


def device_id_for_group(group: str) -> str:
    if group == "main":
        return DEVICE_ID
    return f"{DEVICE_ID}_{group}"


def state_topic_for_group(group: str) -> str:
    if group == "main":
        return STATE_TOPIC
    if STATE_TOPIC.endswith("/state"):
        return f"{STATE_TOPIC[:-6]}/{group}/state"
    return f"{STATE_TOPIC}/{group}"


def availability_topic_for_group(group: str) -> str:
    if group == "main":
        return AVAILABILITY_TOPIC
    if AVAILABILITY_TOPIC.endswith("/availability"):
        return f"{AVAILABILITY_TOPIC[:-13]}/{group}/availability"
    return f"{AVAILABILITY_TOPIC}/{group}"


def device_info(group: str) -> Dict[str, object]:
    if group == "main":
        return {
            "identifiers": [DEVICE_ID],
            "name": DEVICE_NAME,
            "manufacturer": MANUFACTURER,
            "model": MODEL_NAME,
        }
    group_title = get_group_title(group)
    group_device_id = device_id_for_group(group)
    return {
        "identifiers": [group_device_id],
        "name": f"{DEVICE_NAME} {group_title}".strip(),
        "manufacturer": MANUFACTURER,
        "model": MODEL_NAME,
        "via_device": DEVICE_ID,
    }


def create_mqtt_client() -> mqtt.Client:
    try:
        c = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
            client_id=f"{DEVICE_ID}_bridge",
            protocol=mqtt.MQTTv311,
        )
    except Exception:
        c = mqtt.Client(client_id=f"{DEVICE_ID}_bridge", protocol=mqtt.MQTTv311)

    if MQTT_USER:
        c.username_pw_set(MQTT_USER, MQTT_PASSWORD)

    c.reconnect_delay_set(min_delay=5, max_delay=30)
    c.will_set(AVAILABILITY_TOPIC, "offline", retain=True)
    return c


client = create_mqtt_client()


def discovery_topic_for_key(key: str) -> str:
    group_device_id = device_id_for_group(get_sensor_group(key))
    platform = SENSORS.get(key, {}).get("platform", "sensor")
    return f"{MQTT_DISCOVERY_PREFIX}/{platform}/{group_device_id}/{key}/config"


def publish_sensor_discovery(key: str) -> None:
    if key not in SENSORS:
        return

    meta = SENSORS[key]
    group = get_sensor_group(key)
    group_device_id = device_id_for_group(group)
    topic = discovery_topic_for_key(key)
    payload = {
        "name": display_sensor_name(str(meta["name"])),
        "unique_id": f"{group_device_id}_{key}",
        "state_topic": state_topic_for_group(group),
        "value_template": f"{{{{ value_json.{key} }}}}",
        "availability_topic": availability_topic_for_group(group),
        "payload_available": "online",
        "payload_not_available": "offline",
        "device": device_info(group),
        "icon": meta.get("icon"),
    }
    if meta.get("platform") == "binary_sensor":
        payload["value_template"] = f"{{{{ 'ON' if value_json.{key} else 'OFF' }}}}"
        payload["payload_on"] = "ON"
        payload["payload_off"] = "OFF"
    telemetry_availability_topic = None
    if key in LOCAL_LIVE_SENSOR_KEYS:
        telemetry_availability_topic = LOCAL_TELEMETRY_AVAILABILITY_TOPIC
    elif key in TEMPERATURE_SENSOR_KEYS:
        telemetry_availability_topic = TEMPERATURE_TELEMETRY_AVAILABILITY_TOPIC
    if telemetry_availability_topic:
        payload.pop("availability_topic")
        payload.pop("payload_available")
        payload.pop("payload_not_available")
        payload["availability"] = [
            {
                "topic": availability_topic_for_group(group),
                "payload_available": "online",
                "payload_not_available": "offline",
            },
            {
                "topic": telemetry_availability_topic,
                "payload_available": "online",
                "payload_not_available": "offline",
            },
        ]
        payload["availability_mode"] = "all"

    if meta.get("unit"):
        payload["unit_of_measurement"] = meta["unit"]
    if meta.get("device_class"):
        payload["device_class"] = meta["device_class"]
    if meta.get("state_class"):
        payload["state_class"] = meta["state_class"]
    if meta.get("entity_category"):
        payload["entity_category"] = meta["entity_category"]
    if "enabled_by_default" in meta:
        payload["enabled_by_default"] = bool(meta["enabled_by_default"])

    client.publish(topic, json.dumps(payload), retain=True)
    _state.PUBLISHED_SENSOR_KEYS.add(key)


def clear_sensor_discovery(key: str) -> None:
    """Remove a retained entity definition that has no validated state."""
    if key not in SENSORS:
        return
    client.publish(discovery_topic_for_key(key), "", retain=True)
    _state.PUBLISHED_SENSOR_KEYS.discard(key)


def publish_discovery() -> None:
    published = 0
    cleared = 0
    for key in sorted(SENSORS.keys()):
        if _state.LAST_STATE.get(key) is not None:
            publish_sensor_discovery(key)
            published += 1
        else:
            clear_sensor_discovery(key)
            cleared += 1

    for group in get_grouped_sensor_keys():
        client.publish(availability_topic_for_group(group), "online", retain=True)
    _state.DISCOVERY_PUBLISHED = True
    log(
        f"[HA MQTT] Discovery reconciled published={published} cleared={cleared}",
        level="info",
    )


def publish_grouped_state(state_payload: Dict[str, object]) -> None:
    # A retained MQTT topic is shared by every sensor in a logical group. A
    # partial JSON update would therefore make templates for omitted keys render
    # blank in Home Assistant. Republish the complete cached state for only the
    # groups touched by this update.
    touched_groups = {
        get_sensor_group(key)
        for key, value in state_payload.items()
        if value is not None
    }
    merged_state = dict(_state.LAST_STATE)
    merged_state.update(state_payload)
    grouped_state: Dict[str, Dict[str, object]] = {}
    for key, value in merged_state.items():
        if value is None:
            continue
        group = get_sensor_group(key)
        if group in touched_groups:
            grouped_state.setdefault(group, {})[key] = value

    for group, payload in grouped_state.items():
        client.publish(state_topic_for_group(group), json.dumps(payload), retain=MQTT_RETAIN)


def set_local_telemetry_available(available: bool) -> None:
    global LOCAL_TELEMETRY_AVAILABLE
    LOCAL_TELEMETRY_AVAILABLE = available
    client.publish(
        LOCAL_TELEMETRY_AVAILABILITY_TOPIC,
        "online" if available else "offline",
        retain=True,
    )


def set_temperature_telemetry_available(available: bool) -> None:
    global TEMPERATURE_TELEMETRY_AVAILABLE
    TEMPERATURE_TELEMETRY_AVAILABLE = available
    client.publish(
        TEMPERATURE_TELEMETRY_AVAILABILITY_TOPIC,
        "online" if available else "offline",
        retain=True,
    )


def on_connect(_client, _userdata, _flags, rc, _properties=None):
    code = int(rc) if rc is not None else -1
    if code == 0:
        log(f"[HA MQTT] Connected to {MQTT_HOST}:{MQTT_PORT}", level="info")
        publish_discovery()
        set_local_telemetry_available(LOCAL_TELEMETRY_AVAILABLE)
        set_temperature_telemetry_available(TEMPERATURE_TELEMETRY_AVAILABLE)
        if any(v is not None for v in _state.LAST_STATE.values()):
            publish_grouped_state(_state.LAST_STATE)
    else:
        log(f"[HA MQTT ERROR] Connection failed with rc={code}", level="error")


def on_disconnect(_client, _userdata, rc, _properties=None):
    code = int(rc) if rc is not None else -1
    if code != 0 and RUNNING:
        log(f"[HA MQTT] Disconnected (rc={code}), retrying...", level="warning")


client.on_connect = on_connect
client.on_disconnect = on_disconnect


def start_mqtt() -> None:
    try:
        client.connect_async(MQTT_HOST, MQTT_PORT, 60)
        client.loop_start()
    except Exception as exc:
        log(f"[HA MQTT ERROR] {exc}", level="error")
