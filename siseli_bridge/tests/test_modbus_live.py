"""Regression coverage for validated telemetry and MQTT availability."""
import base64
import json
import unittest
from unittest import mock

from src.siseli_bridge import core, mqtt


class TestModbusLive(unittest.TestCase):
    def setUp(self):
        self.last_state = dict(core._state.LAST_STATE)
        self.published_keys = set(core._state.PUBLISHED_SENSOR_KEYS)
        core.PENDING_MODBUS.clear()
        core.MODBUS_REGISTERS.clear()

    def tearDown(self):
        core.PENDING_MODBUS.clear()
        core.MODBUS_REGISTERS.clear()
        core._state.LAST_STATE.clear()
        core._state.LAST_STATE.update(self.last_state)
        core._state.PUBLISHED_SENSOR_KEYS.clear()
        core._state.PUBLISHED_SENSOR_KEYS.update(self.published_keys)

    @staticmethod
    def _with_crc(data: bytes) -> bytes:
        return data + core._modbus_crc(data).to_bytes(2, "little")

    def test_live_register_words_are_low_byte_first(self):
        self.assertEqual(core._decode_live_register(b"\x70\x04"), 1136)
        self.assertEqual(core._decode_live_register(b"\xf5\x01"), 501)
        with self.assertRaises(ValueError):
            core._decode_live_register(b"\x01")

    @mock.patch("src.siseli_bridge.core._persist_modbus_registers")
    @mock.patch("src.siseli_bridge.core.publish_powmr_live_block")
    def test_correlated_4501_block_uses_device_word_order(self, publish, _persist):
        transaction = "Test1234"
        registers = [0, 1136, 501, 0, 0, 267, 100, 0, 17, 1210, 501, 447, 410, 12] + [0] * 31
        request = self._with_crc(bytes.fromhex("05031195002d"))
        request_payload = b"\x00" + json.dumps({
            "t": transaction,
            "b": {"ci": base64.b64encode(request).decode()},
        }).encode()
        core.record_modbus_request(request_payload)

        response = self._with_crc(
            b"\x05\x03\x5a"
            + b"".join(value.to_bytes(2, "little") for value in registers)
        )
        response_payload = b"\x00" + json.dumps({
            "t": transaction,
            "b": {"co": base64.b64encode(response).decode()},
        }).encode()
        core.record_modbus_response(response_payload)

        publish.assert_called_once_with(4501, registers)
        self.assertEqual(core.MODBUS_REGISTERS["0x1196"]["value"], 1136)
        self.assertEqual(core.MODBUS_REGISTERS["0x1197"]["value"], 501)

    @mock.patch("src.siseli_bridge.core.set_local_telemetry_available")
    @mock.patch("src.siseli_bridge.core.publish_powmr_live_block")
    def test_local_gateway_frame_is_independently_validated(self, publish, availability):
        registers = [0, 1136, 501, 0, 0, 267, 100, 0, 17, 1210, 501, 447, 410, 12] + [0] * 31
        frame = self._with_crc(
            b"\x05\x03\x5a"
            + b"".join(value.to_bytes(2, "little") for value in registers)
        )
        payload = json.dumps({
            "transaction": "Test1234",
            "address": 4501,
            "frame": base64.b64encode(frame).decode(),
        }).encode()

        self.assertTrue(core.accept_local_telemetry_datagram(payload, core.LOCAL_TELEMETRY_SOURCE))
        publish.assert_called_once_with(4501, registers)
        availability.assert_called_once_with(True)

        publish.reset_mock()
        damaged = bytearray(frame)
        damaged[10] ^= 1
        rejected = json.dumps({
            "transaction": "Test1234",
            "address": 4501,
            "frame": base64.b64encode(damaged).decode(),
        }).encode()
        self.assertFalse(core.accept_local_telemetry_datagram(rejected, core.LOCAL_TELEMETRY_SOURCE))
        self.assertFalse(core.accept_local_telemetry_datagram(payload, "192.168.0.99"))
        publish.assert_not_called()

    @mock.patch("src.siseli_bridge.core.set_temperature_telemetry_available")
    @mock.patch("src.siseli_bridge.core.publish_powmr_live_block")
    def test_local_companion_block_is_separately_available(self, publish, availability):
        registers = [0] * 16
        registers[7] = 0x0040
        registers[8] = 0x0001
        registers[9] = 2
        registers[11] = 40
        body = b"\x05\x03\x20" + b"".join(value.to_bytes(2, "little") for value in registers)
        frame = self._with_crc(body)
        payload = json.dumps({
            "transaction": "Temp1234",
            "address": 4546,
            "frame": base64.b64encode(frame).decode(),
        }).encode()

        self.assertTrue(core.accept_local_telemetry_datagram(payload, core.LOCAL_TELEMETRY_SOURCE))
        publish.assert_called_once_with(4546, registers)
        availability.assert_called_once_with(True)

    def test_companion_block_decodes_status_and_whole_degree_temperature(self):
        registers = [0] * 16
        registers[7] = 0x0040
        registers[8] = 0x0001
        registers[9] = 2
        registers[11] = 40
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4546, registers)
        grouped.assert_called_once_with({
            "grid_active": True,
            "on_battery": False,
            "load_enabled": True,
            "charger_status": "Active",
            "charger_status_raw": 2,
            "status_flags_4553_raw": 0x0040,
            "status_flags_4554_raw": 0x0001,
            "inverter_temperature_c": 40,
            "strong_charging_voltage_v": 0.0,
            "float_charging_voltage_v": 0.0,
            "low_electric_lock_voltage_v": 0.0,
            "battery_equalization_voltage_v": 0.0,
            "equalization_time": "0 min",
            "equalization_overtime": "0 min",
            "equalization_interval": "0 days",
        })

    def test_main_block_decodes_swapped_power_and_probable_overload(self):
        registers = [0, 1153, 501, 0, 0, 265, 100, 0, 9, 1199, 502, 239, 217, 6, 6, 0x1] + [0] * 29
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4501, registers)
        state = grouped.call_args.args[0]
        self.assertEqual(state["apparent_va"], 239)
        self.assertEqual(state["load_w"], 217)
        self.assertEqual(state["load_power_factor"], 90.8)
        self.assertEqual(state["load_current_a"], 1.99)
        self.assertTrue(state["overload_active"])
        self.assertEqual(state["overload_flag_raw"], 0x1)

    def test_main_block_derives_useful_pv_values(self):
        registers = [0] * 45
        registers[3] = 1000  # 100.0 V
        registers[4] = 500   # 500 W PV
        registers[12] = 217  # 217 W load
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4501, registers)
        state = grouped.call_args.args[0]
        self.assertEqual(state["pv_current_a"], 5.0)
        self.assertEqual(state["pv_surplus_w"], 283)
        self.assertTrue(state["pv_generating"])

    def test_main_block_reports_zero_pv_derivatives_at_night(self):
        registers = [0] * 45
        registers[12] = 217
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4501, registers)
        state = grouped.call_args.args[0]
        self.assertEqual(state["pv_current_a"], 0.0)
        self.assertEqual(state["pv_surplus_w"], 0)
        self.assertFalse(state["pv_generating"])

    def test_main_block_decodes_read_only_lcd_program_values(self):
        registers = [0] * 45
        registers[34:45] = [0x0145, 2, 2, 0, 2, 0, 80, 120, 40, 240, 270]
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4501, registers)
        state = grouped.call_args.args[0]
        self.assertEqual(state["working_mode"], "SBU priority")
        self.assertEqual(state["charging_priority_order"], "Solar and Utility")
        self.assertEqual(state["mains_input_range"], "Appliances (90-280 VAC)")
        self.assertEqual(state["battery_type"], "User-defined")
        self.assertEqual(state["maximum_total_charging_current_a"], 80)
        self.assertEqual(state["output_set_voltage"], 120)
        self.assertEqual(state["return_to_mains_mode_voltage_v"], 24.0)
        self.assertEqual(state["return_to_battery_mode_voltage_v"], 27.0)
        self.assertEqual(state["buzzer_function"], "On")
        self.assertEqual(state["overload_restart_function"], "Off")
        self.assertEqual(state["record_fault_code"], "On")

    def test_companion_block_decodes_read_only_battery_program_values(self):
        registers = [288, 270, 220, 292, 60, 120, 30, 1137, 7, 10, 0, 35, 0, 0, 5, 1]
        with mock.patch("src.siseli_bridge.core.publish_grouped_state") as grouped, \
             mock.patch("src.siseli_bridge.core.publish_sensor_discovery"):
            core.publish_powmr_live_block(4546, registers)
        state = grouped.call_args.args[0]
        self.assertEqual(state["strong_charging_voltage_v"], 28.8)
        self.assertEqual(state["float_charging_voltage_v"], 27.0)
        self.assertEqual(state["low_electric_lock_voltage_v"], 22.0)
        self.assertEqual(state["battery_equalization_voltage_v"], 29.2)
        self.assertEqual(state["equalization_time"], "60 min")
        self.assertEqual(state["equalization_overtime"], "120 min")
        self.assertEqual(state["equalization_interval"], "30 days")

    @mock.patch("src.siseli_bridge.core.set_local_telemetry_available")
    def test_local_gateway_can_only_report_offline_status(self, availability):
        offline = json.dumps({"kind": "status", "available": False}).encode()
        online = json.dumps({"kind": "status", "available": True}).encode()
        self.assertTrue(core.accept_local_telemetry_datagram(offline, core.LOCAL_TELEMETRY_SOURCE))
        self.assertFalse(core.accept_local_telemetry_datagram(online, core.LOCAL_TELEMETRY_SOURCE))
        availability.assert_called_once_with(False)

    def test_live_sensor_discovery_requires_bridge_and_local_availability(self):
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_sensor_discovery("grid_v")
        discovery = json.loads(publish.call_args.args[1])
        self.assertEqual(discovery["availability_mode"], "all")
        self.assertEqual(len(discovery["availability"]), 2)
        self.assertEqual(
            discovery["availability"][1]["topic"],
            mqtt.LOCAL_TELEMETRY_AVAILABILITY_TOPIC,
        )
        self.assertNotIn("availability_topic", discovery)

    def test_temperature_discovery_uses_separate_availability(self):
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_sensor_discovery("inverter_temperature_c")
        discovery = json.loads(publish.call_args.args[1])
        self.assertEqual(
            discovery["availability"][1]["topic"],
            mqtt.TEMPERATURE_TELEMETRY_AVAILABILITY_TOPIC,
        )

    def test_overload_discovery_is_binary_problem_entity(self):
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_sensor_discovery("overload_active")
        topic, raw = publish.call_args.args[:2]
        discovery = json.loads(raw)
        self.assertIn("/binary_sensor/", topic)
        self.assertEqual(discovery["device_class"], "problem")
        self.assertEqual(discovery["payload_on"], "ON")

    def test_pv_generating_discovery_is_binary_entity(self):
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_sensor_discovery("pv_generating")
        topic, raw = publish.call_args.args[:2]
        discovery = json.loads(raw)
        self.assertIn("/binary_sensor/", topic)
        self.assertEqual(discovery["payload_on"], "ON")
        self.assertEqual(
            discovery["availability"][1]["topic"],
            mqtt.LOCAL_TELEMETRY_AVAILABILITY_TOPIC,
        )

    def test_discovery_clears_entities_without_validated_values(self):
        core._state.LAST_STATE.clear()
        core._state.LAST_STATE.update({
            "grid_v": 113.7,
            "float_charging_voltage_v": None,
        })
        core._state.PUBLISHED_SENSOR_KEYS.clear()
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_discovery()

        calls = {call.args[0]: call.args[1] for call in publish.call_args_list}
        self.assertTrue(calls[mqtt.discovery_topic_for_key("grid_v")])
        self.assertEqual(
            calls[mqtt.discovery_topic_for_key("float_charging_voltage_v")],
            "",
        )
        self.assertIn("grid_v", core._state.PUBLISHED_SENSOR_KEYS)
        self.assertNotIn(
            "float_charging_voltage_v", core._state.PUBLISHED_SENSOR_KEYS
        )

    def test_grouped_state_omits_null_fields(self):
        core._state.LAST_STATE.clear()
        core._state.LAST_STATE.update({"grid_v": 113.7, "grid_hz": None})
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_grouped_state({"grid_v": 113.7, "grid_hz": None})
        self.assertEqual(publish.call_count, 1)
        payload = json.loads(publish.call_args.args[1])
        self.assertEqual(payload, {"grid_v": 113.7})

    def test_grouped_state_keeps_cached_keys_on_partial_update(self):
        core._state.LAST_STATE.clear()
        core._state.LAST_STATE.update({
            "working_mode": "SBU priority",
            "float_charging_voltage_v": 27.0,
        })
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_grouped_state({"float_charging_voltage_v": 27.0})
        payload = json.loads(publish.call_args.args[1])
        self.assertEqual(payload["working_mode"], "SBU priority")
        self.assertEqual(payload["float_charging_voltage_v"], 27.0)


if __name__ == "__main__":
    unittest.main()
