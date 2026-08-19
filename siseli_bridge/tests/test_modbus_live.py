"""Regression coverage for local live telemetry and MQTT availability."""
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
        with mock.patch.object(mqtt.client, "publish") as publish:
            mqtt.publish_grouped_state({"grid_v": 113.7, "grid_hz": None})
        self.assertEqual(publish.call_count, 1)
        payload = json.loads(publish.call_args.args[1])
        self.assertEqual(payload, {"grid_v": 113.7})


if __name__ == "__main__":
    unittest.main()

