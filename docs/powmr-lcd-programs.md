# PowMr LCD program telemetry

The local gateway publishes the following inverter configuration as read-only
Home Assistant sensors. The values come from the same CRC-validated FC03 blocks
already used for live telemetry; the bridge has no Modbus write path.

| LCD program | Home Assistant value | Read register |
|---|---|---:|
| P01 | Output source priority | 4537 |
| P02 | Maximum total charging current | 4541 |
| P03 | AC input voltage range | 4538 |
| P05 | Battery type | 4539 |
| P06 | Auto restart on overload | 4535 flag |
| P07 | Auto restart on over temperature | 4535 flag |
| P09 | Output frequency | 4540 |
| P10 | Output voltage | 4542 |
| P11 | Maximum utility charging current | 4543 |
| P12 | Back to utility voltage | 4544 |
| P13 | Back to battery voltage | 4545 |
| P16 | Charger source priority | 4536 |
| P18 | Buzzer alarm | 4535 flag |
| P19 | Auto return to default screen | 4535 flag |
| P20 | LCD backlight | 4535 flag |
| P22 | Beep on primary source failure | 4535 flag |
| P23 | Overload bypass | 4535 flag |
| P25 | Record fault code | 4535 flag |
| P26 | Bulk charging voltage | 4546 |
| P27 | Float charging voltage | 4547 |
| P29 | Low DC cut-off voltage | 4548 |
| P30 | Battery equalization | 4535 flag |
| P31 | Battery equalization voltage | 4549 |
| P33 | Battery equalization time | 4550 |
| P34 | Battery equalization timeout | 4551 |
| P35 | Battery equalization interval | 4552 |
| P36 | Equalization activate immediately | 4535 flag |

For this POW-LVM3.6M variant, P16 register 4536 uses the three LCD choices
`0 = Solar first (CSO)`, `1 = Solar and Utility (SNU)`, and
`2 = Only Solar (OSO)`. The installed inverter's LCD and raw value 2 were
cross-checked on 2026-08-20; do not apply the four-mode enum used by other
PowMr model families.

Registers 4501-4545 refresh every minute. Registers 4546-4561 refresh every
five minutes. Unknown model-specific enum values are displayed as a numeric
variant code rather than being assigned an unverified label.

The 4535 masks published by community maps describe raw wire-byte order. This
bridge first normalizes the inverter's low-byte-first words, then applies the
correspondingly byte-swapped masks. The disabled-by-default
`settings_flags_4535_raw` entity preserves the normalized word for diagnosis.

## Current validated installation

The Norwood 24 V / 120 V inverter reported these values on 2026-08-19:

- P01 SBU priority
- P02 80 A
- P03 Appliances (90-280 VAC)
- P05 User-defined
- P09 50 Hz
- P10 120 V
- P11 40 A
- P12 24.0 V
- P13 27.0 V
- P16 Only Solar (OSO)
- P26 28.8 V
- P27 27.0 V
- P29 22.0 V
- P31 29.2 V
- P33 60 minutes
- P34 120 minutes
- P35 30 days

Treat the entities as remote visibility, not remote configuration controls.
Any future write support requires a separate safety review and explicit opt-in.
