## Update an existing device and keep settings

For an existing SOLO HUNTER v1.0.5 or v1.0.6 installation, use the two update files for your display. This preserves saved Wi-Fi, wallet, currency, rotation, and mining settings when flashed as instructed. A new device still needs the complete firmware image.

| Display | Application update — flash at `0x10000` | Partition table — flash at `0x8000` |
| --- | --- | --- |
| ILI9341 | [ILI9341_UPDATE.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ILI9341_UPDATE.bin) | [ILI9341_PARTITIONS.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ILI9341_PARTITIONS.bin) |
| ST7789 | [ST7789_UPDATE.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ST7789_UPDATE.bin) | [ST7789_PARTITIONS.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ST7789_PARTITIONS.bin) |

1. Connect your device using [Espressif ESP Web Tool](https://espressif.github.io/esptool-js/) or an ESP32-compatible flasher that accepts multiple file/address rows.
2. **Turn OFF “Erase all flash.” Do not erase the whole device.**
3. Add the matching `PARTITIONS.bin` at **`0x8000`** and `UPDATE.bin` at **`0x10000`**. Program both in the same operation.
4. Wait for write verification, then reset the device. Confirm the dashboard shows **v1.0.6 / HELIOS-ENGINE** and your settings are still present.

**Do not flash `UPDATE.bin` at `0x0`. Do not use the complete 4 MB image for this procedure:** it overwrites saved settings even with whole-chip erase disabled.

The partition file is required when upgrading from v1.0.5 because v1.0.6 exceeds the old application slot. If v1.0.6 is already installed with the released layout, only the matching `UPDATE.bin` at `0x10000` is needed.

Both files are unchanged copies of the owner's exports. The old/new settings partition location and preference names match, and the write ranges exclude the settings partition. The settings-preserving upgrade procedure itself still needs device testing; the owner's earlier tests covered complete-image flashing and successful mining. Other versions or custom partition layouts have not been verified.

[Espressif documents](https://docs.espressif.com/projects/esptool/en/latest/esp32/esptool/basic-commands.html) that normal writes erase the affected flash sectors, while “erase all” clears the whole chip. Keeping writes away from the settings partition is what preserves the saved settings.
