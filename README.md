# SOLO HUNTER v1.0.6

SOLO HUNTER is an ESP32 CYD DigiByte wallet display with an optional SHA-256
solo-mining mode. Version 1.0.6 uses the HELIOS HUNTER engine and retains mining
statistics to the screen and a separate Mining tab in the Web UI.

[Download SOLO HUNTER v1.0.6](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/tag/v1.0.6)

## HELIOS mining performance upgrade

v1.0.6 adds the HELIOS hardware SHA-256d pipeline and a software helper on the
second core, designed to increase hash rate. Mining continues during wallet
and price HTTPS requests. Hardware candidate verification, SHA recovery, and
software fallback are included.

The project owner compiled, flashed, and confirmed successful hashing on both
ILI9341 and ST7789 versions. The downloads are the owner's exported complete
4 MB images. A measured SOLO before/after benchmark has not been provided;
no numeric speed or percentage gain is claimed. Performance varies by device,
clock settings, pool, and network activity.

[Read the v1.0.6 release notes](RELEASE_NOTES_v1.0.6.md).

## Highlights

- Live DigiByte wallet balance and USD, GBP, or CAD value
- Persistent wallet `BLOCK FOUND` alert when the DGB balance increases
- Optional SHA-256 Stratum mining
- Hardware SHA acceleration with automatic recovery
- Live Web UI mining dashboard
- On-screen hashrate, shares, best difficulty, and blocks found
- Separate ST7789 and ILI9341 firmware
- Build: `v1.0.6 / HELIOS-ENGINE`

## Choose Your Firmware

| Screen | Download |
| --- | --- |
| ST7789 | [SOLO_HUNTER_v1.0.6_ST7789.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ST7789.bin) |
| ILI9341 | [SOLO_HUNTER_v1.0.6_ILI9341.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ILI9341.bin) |

Use the file that matches the screen controller in your device. The wrong file
can produce a black screen, incorrect colors, or a distorted display. If that
happens, flash the other screen version.

## Full install with ESP Web Tool — clears settings

No Arduino IDE is required. Use Google Chrome or Microsoft Edge and open the
[Espressif ESP Web Tool](https://espressif.github.io/esptool-js/).

1. Connect the ESP32 with a data-capable USB cable.
2. Close any Serial Monitor or other program using the device's COM port.
3. Click `Connect` and select the ESP32 USB serial port.
4. Select the downloaded SOLO HUNTER `.bin` file.
5. Set the flash address to `0x0`.
6. Use `DIO`, `80 MHz`, and `4 MB` when those options are shown.
7. Enable erase flash, then click `Program`.
8. Wait for flashing and verification to finish before resetting the board.

These are complete 4 MB firmware images. A full flash clears saved WiFi, wallet,
currency, and mining settings.

If the Web Tool cannot connect, close other serial applications, try baud rate
`115200`, or hold the board's `BOOT` button while connecting.

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

## First-Time Setup

1. Connect to the WiFi network `SOLO_HUNTER_SETUP`.
2. Enter password `solohunter`.
3. Open `http://192.168.4.1` if the setup page does not appear automatically.
4. Enter your WiFi information and save.
5. Open the IP address shown on the SOLO HUNTER screen.

## Web UI

### Display Tab

Configure the DigiByte wallet address, display currency, and screen rotation.

### Mining Tab

Enable SHA-256 mining and enter the pool host, port, wallet or pool username,
worker name, and pool password. The dashboard shows hashrate, mining engine,
session totals, share counters, difficulty, and blocks found.

## Mining Statistics

The left side of the physical display shows:

- `HASH` - current hashrate
- `ACC` - accepted shares
- `REJ` - rejected shares
- `BEST` - best share difficulty
- `BLK` - network-target hashes found during the mining session

Accepted shares are not automatically blocks. The `BLK` counter increases only
when a verified hash also meets the network target supplied by the pool job.

The full-screen `BLOCK FOUND` popup is separate: it means the configured DGB
wallet balance increased.

## Notes

- Mining mode supports SHA-256 only.
- SOLO HUNTER is a small ESP32 lottery miner, not an ASIC.
- Mining rewards are not guaranteed.
- The mining `BLK` counter resets with a new mining session.
- Do not expose the device Web UI directly to the public internet.
- Verify downloads with the release's
  [SHA256SUMS.txt](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SHA256SUMS.txt).

## Source Files

Complete sketches: `SOLO_HUNTER_v1_0_6_ILI9341` and
`SOLO_HUNTER_v1_0_6_ST7789`. The dashboard identifies this version as
**v1.0.6 / HELIOS-ENGINE**.


Use the `.ino` file matching the screen controller and keep
`SoloHunterMiner.cpp`, `SoloHunterMiner.h`, `SoloHunterSha256.cpp`, and
`SoloHunterSha256.h` in the same sketch folder when compiling.

This is hobby firmware. Flashing and cryptocurrency mining are performed at
your own risk.
