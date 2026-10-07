# SOLO HUNTER v1.0.6 — HELIOS Mining Performance Upgrade

SOLO HUNTER now uses HELIOS HUNTER's mining engine on both ILI9341 and ST7789 CYDs. The hardware SHA-256d pipeline and second-core software helper are designed to increase hash rate, while mining continues during wallet and price HTTPS refreshes.

Both display versions were compiled, flashed, and confirmed hashing successfully by the project owner. These firmware downloads are the owner's exported binaries.

## Download firmware

| Display | Complete firmware image |
| --- | --- |
| ILI9341 | [SOLO_HUNTER_v1.0.6_ILI9341.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ILI9341.bin) |
| ST7789 | [SOLO_HUNTER_v1.0.6_ST7789.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SOLO_HUNTER_v1.0.6_ST7789.bin) |

Choose the image matching your screen controller. Both downloads are complete 4 MB merged images: flash at **0x0** using an ESP32-compatible flasher. A full image flash replaces saved Wi-Fi, wallet, and mining settings; save your settings first.

Verify downloads with [SHA256SUMS.txt](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.6/SHA256SUMS.txt). After flashing, the dashboard should show **v1.0.6 / HELIOS-ENGINE**.

## What's new

- Optimized hardware SHA-256d pipeline, plus a software helper searching a separate nonce range.
- Continued mining during wallet and price HTTPS requests instead of SOLO's previous hashing pause.
- Hardware candidate verification, automatic SHA recovery, and software fallback.
- Display and web work scheduled separately from the primary hardware miner.
- SOLO's DigiByte display, wallet alerts, web dashboard, and mining configuration remain available.

## Performance and testing

The owner reports both versions are hashing nicely after flashing. A measured before/after benchmark has not been provided, so no numeric speed or percentage increase is claimed. Sustained hash rate varies with chip revision, clock settings, pool, and network activity. Long-running stability and all refresh/reconnection paths have not been exhaustively validated.

## Source

The source archive includes complete sketch folders for both displays:

- `SOLO_HUNTER_v1_0_6_ILI9341/SOLO_HUNTER_v1_0_6_ILI9341.ino`
- `SOLO_HUNTER_v1_0_6_ST7789/SOLO_HUNTER_v1_0_6_ST7789.ino`

Each folder includes the miner and SHA source files. Libraries: ArduinoJson, LovyanGFX, and WiFiManager. The fast hardware path requires classic ESP32 at 240 MHz CPU / 80 MHz APB clocks.