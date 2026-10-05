# SOLO HUNTER v1.0.6 — HELIOS mining performance upgrade

SOLO HUNTER now brings HELIOS HUNTER's mining engine to both ILI9341 and ST7789 CYDs, with a hardware SHA pipeline and a second-core software helper designed to increase hash rate.

## What's new

- Optimized hardware SHA-256d mining with a software helper working on a separate nonce range.
- Mining continues during wallet and price HTTPS requests instead of using SOLO's previous hashing pause.
- Hardware candidate verification, automatic SHA recovery, and software fallback.
- Display and web work scheduled separately from the primary hardware miner.
- The familiar SOLO DigiByte display, wallet alerts, and mining settings are retained.

## Hash-rate expectations

This is a performance-focused engine upgrade. Actual SOLO HUNTER before/after hash rates have not yet been measured for this port, so no numeric speed or percentage gain is claimed. Results depend on the ESP32 chip, clock settings, pool, and network activity. Compare sustained hash rate and pool-accepted shares on the same device and pool when testing.

## Source prerelease — firmware pending

This prerelease contains source code for both display variants. No new flashable `.bin` files are included. Compilation and device validation are pending; the existing v1.0.5 firmware does not include this upgrade.

Download the source archive below and open the matching folder:

- `SOLO_HUNTER_v1_0_6_ILI9341/SOLO_HUNTER_v1_0_6_ILI9341.ino`
- `SOLO_HUNTER_v1_0_6_ST7789/SOLO_HUNTER_v1_0_6_ST7789.ino`

Each folder contains its required miner and SHA source files. Use the ESP32 core/toolchain compatible with HELIOS HUNTER, plus ArduinoJson, LovyanGFX, and WiFiManager. The fast hardware path requires classic ESP32 with 240 MHz CPU / 80 MHz APB clocks.

Before a stable firmware release, validate compilation, accepted shares, sustained hash rate, web/display responsiveness during HTTPS refreshes, mining enable/disable, and pool reconnection on both display variants.