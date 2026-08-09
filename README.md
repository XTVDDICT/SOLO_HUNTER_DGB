<img width="1966" height="1378" alt="SH1 0 5" src="https://github.com/user-attachments/assets/94345a36-bb17-49bf-8ac3-fef601176463" />
<img width="2048" height="1536" alt="dashboard" src="https://github.com/user-attachments/assets/ea24e3f8-c298-46b0-84ca-69bbd04d50d9" />
<img width="1783" height="1472" alt="reg dashboard" src="https://github.com/user-attachments/assets/69650da5-0673-421e-86ff-6aaf169e7fd1" />


🚀 # SOLO HUNTER v1.0.5

SOLO HUNTER is an ESP32 CYD DigiByte wallet display with an optional SHA-256
solo-mining mode. Version 1.0.5 keeps the original DGB display and adds mining
statistics to the screen and a separate Mining tab in the Web UI.

[Download SOLO HUNTER v1.0.5](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/tag/v1.0.5)

## Highlights

- Live DigiByte wallet balance and USD, GBP, or CAD value
- Persistent wallet `BLOCK FOUND` alert when the DGB balance increases
- Optional SHA-256 Stratum mining
- Hardware SHA acceleration with automatic recovery
- Live Web UI mining dashboard
- On-screen hashrate, shares, best difficulty, and blocks found
- Separate ST7789 and ILI9341 firmware
- Build: `v1.0.5 / HW-SHA-9`

## Choose Your Firmware

| Screen | Download |
| --- | --- |
| ST7789 | [SOLO_HUNTER_v1.0.5_ST7789.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.5/SOLO_HUNTER_v1.0.5_ST7789.bin) |
| ILI9341 | [SOLO_HUNTER_v1.0.5_ILI9341.bin](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.5/SOLO_HUNTER_v1.0.5_ILI9341.bin) |

Use the file that matches the screen controller in your device. The wrong file
can produce a black screen, incorrect colors, or a distorted display. If that
happens, flash the other screen version.

## Flash With ESP Web Tool

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
  [SHA256SUMS.txt](https://github.com/XTVDDICT/SOLO_HUNTER_DGB/releases/download/v1.0.5/SHA256SUMS.txt).

## Source Files

Use the `.ino` file matching the screen controller and keep
`SoloHunterMiner.cpp`, `SoloHunterMiner.h`, `SoloHunterSha256.cpp`, and
`SoloHunterSha256.h` in the same sketch folder when compiling.

This is hobby firmware. Flashing and cryptocurrency mining are performed at
your own risk.

