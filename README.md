<img width="1966" height="1378" alt="SH1 0 5" src="https://github.com/user-attachments/assets/94345a36-bb17-49bf-8ac3-fef601176463" />
<img width="2048" height="1536" alt="dashboard" src="https://github.com/user-attachments/assets/ea24e3f8-c298-46b0-84ca-69bbd04d50d9" />
<img width="1783" height="1472" alt="reg dashboard" src="https://github.com/user-attachments/assets/69650da5-0673-421e-86ff-6aaf169e7fd1" />


🚀 SOLO_HUNTER v1.0.3

SOLO_HUNTER is a DigiByte wallet display built for ESP32 CYD / NerdMiner-style devices.

It provides a clean, real-time view of your wallet activity on a dedicated device—so you never miss the moment a block hits.

✨ Features
📡 Live DigiByte wallet balance
💰 Estimated USD value
🎉 BLOCK FOUND notification when balance increases
🔔 Persistent alerts (must be manually cleared)
⚙️ On-device settings:
WiFi setup
Wallet address
Screen rotation (flip)
🌐 Simple browser-based configuration
🆕 What’s New in v1.0.3
✅ Corrected firmware naming and version consistency
✅ Improved stability and display behavior
✅ Faster and more reliable USD value updates
✅ Minor UI and usability improvements
🧰 Supported Hardware
Device Type	Screen	Firmware File
ESP32 CYD / NerdMiner	ILI9341	SOLO_HUNTER_v1.0.3_ILI9341.bin
ESP32 CYD / NerdMiner	ST7789	SOLO_HUNTER_v1.0.3_ST7789_merged.bin
⚠️ IMPORTANT

You must use the correct firmware for your screen type.

If you flash the wrong version, you may see:

Blank screen
Wrong colors
Distorted or misaligned display

👉 If that happens, simply flash the other version.

🚀 Installation (No Arduino Required)

You do NOT need Arduino for this.

🧰 What You Need
ESP32 device (CYD / NerdMiner)
USB cable
Windows PC
ESP Flash Download Tool (or similar)
Correct .bin firmware file
🔧 Flashing Steps
Open your ESP flashing tool
Select Chip Type: ESP32
Select your COM port
Load the correct firmware:
ILI9341 → SOLO_HUNTER_v1.0.3_merged.bin
ST7789 → SOLO_HUNTER_v1.0.3_ST7789_merged.bin
Set flash address to:
0x0
Click Start / Flash
Wait for flashing to complete
📶 First-Time Setup

After flashing:

Power on the device
Connect to WiFi network:
SOLO_HUNTER_SETUP
Password:
solohunter
Open setup page automatically
If it does NOT open, go to:
http://192.168.4.1
Enter:
Your WiFi credentials
Your DigiByte wallet address
Save settings

👉 The device will connect and begin displaying your wallet data.

🌐 No Wallet Config?

If no wallet is set, the device will display its IP address.

➡️ Open that IP in your browser to access settings.

⚙️ Settings Page

Open the device IP in your browser to:

Change wallet address
Flip screen rotation
Clear BLOCK FOUND notification
Reopen WiFi setup
📝 Notes
BLOCK FOUND alerts stay on screen until manually cleared
USD value updates are faster and more reliable in this version
ILI9341 and ST7789 require different firmware files
📦 Files Included
SOLO_HUNTER_v1.0.3_ILI9341_merged.bin → ILI9341 firmware
SOLO_HUNTER_v1.0.3_ST7789_merged.bin → ST7789 firmware
.ino files → source code
💡 About

This project was built to be simple, fast, and usable for home miners—no coding required.

Set it up once, and let it watch your wallet 24/7.
