# WRS — WhatsApp Recovery Scanner

A local-first, forensic-grade acquisition and recovery-assistance utility engineered for Android devices via Android Debug Bridge (ADB).

---

## 1. Overview & Capabilities

**WRS (WhatsApp Recovery Scanner)** is designed for digital forensics specialists, security researchers, and device owners who need to safely identify, inventory, validate, hash, and acquire WhatsApp data from an Android device without risking modification to the target phone.

### Key Capabilities
- **100% Local Execution**: Zero cloud APIs, telemetry, external network requests, or third-party tracking. All processing occurs locally on Kali Linux.
- **Two-Stage Acquisition Protocol**:
  1. *Discovery & Pre-Acquisition Inventory*: Recursively scans accessible shared storage and presents total file counts, sizes by category, and disk space assessments.
  2. *Explicit User Confirmation*: Files are never pulled without mandatory affirmative confirmation (`[y/N]`, defaulting to No).
- **Strict Forensic Safety**:
  - Never deletes, modifies, renames, or overwrites source files on the Android device.
  - Never executes write operations or root exploits on the device.
  - Read-only SQLite database inspection with `PRAGMA integrity_check`.
  - Non-destructive acquisition into structured directories.
- **Dual SHA-256 Verification**:
  - Computes destination file hash locally via memory-bounded streaming chunks.
  - Queries independent device-side SHA-256 via ADB when supported.
  - Strictly distinguishes verified files (`VERIFIED`) from cases where the source hash was unavailable on-device (`SOURCE_HASH_UNAVAILABLE`).
- **Comprehensive Forensic Reporting**:
  - Produces standalone **HTML**, **CSV**, and **JSON** reports with full metadata, verification statuses, and sanitized paths.
  - Standalone verification command to re-audit existing recovery archives against the original manifest.
- **Interrupted Transfer Resumption**:
  - Safe state persistence via incremental manifest updates.
  - Resumes without re-copying or overwriting already verified files.

---

## 2. System Requirements

- **Operating System**: Kali Linux 2023+ (or standard Debian/Ubuntu derivatives).
- **Python**: Python 3.11 or later (tested on Python 3.14).
- **Android Debug Bridge (ADB)**: Android SDK Platform-Tools 1.0.41+.
- **Disk Space**: Sufficient local storage at the destination path for target files plus a 10% safety margin (minimum 100 MiB free space safety buffer).

---

## 3. Installation on Kali Linux

### Step 1: Update Packages and Install ADB
On Kali Linux, ADB is available via the `adb` package:
```bash
sudo apt update
sudo apt install -y adb python3 python3-pip
```

Verify that ADB is operational:
```bash
adb version
```

### Step 2: Clone or Download the Repository
```bash
git clone https://github.com/your-repo/wrs.git
cd wrs
```

### Step 3: Install Optional Dependencies (Recommended)
Core functionality runs using Python's standard library alone. Optional libraries enhance terminal tables and file signature sniffing:
```bash
pip install -r requirements.txt --break-system-packages
```
*(Alternatively, use a Python virtual environment: `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt`)*

---

## 4. Android Device Preparation

### 1. Enable Developer Options
1. On the Android device, navigate to **Settings** > **About Phone**.
2. Tap **Build Number** 7 times until you see the prompt *"You are now a developer!"*.

### 2. Enable USB Debugging
1. Navigate to **Settings** > **System** > **Developer Options** (or **Additional Settings**).
2. Toggle **USB Debugging** to **ON**.
3. Connect the phone to your Kali Linux workstation via a USB data cable (ensure the cable supports data transfer, not charge-only).

### 3. Authorize the Workstation
1. Unlock the phone screen.
2. When the pop-up appears asking **"Allow USB debugging?"**, check **"Always allow from this computer"** and tap **Allow** / **OK**.
3. Verify connection in your Kali terminal:
   ```bash
   adb devices -l
   ```
   *Expected status:* `device` (if listed as `unauthorized`, unlock the screen and accept the prompt).

---

## 5. Usage & Workflow

### Interactive Menu Mode
Launch the interactive terminal interface:
```bash
python3 wrs.py
```

The menu provides:
```text
[1] Scan Android device and discover WhatsApp data (Inventory Only)
[2] Scan and acquire WhatsApp data
[3] Inspect an existing recovery folder
[4] Verify acquired files and hashes
[5] Generate or regenerate reports
[6] View supported recovery locations and limitations
[7] Exit
```

### Automated / CLI Scripting Mode
For headless or scripted execution:

- **List connected devices:**
  ```bash
  python3 wrs.py --list-devices
  ```

- **Perform inventory scan only (no file copying):**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --scan
  ```

- **Scan and acquire data to default recovery folder:**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire
  ```

- **Specify custom output directory:**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --output /path/to/forensics/case_01
  ```

- **Verify integrity of an existing acquired directory:**
  ```bash
  python3 wrs.py --verify ./recovery/Pixel_7_scan_2026-10-28_10-00-00
  ```

- **Unattended / Headless acquisition (strict non-interactive):**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --output ./recovery --unattended
  ```

---

## 6. Pre-Acquisition Preview & Confirmation

Before copying any data, WRS calculates a complete file inventory from the selected storage location and displays a detailed preview:

*(Illustrative Example Output)*
```text
========================================================================
  WRS — ACQUISITION PREVIEW
========================================================================
  Device           : Google Pixel 7
  Serial           : 28241FDH2006G7
  Android Version  : 14 (API 34)
  Scan Date        : 2026-10-28 09:30:45
  Selected Location: /storage/emulated/0/Android/media/com.whatsapp/WhatsApp/
------------------------------------------------------------------------
  CATEGORY                  FILES        TOTAL SIZE
  --------------------------------------------------
  Databases                     2          42.18 MiB
  Backups                       7         128.45 MiB
  Images                      450         312.80 MiB
  Videos                       32         850.12 MiB
  Audio                        18          14.20 MiB
  Voice Notes                 812          68.90 MiB
  Documents                    24          45.10 MiB
  Stickers                    120          11.35 MiB
  Animated GIFs                 6           4.12 MiB
  Other                        45           1.25 MiB
  --------------------------------------------------
  TOTAL                      1516           1.44 GiB

  Unreadable Files       : 0
  Skipped Files          : 0
  Database/Backup Assets : 9
  Destination Directory  : /home/bablu/TOOLS/wrs/recovery/Pixel_7_scan_2026-10-28_09-30-45
  Storage Assessment     : Disk space OK: 148.50 GiB available. Required: 1.44 GiB + 147.45 MiB safety margin.
========================================================================

The scanner is ready to copy the selected files to:
  /home/bablu/TOOLS/wrs/recovery/Pixel_7_scan_2026-10-28_09-30-45

No source files will be deleted or modified on the Android device.

Proceed with acquisition? [y/N]: 
```

**Safeguard Rules:**
- The default option is **No**.
- Only affirmative input (`y` or `yes`) initiates acquisition.
- If storage space on the workstation is insufficient, WRS stops immediately before any transfer starts.

---

## 7. Recovery Directory Structure

Acquired files are organized into standard forensic directories:

```text
recovery/
└── Pixel_7_scan_2026-10-28_09-30-45/
    ├── metadata/
    │   ├── device.json
    │   ├── scan_summary.json
    │   ├── acquisition_manifest.json
    │   └── errors.json
    ├── Databases/
    │   ├── msgstore.db.crypt14
    │   └── wa.db
    ├── Backups/
    │   ├── msgstore-2026-10-25.1.db.crypt14
    │   └── msgstore-2026-10-26.1.db.crypt14
    ├── Images/
    │   └── IMG-20261025-WA0001.jpg
    ├── Videos/
    ├── Audio/
    ├── Voice_Notes/
    │   └── PTT-20261025-WA0002.opus
    ├── Documents/
    ├── Stickers/
    ├── Animated_GIFs/
    ├── Thumbnails/
    ├── Other/
    └── reports/
        ├── report.html
        ├── report.csv
        └── report.json
```

---

## 8. File Classification Rules

Files are categorized into forensically distinct buckets:

| Category | Description & Qualification Rules |
| :--- | :--- |
| **Databases** | Active WhatsApp SQLite databases (`msgstore.db`, `wa.db`, `chatsettingsbackup.db`) and active encrypted databases (`msgstore.db.crypt14`, `msgstore.db.crypt15`). |
| **Backups** | Dated WhatsApp backup archives matching date patterns (e.g. `msgstore-YYYY-MM-DD.N.db.crypt14/15`). *Files are never categorized as backups solely because their name contains the word "backup".* |
| **Images** | JPG, PNG, WebP, BMP, TIFF photos and media located in WhatsApp image directories. |
| **Videos** | MP4, 3GP, MOV, MKV, AVI video recordings. |
| **Audio** | Music tracks and standard audio files in WhatsApp Audio folders. |
| **Voice Notes** | Push-to-Talk (PTT) recordings and WhatsApp voice clips located in voice-note specific folders. *Categorized specifically as Voice Notes rather than generic audio.* |
| **Documents** | PDF, DOC, DOCX, XLS, XLSX, PPT, TXT, and archive files. |
| **Stickers** | Sticker assets located in WhatsApp Stickers directory (`.webp`). |
| **Animated GIFs**| Looping animations and GIF/MP4 media from WhatsApp Animated Gifs folders. |
| **Thumbnails** | Cached preview images and `.thumbs` files. |
| **Other** | `.nomedia` files, application logs, configuration, and unclassified entries. |

---

## 9. Forensic Integrity & Status Codes

For every acquired file, WRS evaluates SHA-256 integrity and assigns a forensic status:

| Status Code | Meaning |
| :--- | :--- |
| `VERIFIED` | Both source hash (computed on device) and destination hash (computed locally) were obtained and match identically. |
| `SOURCE_HASH_UNAVAILABLE` | Local file hash was successfully computed, but on-device hashing tool (`sha256sum`) was restricted or unavailable on the Android build. Integrity of local file is preserved. |
| `SIZE_MISMATCH` | Local acquired byte size differs from the expected size reported on device. |
| `HASH_MISMATCH` | Source and destination SHA-256 hashes differ. |
| `PARTIAL` | Acquisition was interrupted before completion. |
| `FAILED` | Copy or read error occurred during acquisition. |
| `SKIPPED` | File was excluded by category filter or was previously acquired in a resumed session. |

---

## 10. Reports

Reports are automatically generated inside `reports/`:
- **`report.html`**: Visual, responsive dashboard with category distribution, candidate lists, integrity audit summary, and forensic disclosures. Filenames and paths are strictly escaped to prevent injection.
- **`report.csv`**: Delimited tabular dataset containing one record per file with original path, relative path, local destination, sizes, hashes, and verification statuses.
- **`report.json`**: Machine-readable structured export with complete hardware properties, scan timestamps, and per-file audit entries.

---

## 11. Important Forensic & Android Boundaries

### 1. Internal App Sandbox (`/data/data/com.whatsapp/`)
Standard unrooted ADB communicates exclusively with accessible external and shared storage volumes (`/sdcard/`, `/storage/emulated/0/`). WhatsApp's internal private app directory (`/data/data/com.whatsapp/`) is protected by Android OS sandbox permissions (UID separation and SELinux). It cannot be read without root privileges or physical JTAG/chip-off extractions.

### 2. WhatsApp Cryptographic Keys
Encrypted WhatsApp databases (`.crypt14` and `.crypt15`) use AES-256-GCM encryption. The decryption key is stored inside private storage at:
`/data/data/com.whatsapp/files/key`

WRS acquires and preserves encrypted database backups in their exact byte-for-byte raw format. It does not attempt unauthorized decryption, brute-force key generation, or exploit-based privilege escalation.

### 3. Backup Acquisition vs. Deleted Data Recovery
- **What WRS Does**: Inventories and extracts existing files, dated backups, voice notes, photos, and media remaining in device storage.
- **What WRS Does Not Do**: WRS does not carve unallocated flash blocks or recover deleted chat records that were never saved to a backup. When a WhatsApp account is re-registered on a new phone, local chats on the previous phone remain preserved in backup files until overwritten or deleted by the user.

---

## 12. Troubleshooting

| Issue | Cause & Resolution |
| :--- | :--- |
| **`adb: command not found`** | ADB is not installed. Run `sudo apt install adb`. |
| **Device listed as `unauthorized`** | Unlock your phone screen, locate the "Allow USB debugging?" dialog, check "Always allow", and tap OK. |
| **Device listed as `offline`** | Disconnect and reconnect the USB cable, or run `adb kill-server && adb start-server`. |
| **No devices detected** | Ensure Developer Options and USB Debugging are enabled on phone. Verify USB cable supports data transfer. |
| **`Insufficient disk space` warning** | Free space on your Kali workstation destination filesystem or specify an external drive using `--output`. |

---

## 13. Running Automated Tests

To run the complete automated test suite (31 tests):
```bash
python3 -m pytest -v tests/
```
or with the standard library `unittest`:
```bash
python3 -m unittest discover tests
```

---

## 14. Uninstallation

To remove WRS completely from your workstation:
```bash
rm -rf /path/to/wrs
```
*(No background daemons, systemd services, or persistent system modifications are installed.)*

---

## 15. License

Released under the **MIT License**. See [LICENSE](file:///home/bablu/TOOLS/wrs/LICENSE) for terms.
