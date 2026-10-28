# WRS — WhatsApp Recovery Scanner (v2.0.0)
## Advanced WhatsApp Forensic Acquisition, Backup Analysis & Recovery Workstation

A local-first, forensic-grade acquisition, database analysis, chat reconstruction, and recovery workstation engineered for Android devices via Android Debug Bridge (ADB) on Kali Linux.

---

## 1. Overview & Forensic Architecture

**WRS (WhatsApp Recovery Scanner)** is designed for digital forensics examiners, incident responders, and privacy researchers who need to safely discover, inventory, hash, acquire, analyze, and reconstruct WhatsApp communications from Android devices without modifying or risking evidence on the target phone.

```
                      +-----------------------------+
                      |   Target Android Device     |
                      |  (Standard / Business WA)   |
                      +--------------+--------------+
                                     |  (Read-only ADB)
                                     v
                       +---------------------------+
                       |    Device & Storage       |
                       |       Discovery           |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       |   SQLite Persistent Scan  |
                       |     Inventory Catalog     |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       | Pre-Acquisition Preview   |
                       |  & Scope Recalculation    |
                       +-------------+-------------+
                                     |
                                     v
                       +---------------------------+
                       | Explicit Confirmation     |
                       |  & Forensic Acquisition   |
                       +-------------+-------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
+----------------------+                            +----------------------+
|  Database Analysis   |                            |   Media Validation   |
|  & AES-GCM Decrypt   |                            |   & Association      |
+----------+-----------+                            +----------+-----------+
           |                                                   |
           +-------------------------+-------------------------+
                                     |
                                     v
                       +---------------------------+
                       |    Chat Reconstruction    |
                       |          Engine           |
                       +-------------+-------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
+----------------------+                            +----------------------+
| Multi-Format Exports |                            | Case Audit Logging   |
| (TXT/HTML/JSON/CSV)  |                            | & Verified ZIP Pkg   |
+----------------------+                            +----------------------+
```

### Key Capabilities

1. **100% Local Execution**: Zero cloud APIs, telemetry, external network requests, or third-party processing.
2. **Two-Stage Acquisition Protocol**:
   - *Discovery & Inventory*: Recursively scans accessible WhatsApp storage and builds a persistent SQLite inventory.
   - *Interactive Scope Planning*: Recalculate file counts, sizes, and disk assessments dynamically when selecting categories or excluding duplicate candidates.
   - *Explicit Confirmation*: Files are never pulled without mandatory affirmative confirmation (`[y/N]`, defaulting to No).
3. **Forensic Device Management**:
   - Secure internal device identifier generated from non-secret hardware properties with local salting.
   - Disconnection detection and safe interrupt handling.
4. **Staged Duplicate Content Detection**:
   - Groups files by exact byte size.
   - Eliminates unique sizes and evaluates SHA-256 digests on candidate collisions.
   - Allows excluding redundant duplicate copies while preserving the primary reference.
5. **Modular Database & Backup Inspection**:
   - Read-only SQLite inspection (`PRAGMA integrity_check`, table catalogs).
   - Schema-aware adapters for both classic (`messages`) and modern (`message` / `chat` / `jid`) WhatsApp databases.
   - Crypt14 and Crypt15 detection with user-supplied AES-GCM-256 decryption adapter.
6. **Chat Reconstruction Engine**:
   - Normalizes raw database records into a structured forensic message model (`ReconstructedMessage`).
   - Chronological message sorting, participant resolution, quoted replies, and reaction tracking.
7. **Forensic Media Association**:
   - Correlates message attachments against acquired media using strict evidence levels:
     - `EXACT_DATABASE_REFERENCE`
     - `MATCHED_RELATIVE_PATH`
     - `MATCHED_FILENAME`
     - `UNMATCHED`
8. **Multi-Format Export & ZIP Packaging**:
   - Exports conversation transcripts to **TXT**, **HTML** (with speech bubbles and forensic metadata), **JSON**, and **CSV**.
   - Standard-library `zipfile` packaging with pre-packaging disk check, internal `archive_manifest.json`, `testzip()` integrity verification, and archive SHA-256 hashing.
9. **Case Management & Audit Trail**:
   - Append-only event logging (`case_events.jsonl`) with automatic redaction of sensitive credentials and keys.
   - Historical case comparison detecting identical, newly acquired, deleted, or modified assets across scans.

---

## 2. System Requirements

- **Workstation OS**: Kali Linux 2023+ (or standard Debian / Ubuntu derivatives).
- **Python Runtime**: Python 3.11 or later (tested and validated on Python 3.14).
- **Android Debug Bridge (ADB)**: Android SDK Platform-Tools 1.0.41+.
- **Workstation Storage**: Sufficient free disk space at destination plus a 10% safety margin (minimum 100 MiB free space buffer).

---

## 3. Installation on Kali Linux

### Step 1: Install System Dependencies
```bash
sudo apt update
sudo apt install -y adb python3 python3-pip
```

Verify ADB installation:
```bash
adb version
```

### Step 2: Clone the Repository
```bash
git clone https://github.com/your-repo/wrs.git
cd wrs
```

### Step 3: Install Python Dependencies
```bash
pip install -r requirements.txt --break-system-packages
```
*(Dependencies are strictly minimal: `cryptography`, `rich`, `python-magic`, and `pytest`.)*

---

## 4. Android Device Setup

1. **Enable Developer Options**: Go to **Settings** > **About Phone** and tap **Build Number** 7 times.
2. **Enable USB Debugging**: In **Settings** > **System** > **Developer Options**, enable **USB Debugging**.
3. **Authorize Workstation**:
   - Connect the phone to Kali Linux via a USB data cable.
   - Unlock the phone screen.
   - On the "Allow USB debugging?" pop-up, check **"Always allow from this computer"** and tap **Allow** / **OK**.
4. **Confirm Device Connectivity**:
   ```bash
   adb devices -l
   ```
   *Status must be `device` (not `unauthorized` or `offline`).*

---

## 5. Usage & Commands

### Interactive Menu Mode
Launch the comprehensive terminal workstation:
```bash
python3 wrs.py
```

The menu provides:
```text
[1] Scan Android device and discover WhatsApp data (Inventory Only)
[2] Scan and acquire WhatsApp data
[3] Inspect recovery folder or SQLite database
[4] Verify acquired files and hashes
[5] Reconstruct and export chats from acquired database
[6] Package recovery directory into ZIP archive
[7] View case audit log and past scans
[8] View supported recovery locations and limitations
[9] Exit
```

### Command-Line Scripting & Headless Automation

- **List connected devices:**
  ```bash
  python3 wrs.py --list-devices
  ```

- **Inventory scan without copying files:**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --scan
  ```

- **Scan and acquire with category filter:**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --categories Images,Videos,Databases
  ```

- **Acquire while automatically excluding duplicate copies:**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --exclude-duplicates
  ```

- **Inspect an acquired database or recovery folder:**
  ```bash
  python3 wrs.py --inspect ./recovery/Google_Pixel_7_scan_2026-10-28_10-00-00/Databases/msgstore.db
  ```

- **Inspect and decrypt an encrypted database using user key:**
  ```bash
  python3 wrs.py --inspect ./recovery/.../msgstore.db.crypt14 --key ./whatsapp.key
  ```

- **Reconstruct and export chats from a database to HTML/JSON/CSV:**
  ```bash
  python3 wrs.py --export ./recovery/.../msgstore.db --format all
  ```

- **Package a recovery directory into a verified ZIP archive:**
  ```bash
  python3 wrs.py --export ./recovery/Google_Pixel_7_scan_2026-10-28_10-00-00 --format zip
  ```

- **Verify integrity of an existing recovery folder against its manifest:**
  ```bash
  python3 wrs.py --verify ./recovery/Google_Pixel_7_scan_2026-10-28_10-00-00
  ```

- **Headless unattended acquisition (for forensic scripting):**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --output ./case_01 --unattended
  ```

---

## 6. Pre-Acquisition Preview & Interactive Planning

Before pulling files, WRS calculates exact metrics and presents an interactive planning interface:

```text
========================================================================
  WRS — ACQUISITION PREVIEW
========================================================================
  Scan ID          : scan_28241FDH_20261028_100000_a1b2c3
  Device           : Google Pixel 7
  Serial           : 28241FDH2006G7
  Android Version  : 14 (API 34)
  Scan Date        : 2026-10-28 10:00:00
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
  Duplicate Candidates   : 48 (18.20 MiB redundant)
  Destination Directory  : /home/bablu/TOOLS/wrs/recovery/Google_Pixel_7_scan_2026-10-28_10-00-00
  Storage Assessment     : Disk space OK: 148.50 GiB available. Required: 1.44 GiB + 147.45 MiB safety margin.
========================================================================

Acquisition Selection Options:
  [1] Proceed with current selection
  [2] Select specific categories
  [3] Exclude duplicate candidate files
  [4] Export inventory catalog only
  [5] Cancel
```

---

## 7. Recovery Directory Layout

Each acquisition generates an isolated, collision-safe directory structure:

```text
recovery/
└── Google_Pixel_7_scan_2026-10-28_10-00-00/
    ├── metadata/
    │   ├── device.json                     # Hardware and Android OS properties
    │   ├── scan_inventory.db               # Persistent SQLite scan catalog with indexes
    │   ├── acquisition_manifest.json       # Per-file SHA-256 verification manifest
    │   ├── case_events.jsonl               # Append-only forensic audit trail
    │   └── errors.json                     # Traversal and transfer error logs
    ├── Databases/
    │   ├── msgstore.db.crypt14
    │   └── wa.db
    ├── Backups/
    │   ├── msgstore-2026-10-25.1.db.crypt14
    │   └── msgstore-2026-10-26.1.db.crypt14
    ├── Images/
    ├── Videos/
    ├── Audio/
    ├── Voice_Notes/
    ├── Documents/
    ├── Stickers/
    ├── Animated_GIFs/
    ├── Thumbnails/
    ├── Other/
    ├── chats/                              # Reconstructed chat transcripts
    │   ├── Alice_Smith.txt
    │   ├── Alice_Smith.html
    │   ├── Alice_Smith.json
    │   └── Alice_Smith.csv
    └── reports/
        ├── report.html                     # Standalone visual HTML dashboard
        ├── report.csv                      # RFC-4180 evidence inventory table
        └── report.json                     # Machine-readable case report
```

---

## 8. Forensic File Classification & Integrity Codes

### Classification Categories

| Category | Qualification Criteria |
| :--- | :--- |
| **Databases** | Active WhatsApp SQLite databases (`msgstore.db`, `wa.db`, `chatsettingsbackup.db`) and active encrypted databases (`msgstore.db.crypt14`, `msgstore.db.crypt15`). |
| **Backups** | Dated backup archives matching pattern `msgstore-YYYY-MM-DD.N.db.crypt14/15`. Never classified as backup merely for having "backup" in the filename. |
| **Images** | JPG, PNG, WebP, BMP, TIFF photos in WhatsApp image paths. |
| **Videos** | MP4, 3GP, MOV, MKV, AVI video recordings. |
| **Audio** | Music tracks and standard audio in WhatsApp Audio paths. |
| **Voice Notes** | Push-to-Talk (PTT) recordings and WhatsApp Opus voice notes. |
| **Documents** | PDF, DOC, DOCX, XLS, XLSX, PPT, TXT, and zip archives. |
| **Stickers** | WebP sticker assets in WhatsApp Stickers directory. |
| **Animated GIFs**| GIF/MP4 media from Animated Gifs folders. |
| **Thumbnails** | Cached preview images and `.thumbs` files. |
| **Other** | `.nomedia` files, application logs, configuration, and unclassified entries. |

### Integrity Verification Codes

| Status Code | Meaning |
| :--- | :--- |
| `VERIFIED` | Both source hash (computed on device via ADB stream) and destination hash match identically. |
| `SOURCE_HASH_UNAVAILABLE` | Local file hash was successfully computed, but on-device hashing tool (`sha256sum`) was restricted by Android SELinux. Destination integrity is preserved. |
| `SIZE_MISMATCH` | Local acquired byte size differs from device logical size. |
| `HASH_MISMATCH` | Source and destination SHA-256 digests do not match. |
| `PARTIAL` | Acquisition was interrupted before transfer completed. |
| `FAILED` | Copy or read error occurred during acquisition. |
| `SKIPPED` | File excluded by category filter, duplicate exclusion, or already verified in a resumed session. |

---

## 9. Forensic Boundaries & Limitations

1. **Android App Sandbox**:
   - Standard unrooted ADB accesses shared and external storage volumes (`/sdcard/`, `/storage/emulated/0/`).
   - WhatsApp's private internal storage (`/data/data/com.whatsapp/`) is isolated by Android OS UID separation and cannot be accessed without root privileges or physical chip-off extractions.
2. **Cryptographic Key Handling**:
   - WhatsApp Crypt14/15 backups require the 32-byte AES key located at `/data/data/com.whatsapp/files/key`.
   - WRS preserves encrypted backups in their raw, byte-accurate form and provides an AES-GCM decryption adapter for valid user-supplied key material. WRS does not implement brute-force key cracking, unauthorized privilege escalation, or key theft.
3. **Surviving Data vs. Carving**:
   - WRS recovers existing files, dated backups, databases, and media from device storage.
   - Deleted messages purged prior to backup creation without surviving database remnants cannot be carved from flash memory via standard unrooted ADB.

---

## 10. Automated Test Suite

WRS includes a comprehensive suite of 55 automated unit tests:

```bash
# Run full test suite with pytest
python3 -m pytest -v tests/

# Run with standard library unittest
python3 -m unittest discover tests
```

### Test Coverage Summary:
- `test_acquisition.py`: Preview generation, directory hierarchy, mock ADB pulls, and resumption.
- `test_case.py`: Append-only `case_events.jsonl`, sensitive key redaction, scan IDs, case comparisons.
- `test_categorizer.py`: Pattern detection, dated backups, magic byte sniffing, voice notes, stickers, unicode.
- `test_chat.py`: Message normalization, chronological sorting, group handling, message type mapping.
- `test_cli.py`: Argument parsing, confirmation default-no, banner generation.
- `test_database.py`: Classic v1 and modern v2 SQLite adapters, crypt14/15 detection, AES-GCM decryption.
- `test_device.py`: Device enumeration, property parsing, missing ADB handling.
- `test_discovery.py`: Standard WhatsApp and WhatsApp Business storage discovery, deduplication.
- `test_duplicate.py`: Staged duplicate detection (size grouping -> hash comparison), deduplicated acquisition.
- `test_exporter.py`: TXT, HTML, JSON, CSV chat exports, and validated ZIP packaging with `ZipPackager`.
- `test_hashing.py`: Memory-bounded streaming SHA-256, verification evaluation.
- `test_inventory.py`: `ScanInventoryDB` tables, indexes, batch upsert, status updates, duplicate groups.
- `test_media.py`: Forensic evidence levels (`EXACT_DATABASE_REFERENCE`, `MATCHED_RELATIVE_PATH`, `MATCHED_FILENAME`, `UNMATCHED`).
- `test_reporting.py`: HTML escaping, CSV/JSON report creation, recovery directory verification.
- `test_scanner.py`: ADB shell `find` and fallback enumeration with unicode and spaces.
- `test_validation.py`: Read-only SQLite inspection, path traversal protection, non-SQLite rejection.

---

## 11. License

Released under the **MIT License**. See [LICENSE](file:///home/bablu/TOOLS/wrs/LICENSE) for complete details.
