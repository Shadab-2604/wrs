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

### Device-Aware Startup Preflight & Terminal Header
When WRS launches, it automatically performs preflight checks and independently queries ADB and connected devices:

```text
╭────────────────── WRS — WhatsApp Recovery Scanner ──────────────────╮
│ Processing Mode : 100% Local Execution                              │
│ ADB Status      : AVAILABLE (version 1.0.41)                         │
│ Android Device  : NONE DETECTED                                     │
│ Version         : v2.0.0                                            │
│ Timestamp       : 2026-10-28 10:15:30                               │
╰──────────── Forensic Acquisition & Preservation Utility ────────────╯
```

#### Independent Status Separation:
- **ADB Status**: Derived strictly from `adb version`. Accurately reports `AVAILABLE (version X.Y.Z)`, `NOT INSTALLED`, `UNAVAILABLE`, or `ERROR (Command timed out)`. Success of ADB version is never used as proof of device connectivity.
- **Android Device**: Derived strictly from `adb devices -l` enumeration. Accurately reports `NONE DETECTED` (when 0 devices connected), `CONNECTED AND AUTHORIZED`, `UNAUTHORIZED`, `OFFLINE`, or `ENUMERATION FAILED (error)`.
- **Navigation with Zero Devices**: If no phone is attached, WRS displays actionable connection instructions and remains available for offline analysis (inspecting existing recovery directories, verifying cryptographic file hashes, packaging ZIP archives, reviewing databases, and managing settings).
- **Single Source of Truth (`RuntimeStateManager`)**: All values throughout the workstation are tracked with explicit provenance (`CONFIGURED`, `OBSERVED`, `CALCULATED`, `COMPLETED`, `UNAVAILABLE`, `STALE`) ensuring zero fabricated or placeholder data leaks into reports or screens.

When an authorized device is connected:
```text
==============================================================
          WRS — WHATSAPP RECOVERY SCANNER
==============================================================
Environment       : Kali GNU/Linux Rolling
ADB Status        : AVAILABLE (version 1.0.41)
Connected Devices : 1
Current Time      : 2026-10-28 10:15:30

CONNECTED ANDROID DEVICES
--------------------------------------------------------------
[1] Device Name : Google Pixel 7
    Model       : Pixel 7
    Manufacturer: Google
    Android     : 14
    Device ID   : 2824****06G7
    Status      : CONNECTED / AUTHORIZED
--------------------------------------------------------------
Selected Device  : Google Pixel 7
==============================================================
```

### 10-Option Main Menu (Phase 4)

```text
========================================================
       WRS — WHATSAPP RECOVERY SCANNER
========================================================

Selected Device : Google Pixel 7 (2824****06G7)
ADB Status      : AVAILABLE (version 1.0.41)
Scan Status     : READY

MAIN MENU

[1] Scan and Recover Data
[2] Select Specific Data Categories
[3] Recover Chat History
[4] Recover Media and Attachments
[5] Inspect Backups and Databases
[6] View Available Chat Dates
[7] Export Recovered Data
[8] Verify Existing Recovery Files
[9] View Previous Scans
[10] Settings and Help
[0] Exit

Select an option:
```

---

## 6. Comprehensive Option Guide & Workflows

### Option [1]: Scan and Recover Data (Recovery Operation Selection Wizard)
**Purpose:** Central entry point to the complete Phase 4 Recovery Selection Wizard. Guides the examiner through selecting the exact operation type to perform:

```text
========================================================
       WRS — RECOVERY OPERATION SELECTION
========================================================
Selected Device : Google Pixel 7
Categories      : All Supported Data

SELECT OPERATION

[1] Scan Only
    Discover data and calculate counts and sizes.

[2] Acquire Files
    Copy selected accessible files to the recovery directory.

[3] Analyze Chat Databases
    Inspect supported readable databases and backup candidates.

[4] Export Readable Chats
    Export supported, actually available chat records.

[5] Export Selected Media
    Export selected media files and their metadata.

[6] Prepare Native WhatsApp Restore
    Validate supported backup candidates and guide the user
    through an applicable native WhatsApp restoration process.

[7] Verify Acquired Data
    Verify existing acquired files and their integrity.

[0] Back
```

- **Scan Only**: Discovers accessible storage, categorizes assets, counts files, and calculates sizes without copying files or modifying device data.
- **Acquire Files**: Executes evidence acquisition for selected categories after presenting a detailed pre-acquisition preview and requiring affirmative confirmation.
- **Analyze Chat Databases**: In-depth inspection of SQLite databases and crypt14/15 backup containers.
- **Export Readable Chats**: Date-range filtered chat export to HTML, JSON, TXT, CSV, and ZIP.
- **Export Selected Media**: Dedicated media acquisition for selected image, video, audio, voice note, or document categories.
- **Prepare Native WhatsApp Restore**: Forensic restoration assistant staging validated backup containers and deploying via ADB with strict collision safeguards.
- **Verify Acquired Data**: Cryptographic integrity verification of acquired folders.

---

### Option [2]: Select Specific Data Categories
**Purpose:** Dedicated category selection screen supporting individual categories, multi-category combinations, and fast shortcuts:

```text
========================================================
       WRS — SELECT DATA CATEGORIES
========================================================
Current Selection : All Supported Data

[1] All Supported Data
[2] Chat History
[3] Photos and Images
[4] Videos
[5] Audio Files
[6] Voice Notes
[7] Documents and Files
[8] Stickers
[9] GIFs and Animated Media
[10] Thumbnails
[11] Databases and Backups
[12] Other Supported Files

Enter multiple options separated by commas.
Example: 2,4,7

[A] Select All
[C] Clear Selection
[0] Back

Your selection: 2,4,7
```

**Selection Rules & Validation:**
- Selecting `1`, `A`, or `ALL` selects all 11 supported data categories.
- Selecting multiple options combines categories without duplication (e.g. `2,4,7,4` normalizes to `Chat History, Videos, Documents and Files`).
- Selecting `C` clears the selection; `0` returns without changing current settings.
- Invalid tokens or numbers outside 1–12 produce clear actionable error messages.

---

### Option [3]: Recover Chat History & Date-Range Engine
**Purpose:** Discovers chat history availability, extracts chronological message timestamps from oldest to most recent, validates user-entered `DD-MM-YYYY` date ranges, filters conversations, optionally associates referenced media, and exports transcripts.

#### Step 1: Chat History Availability Discovery
If no readable database has been established:
```text
========================================================
       CHAT HISTORY STATUS
========================================================
No readable chat source has been established.

Possible reasons:
- No database or backup was found in accessible locations.
- The available database is encrypted and cannot currently be processed.
- The source format is unsupported.
- The available files contain media but no readable messages.

No chat records have been reconstructed.

Next actions:
[1] Scan additional accessible locations
[2] Inspect discovered database candidates
[3] Import an existing supported chat export
[0] Back
```

#### Step 2: Oldest-to-Most-Recent Chat Timeline
When a supported database is parsed:
```text
========================================================
       AVAILABLE CHAT HISTORY
========================================================
Oldest Available Message : 14-03-2022 09:17
Most Recent Message      : 26-10-2026 21:43

Readable Messages        : 2,840
Conversations            : 14
Missing Timestamps       : 3

Choose History Range

[1] All Available History
[2] Custom Date Range
[3] Select One Conversation
[4] Select Multiple Conversations
[0] Back
```

#### Step 3: Custom Date-Range Selection (`DD-MM-YYYY`)
- Validates real calendar dates (rejects impossible dates like `31-02-2024`).
- Rejects end dates earlier than start dates.
- Detects ranges entirely outside available history and reports boundaries.
- Detects partial overlaps and prompts examiner to accept adjusted boundaries.
- Inclusive day boundaries: `Start 00:00:00.000000` to `End 23:59:59.999999`.

#### Step 4: Distinguish Chat Records from Chat-Related Media
Prompts:
```text
Include media referenced by selected chats? [y/N]: y
```
When enabled, only media files linked to selected messages through evidence (`EXACT_DATABASE_REFERENCE` or `MATCHED_RELATIVE_PATH`) are included.

#### Step 5: Acquisition & Export Preview (Section 12)
```text
========================================================
       RECOVERY SELECTION PREVIEW
========================================================
Device               : Google Pixel 7
Operation            : Export Readable Chats
Categories           : Chat History + Associated Media

Chat Source           : msgstore.db (Reconstructed)
Oldest Available Date : 14-03-2022 09:17
Newest Available Date : 26-10-2026 21:43

Requested Range       : 01-01-2024 to 31-12-2024
Selected Conversations: 8
Selected Messages     : 1,420
Selected Files        : 84 media files
Total Selected Size   : 45.20 MiB

Unreadable Records    : 0
Missing Timestamps    : 3
Unmatched Media       : 0

Destination           : recovery/chat_export_2026-10-28_10-30-00
========================================================
```

#### Step 6: Explicit Confirmation (Section 13)
```text
You are about to export selected chat records.

Conversations : 8
Messages      : 1,420
Date Range    : 01-01-2024 to 31-12-2024
Output Format : TXT, HTML, JSON, and ZIP archive
Destination   : recovery/chat_export_2026-10-28_10-30-00

Proceed? [y/N]: y
```
*Note: Exporting chats to HTML/JSON/ZIP creates forensic archives but does NOT restore chats inside the WhatsApp app.*

---

### Option [4]: Recover Media and Attachments
**Purpose:** Dedicated media acquisition workflow. Separates media recovery from chat recovery, allowing examiners to acquire photos, videos, voice notes, audio, stickers, and documents without requiring active chat databases.

---

### Option [5]: Inspect Backups and Databases (Recovery Assistant)
**Purpose:** Scans accessible Android WhatsApp storage and existing WRS acquisition folders for database and backup candidates using `RestoreAssistant`.

```text
========================================================================================
  WRS — INSPECT BACKUPS & DATABASES
========================================================================================
Found 3 candidate artifact(s):

  #    FILENAME                         SIZE        FORMAT     STATUS       LOCATION        
  ----------------------------------------------------------------------------------------
  [1]  msgstore-2026-10-26.1.db.crypt14 41.90 MiB   CRYPT14    RESTORABLE   LOCAL_ACQUISITION
  [2]  msgstore.db                      12.80 MiB   SQLITE     PARSEABLE    LOCAL_ACQUISITION
  [3]  empty_file.db.crypt14            0 B         EMPTY      UNSUPPORTED  LOCAL_ACQUISITION
```

#### Forensic Rules & Provenance:
1. **Never Classify by Filename Alone**: A file named `msgstore.db.crypt14` that is 0-bytes or has an invalid header is classified as `UNSUPPORTED`.
2. **Lifecycle States**:
   - `DISCOVERED`: Discovered on device or directory.
   - `ACQUIRED`: Safely preserved in local recovery case.
   - `VALIDATED`: Cryptographic SHA-256 hash verified.
   - `PARSEABLE`: Unencrypted SQLite database readable by chat parser.
   - `RESTORABLE`: Valid Crypt14/15 container suitable for native WhatsApp restore.
   - `UNSUPPORTED`: Zero-byte, corrupted, or unrecognized format.
3. **Source Categorization**:
   - `LOCAL_BACKUP`: Encrypted WhatsApp backup container with valid headers.
   - `SUPPORTED_READABLE_DATABASE`: Unencrypted SQLite database.
   - `MEDIA_ONLY_COLLECTION`: Collection containing media files but no databases.
   - `UNSUPPORTED_ARTIFACT`: Unrecognized or corrupted candidate.

---

### Option [6]: View Available Chat Dates (Calendar Mode)
**Purpose:** Chronological calendar listing every date for which actual readable message records exist, with message counts per day:

```text
========================================================
       WRS — VIEW AVAILABLE CHAT DATES
========================================================

AVAILABLE MESSAGE DATES

[1]  14-03-2022  | 145 messages
[2]  15-03-2022  | 89 messages
[3]  19-03-2022  | 210 messages
[4]  02-04-2022  | 54 messages
...

Date Selection Options:
  [A]     Select All Available Dates
  [1-N]   Specific Date(s) (comma-separated, e.g. 1,3,5)
  [0]     Back
```

Derives dates strictly from message timestamps, never filesystem metadata.

---

### Option [7]: Export Recovered Data
**Purpose:** Reconstructs and exports chat records to HTML, JSON, CSV, and TXT, or packages existing recovery cases into verified ZIP archives with internal checksums.

---

### Option [8]: Verify Existing Recovery Files
**Purpose:** Post-acquisition cryptographic audit. Verifies all files in a recovery directory against `acquisition_manifest.json` SHA-256 digests.

---

### Option [9]: View Previous Scans
**Purpose:** Catalogs and reviews historical scan cases in `./recovery/`, displaying scan date, folder size, file count, and database candidates.

---

### Option [10]: Settings and Help
**Purpose:** Persistent configuration editor (`config/settings.json`), plus comprehensive guides for:
- Supported storage locations and forensic boundaries.
- Native WhatsApp restoration prerequisites and rollback safeguards.

---

### Option [0]: Exit
Cleanly terminates the application session.

---

## 7. Native WhatsApp Restore Assistant & Rollback Safeguards

For supported local backups (`LOCAL_BACKUP`), WRS includes a guided, non-destructive restoration workflow:

### Restoration Prerequisites:
1. **Same Phone Number**: The phone must register with the same phone number associated with the backup.
2. **Fresh WhatsApp Setup**: WhatsApp must be freshly installed or cleared, and **NOT yet registered or verified**.
3. **Pre-registration Placement**: The backup file (`msgstore.db.crypt14` or `msgstore.db.crypt15`) must be placed in `/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/` **BEFORE** opening WhatsApp.
4. **Storage Permissions**: Android must grant Storage / "All Files Access" permissions to WhatsApp before launching setup.
5. **Skip Google Drive**: When WhatsApp setup prompts for Google Drive backups, choose **Skip** so it falls back to the local database.
6. **Offline Precaution**: Enable Airplane mode during setup if Google Drive attempts to overwrite with empty cloud data.

### Mandatory Safety & Rollback Rules:
- **No Automatic App Modification**: WRS **never** uninstalls WhatsApp, clears application data, or registers phone numbers automatically.
- **Affirmative Confirmation**: WRS **never** writes files to an Android device without explicit affirmative user confirmation (`[y/N]`, defaulting to No).
- **Device Collision Refusal**: If `msgstore.db.crypt14` already exists on the Android device, WRS **refuses** to push and halts with an actionable collision error to prevent accidental evidence destruction.
- **Evidence Preservation**: The original candidate file is never moved or modified; staging creates a verified copy in `recovery/staged_restore_<timestamp>/` with an accompanying `restoration_manifest.json`.

### Post-Restoration Verification Checklist:
```text
=================================================================
  POST-RESTORATION VERIFICATION CHECKLIST
=================================================================
  [ ] 1. Open WhatsApp and confirm chat threads and contacts appear.
  [ ] 2. Check the date of the most recent message to verify the backup date matches.
  [ ] 3. Open a key conversation and scroll up to verify message history and media placeholders.
  [ ] 4. Verify group memberships and participant identifiers have loaded correctly.
  [ ] 5. If media files were also acquired, verify photos and voice notes resolve in WhatsApp.
=================================================================
```

---

## 7. Command-Line Scripting & Headless Automation

WRS supports full non-interactive command-line execution for automated forensic pipelines:

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

- **Dry-run inventory simulation (zero files copied or modified):**
  ```bash
  python3 wrs.py --device SERIAL_NUMBER --acquire --dry-run
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

WRS includes a comprehensive suite of **113 automated unit tests** (100% passing):

```bash
# Run full test suite with pytest
python3 -m pytest -v tests/

# Run with standard library unittest
python3 -m unittest discover tests
```

### Test Coverage Summary:
- `test_recovery_wizard.py` *(Phase 4)*: Category parsing (all, comma-separated e.g. `2,4,7`, `A`, `C`, `0`), storage category translation, real calendar date validation (rejecting `31-02-2024`, end < start, outside range, partial overlaps, inclusive boundaries), timeline extraction, available-date calendar counts, specific-date filtering, multiple conversation filtering, timezone-aware timestamp conversion, and multi-format chat exports.
- `test_restore_assistant.py` *(Phase 4)*: Restoration candidate scanning (local and remote), forensic provenance tracking, source assessment (`LOCAL_BACKUP`, `SUPPORTED_READABLE_DATABASE`, `MEDIA_ONLY_COLLECTION`, `UNSUPPORTED_ARTIFACT`), prohibition against classifying encrypted DB as restorable solely from filename, staging preparation with manifest, staging collision detection, device destination collision refusal, affirmative confirmation requirement, and verification checklist.
- `test_device_status_authenticity.py`: Authentic status separation (`AVAILABLE` vs `NONE DETECTED`), daemon noise filtering, offline/unauthorized device property query suppression, multiple device selection enforcement, hotplug disconnection handling, and runtime state provenance (`RuntimeStateManager`).
- `test_device_ux.py`: Device detection, single/multiple device selection, unauthorized/offline/disconnected states, fallback naming, Unicode handling, serial masking, transfer disconnection safety.
- `test_cli_ux.py`: Persistent screen headers, confirmation prompts, recovery folder naming, plain-text progress fallback, dry-run mode, and persistent configuration.
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
