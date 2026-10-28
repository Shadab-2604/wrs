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
*(Dependencies are strictly minimal: `rich` for professional terminal styling, `python-magic` for MIME sniffing, and `pytest` for test verification.)*

---

## 4. Terminal UI Styling & Design Theme

WRS features a clean, moderately colorful, professional terminal interface tailored for Kali Linux and dark terminal environments. Built like a high-grade forensic utility, it emphasizes readability, clear status hierarchy, and zero clutter or gratuitous animations.

### Color Theme & Semantic Meaning
- **Cyan / Blue**: Main headings, framed banners, menu option numbers, device properties.
- **Green**: Completed operations, verified integrity, authorized Android devices, completed scans (`[SUCCESS]`).
- **Yellow**: Limitations, warnings, encrypted backup candidates, confirmation dialogs (`[WARNING]`).
- **Red**: Critical errors, unauthorized/offline devices, failed operations (`[ERROR]`).
- **Magenta**: Scan activities, analysis modules, recovery/export sections (`[SCAN]`).
- **White / Bright White**: Important values, primary metrics, active category labels.
- **Dim Gray**: Secondary descriptions, metadata timestamps, separators, inactive markers (`[○]`).

### Reusable Status Messages
Operations output standardized, color-coded status prefixes with consistent character alignment:
```text
[SUCCESS] Device authorized and ready.
[INFO]    Scanning accessible shared storage.
[WARNING] Encrypted database detected; readability is not yet verified.
[ERROR]   Device is unauthorized. Approve the debugging prompt on the phone.
[SCAN]    Enumerating accessible storage locations.
[ACQUIRE] [25/100] (25.0%) | Bytes: 10.50 MiB | File: msgstore.db.crypt14 | Status: VERIFIED
```

### Color Accessibility & Graceful Fallback
- **`NO_COLOR` Specification**: Respects the `NO_COLOR` environment variable (https://no-color.org). When set, all ANSI escapes are disabled.
- **Pipe & Redirection Awareness**: Automatically disables terminal escape sequences and cursor rewrites when output is redirected to files or pipes (e.g. `wrs --acquire > acquisition.log`).
- **Terminal Capabilities**: Disables styling automatically on `TERM=dumb`.
- **Command-Line Flag**: Pass `--no-color` to explicitly disable all colors and Rich styling.
- **Graceful Rich Fallback**: If Python `rich` is not installed, WRS operates using clean, standard ASCII borders and tabular text without crashing.

---

## 5. Android Device Setup

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

## 6. Usage & Commands

### CLI Arguments & Options
```bash
python3 wrs.py [OPTIONS]
```

| Argument | Description |
| :--- | :--- |
| `-h`, `--help` | Show complete command options and exit. |
| `--version` | Display installed WRS version. |
| `--list-devices` | List connected Android devices and ADB daemon status, then exit. |
| `--device <SERIAL>` | Target specific device serial when multiple phones are attached. |
| `--scan` | Run discovery and build SQLite inventory without copying files. |
| `--acquire` | Perform scan and acquire verified files to disk. |
| `--output <DIR>` | Custom recovery output directory. |
| `--categories <LIST>` | Filter specific categories (e.g. `Images,Videos,Databases`). |
| `--exclude-duplicates` | Exclude redundant duplicate files during acquisition. |
| `--inspect <PATH>` | Inspect SQLite/crypt database or existing recovery folder. |
| `--verify <DIR>` | Cryptographically verify SHA-256 integrity of recovery directory. |
| `--export <TARGET>` | Reconstruct and export chats from target database. |
| `--format <FMT>` | Chat export format: `all`, `txt`, `html`, `json`, `csv`, `zip`. |
| `--key <KEY_FILE>` | WhatsApp 32-byte encryption key for crypt14/15 decryption. |
| `--unattended`, `--yes`| Run without interactive confirmation prompts (requires `--acquire`). |
| `--dry-run` | Simulate acquisition inventory without writing files. |
| `--no-color` | Disable colored output and terminal styling. |
| `--verbose` | Enable debug logging. |

### Device-Aware Startup Preflight & Terminal Header
When WRS launches, it automatically performs preflight checks and independently queries ADB and connected devices:

```text
╭──────────────────────────────────────────────────────────────╮
│  WRS — WhatsApp Recovery Scanner                             │
│  Local Android Data Discovery & Recovery Assistance          │
╰──────────────────────────────────────────────────────────────╯

  DEVICE       : Google Pixel 8 (CONNECTED AND AUTHORIZED)
  ADB          : AVAILABLE (version 1.0.41)
  SCAN         : READY
  MODE         : 100% Local Execution
  VERSION      : v2.0.0
```

#### Independent Status Separation:
- **ADB Status**: Derived strictly from `adb version`. Accurately reports `AVAILABLE (version X.Y.Z)`, `NOT INSTALLED`, `UNAVAILABLE`, or `ERROR (Command timed out)`. Success of ADB version is never used as proof of device connectivity.
- **Android Device**: Derived strictly from `adb devices -l` enumeration. Accurately reports `NONE DETECTED` (when 0 devices connected), `CONNECTED AND AUTHORIZED`, `UNAUTHORIZED`, `OFFLINE`, or `ENUMERATION FAILED (error)`.
- **Navigation with Zero Devices**: If no phone is attached, WRS displays actionable connection instructions and remains available for offline analysis (inspecting existing recovery directories, verifying cryptographic file hashes, packaging ZIP archives, reviewing databases, and managing settings).
- **Single Source of Truth (`RuntimeStateManager`)**: All values throughout the workstation are tracked with explicit provenance (`CONFIGURED`, `OBSERVED`, `CALCULATED`, `COMPLETED`, `UNAVAILABLE`, `STALE`) ensuring zero fabricated or placeholder data leaks into reports or screens.

When an authorized device is connected in fallback mode:
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

---

## 7. Priority-Based File Discovery & Guided Workflow

WRS enforces a **user-controlled, priority-based, targeted, and permission-aware** discovery and acquisition workflow. **WRS never scans storage automatically at startup**. When launched, it initializes terminal UI, verifies ADB/device status, loads existing scan records, and immediately presents the Main Menu with informational messages:
```text
[INFO] Startup checks completed.
[INFO] No storage scan has been started.
```

The user must explicitly select an option from the menu to start scanning storage.

### Guided Application Flow
```text
                    START WRS
                        |
                        v
              Initialize application
                        |
                        v
              Check ADB & device status
                        |
                        v
              Load previous scan records
                        |
                        v
              [INFO] Startup checks completed.
              [INFO] No storage scan has been started.
                        |
                        v
                 Display MAIN MENU
                        |
                        v
          Select [1] Scan and Recover Data
                        |
                        v
        WRS — SCAN AND RECOVERY WIZARD
        [1] Full Scan
        [2] Targeted Scan
        [3] Scan Known WhatsApp Locations
        [4] Scan Existing WRS Recovery Directories
        [5] Inspect Previous Scan Results
        [0] Back
                        |
                        v
              Execute selected scan
                        |
                        v
           WRS — DISCOVERY SUMMARY
           (Show actual source paths, counts, sizes)
                        |
                        v
           WRS — RECOVERY DESTINATION
           (Press Enter for default destination)
                        |
                        v
        WRS — ACQUISITION CONFIRMATION
        (Review source integrity, destination & counts)
                        |
                        v
             Copy selected files
```
### Scan and Recovery Wizard (Operation Selection)

When the examiner selects `[ 1] Scan and Recover Data` from the Main Menu, WRS displays an interactive operation wizard:

```text
========================================================
       WRS — SCAN AND RECOVERY WIZARD
========================================================

Device       : <actual selected device>
Scan status  : Ready

SELECT AN OPERATION

[1] Full Scan
    Scan prioritized, relevant accessible locations for
    all supported WhatsApp data categories.

[2] Targeted Scan
    Scan only selected locations or data categories.

[3] Scan Known WhatsApp Locations
    Inspect standard WhatsApp database and media paths.

[4] Scan Existing WRS Recovery Directories
    Find previously acquired data and database candidates.

[5] Inspect Previous Scan Results
    Review saved discovery results without rescanning.

[0] Back

Select an operation [0-5]:
```

#### Operation Behaviors:
- **[1] Full Scan**: Prioritized, comprehensive scan of all authorized WhatsApp data locations (Priorities 1 through 6). Before starting, a Scope Summary is displayed and explicit user confirmation (`[y/N]`) is required.
- **[2] Targeted Scan**: Focuses inspection on user-selected targets (WhatsApp Messenger only, WhatsApp Business only, or a custom verified local/Android path). It never expands silently into a full scan.
- **[3] Scan Known WhatsApp Locations**: Focuses specifically on standard WhatsApp database and media paths (Priorities 2, 3, and 4).
- **[4] Scan Existing WRS Recovery Directories**: Discovers previously acquired local evidence and database candidates in the local `./recovery/` directory (Priority 1).
- **[5] Inspect Previous Scan Results**: Loads and reviews the most recent saved `discovery_manifest.json` immediately without rescanning storage.
- **[0] Back**: Returns cleanly to the Main Menu.

### Discovered Locations & Discovery Summary Screen

Following discovery, WRS renders the structured **DISCOVERY SUMMARY** showing verified source paths, categories, file counts, and sizes:

```text
========================================================
       WRS — DISCOVERY SUMMARY
========================================================

Device       : Vivo V2217
Scan status  : Discovery completed
Duration     : 2.15s

DISCOVERED LOCATIONS
--------------------------------------------------------
[1] /sdcard/Android/media/com.whatsapp/WhatsApp/Databases/
    Category : WhatsApp database directory
    Files    : 4
    Size     : 58.20 MiB

[2] /sdcard/Android/media/com.whatsapp/WhatsApp/Media/
    Category : WhatsApp media directory
    Files    : 342
    Size     : 412.50 MiB

--------------------------------------------------------
Total matching files : 346
Total discovered size: 470.70 MiB
--------------------------------------------------------

[1] Review discovered files
[2] Select files or categories to acquire
[3] Acquire selected files
[4] Return to main menu
```

### Recovery Destination Prompt

When the user chooses to acquire discovered files (`[3] Acquire selected files`), WRS displays the dedicated destination prompt before copying:

```text
========================================================
       WRS — RECOVERY DESTINATION
========================================================

Selected device : Vivo V2217
Selected files  : 346
Selected size   : 470.70 MiB

Default recovery destination:
/home/bablu/TOOLS/wrs/recovery/Vivo_V2217/scan_2026-10-28_12-30-00

Enter destination path, or press Enter for the default:
>
```

#### Destination Rules & Safety Controls:
1. **Blank Input Defaults**: Pressing Enter on a blank prompt instantly selects the default recovery directory (`recovery/<device>/scan_<timestamp>/`).
2. **Path Expansion**: Custom paths with `~` are expanded against the user's home directory and resolved to absolute canonical paths.
3. **Safety & Permission Checks**:
   - Prohibits Android device paths (e.g. `/sdcard`, `/storage`) as local recovery destinations.
   - Detects and rejects source/destination overlap to prevent corrupting original files.
   - Verifies filesystem write permissions and disk space availability.
4. **Interactive Retry**: If a path is invalid, an explanatory error is displayed with choices to retry or select the default directory.

### Mandatory Pre-Acquisition Confirmation

Before any files are copied from the target device, WRS displays an explicit confirmation preview:

```text
========================================================
       WRS — ACQUISITION CONFIRMATION
========================================================

Device          : Vivo V2217
Selected files  : 346
Selected size   : 470.70 MiB
Destination     : /home/bablu/TOOLS/wrs/recovery/Vivo_V2217/scan_2026-10-28_12-30-00
Operation       : Copy selected accessible files

Source changes  : None intended

[1] Confirm and start acquisition
[2] Change destination
[3] Change file selection
[0] Cancel

Choose an option:
```

- **Forensic Evidence Protection**: Original device files are strictly accessed in read-only mode and are **never modified, deleted, or moved**.
- **Acquisition Manifest**: Every acquired file is hashed using streaming SHA-256 and cataloged with source path, destination path, and file size in `manifests/acquisition_manifest.json`.

### Discovery Priorities (Order of Execution)

| Priority | Scope | Inspected Locations | Target File Signatures & Assets |
| :---: | :--- | :--- | :--- |
| **Priority 1** | **Existing WRS Results** | `./recovery/`, `database_registry.json`, previous scan catalogs & reports | Validates referenced files on disk. Missing or moved records are marked `stale` / `unavailable`. |
| **Priority 2** | **WhatsApp Databases & Backups** | `/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/`<br>`/sdcard/WhatsApp/Databases/`<br>`/sdcard/Android/media/com.whatsapp/WhatsApp/Backups/` | `msgstore.db`, `msgstore.db.crypt14`, `msgstore.db.crypt15`, `chatsearch.db`, `wa.db`. |
| **Priority 3** | **WhatsApp Media Storage** | `/sdcard/Android/media/com.whatsapp/WhatsApp/Media/`<br>`/sdcard/WhatsApp/Media/` | Enumerate verified subdirectories: `WhatsApp Images`, `WhatsApp Video`, `WhatsApp Audio`, `WhatsApp Voice Notes`, `WhatsApp Documents`, `WhatsApp Stickers`. |
| **Priority 4** | **WhatsApp Business** | `/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/`<br>`/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/` | Discovers WhatsApp Business assets, clearly distinguishing Business data from Standard Messenger. |
| **Priority 5** | **Configured Search Directories** | User-configured directories in `settings.json` (`storage.local_search_paths`) | Local import directories and external backup folders. |
| **Priority 6** | **Optional Extended Discovery** | Removable SD cards (`removable_mounts`), `.trash/`, custom folders | User-approved extended scan. Triggered only upon explicit confirmation (`[y/N]`). |

### Loading Animation & Progress Stages
Discovery displays a live loading animation reflecting real operational stages (with cyan spinner and colored tags when Rich is enabled, and clean plain-text fallback):

```text
[RUNNING] Checking ADB and device authorization...
[RUNNING] Loading existing WRS scan manifests...
[RUNNING] Checking known WhatsApp database locations...
[RUNNING] Discovering WhatsApp media files...
[RUNNING] Validating database candidates...
[RUNNING] Preparing discovery summary...
[SUCCESS] Discovery completed
```

- **Non-Hanging Subprocess Timeouts**: All ADB shell inspection commands use strict 5–10s timeouts to prevent hanging on unresponsive devices.
- **Ctrl+C Safe**: Interrupting discovery cleanly terminates subprocesses, preserves collected records, and marks the manifest as `Cancelled`.

### Discovery Results & Location Summary
After discovery completes, WRS presents a structured summary of locations actually checked and candidates actually found:

```text
========================================================
           WRS — DISCOVERY RESULTS
========================================================

Device       : Google Pixel 8 (TEST_SERIAL_123)
Scan status  : Discovery completed
Duration     : 1.45s

LOCATIONS
--------------------------------------------------------
[1] WRS recovery directory
    Status : Found
    Files  : 4

[2] WhatsApp database directory
    Status : Found
    Files  : 2

[3] WhatsApp media directory
    Status : Found
    Files  : 210
    Subdirs: WhatsApp Images, WhatsApp Video, WhatsApp Documents

[4] WhatsApp Business directory
    Status : Not Applicable (Not installed or not present)
    Files  : N/A

--------------------------------------------------------
Discovered database candidates : 2
Discovered media files         : 210
Unreadable candidates          : 1
Inaccessible locations         : 0
--------------------------------------------------------

DISCOVERED CANDIDATES

DATABASES
  [1] msgstore.db — SQLite / Readable (14,200 msgs) [15-01-2024 to 28-10-2026]
  [2] msgstore.db.crypt14 — CRYPT14 Encrypted Candidate

IMAGES
  150 matching files

VIDEOS
  42 matching files

AUDIO / VOICE NOTES
  0 matching files (checked, none found)

DOCUMENTS
  18 matching files
```

### Discovery Review Menu (Next-Action Choices)
Before entering the main menu, examiners can review and tailor the discovery scope:

```text
Select Next Action:
  [1] Use discovered locations and continue
  [2] Select or deselect specific locations
  [3] Inspect discovered database candidates
  [4] Scan additional accessible locations
  [5] Rescan selected locations
  [0] Exit
```

- **[1] Continue**: Proceeds to the Main Menu with the discovery manifest remembered in session memory.
- **[2] Toggle Locations**: Enables or disables specific discovered directories for subsequent acquisition.
- **[3] Inspect Database Candidates**: Displays forensic properties (path, format, size, message count, encryption status).
- **[4] Extended Discovery**: Prompts for consent and scans secondary/removable storage areas.
- **[5] Rescan**: Re-runs animated discovery across selected locations.
- **[0] Exit**: Safely closes WRS without modifying evidence.

---

### Required Main Menu (Exact 10 Options)

```text
========================================================
       WRS — WHATSAPP RECOVERY SCANNER
========================================================

[ 1] Scan and Recover Data
     Guided discovery, preview & acquisition wizard

[ 2] Select Specific Data Categories
     Filter chat, media, backup & database targets

[ 3] Recover Chat History
     Reconstruct SQLite messages & timeline

[ 4] Recover Media and Attachments
     Acquire pictures, video, audio & docs

[ 5] Inspect Backups and Databases
     Analyze encrypted & unencrypted databases

[ 6] View Available Chat Dates
     Explore calendar spans of message history

[ 7] Export Recovered Data
     Package artifacts into CSV, JSON, HTML or ZIP

[ 8] Verify Existing Recovery Files
     Evaluate cryptographic SHA-256 integrity

[ 9] View Previous Scans
     Browse previous scan sessions & reports

[10] Settings and Help

[ 0] Exit
========================================================

Select an option:
```

### Discovery Result Reuse Across Menu Options
WRS caches discovery results in `recovery/discovery_manifest.json` and session memory:
- **Option [1] (Scan and Recover Data)**: Uses discovered locations in the acquisition wizard and prevents redundant re-discovery.
- **Option [3] (Recover Chat History)**: Automatically detects readable SQLite databases from discovery findings. If only encrypted databases exist, it explains that Crypt14/Crypt15 encryption prevents reading without a key and offers targeted rescan or key import.
- **Option [4] (Recover Media)**: Shows verified counts of discovered media files by category before requesting acquisition confirmation.
- **Option [5] (Inspect Backups and Databases)**: Presents discovered database candidates directly and allows targeted rescan.
- **Option [6] (View Available Chat Dates)**: Directly inspects discovered readable databases and extracts true message timestamps without re-scanning.
- **Option [9] (View Previous Scans)**: Allows browsing discovery manifests alongside acquisition reports.

---

### Bug Fix: Recovery Wizard TypeError (`selected_categories`)
- **Root Cause**: `run_interactive_workflow()` in `src/wrs/cli.py` originally used parameter name `selected_cats`, while callers in `recovery_wizard_flow()` (Option [1] -> Scan Only & Acquire Files) and `recover_media_interactive()` passed keyword argument `selected_categories`. This triggered `TypeError: run_interactive_workflow() got an unexpected keyword argument 'selected_categories'`.
- **Fix**: Added `selected_categories: Optional[Set[str]] = None` to `run_interactive_workflow()`, aliasing `selected_cats = selected_categories if selected_categories is not None and selected_cats is None else selected_cats`.
- **Scan Only Validation**: In `Scan Only` mode (`acquire_mode=False`), WRS executes discovery and inventory without copying or altering source files, accurately filtering the generated inventory and summary report by user-selected categories.

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

### Encrypted Database Candidates, Key-Availability Assessment & Decryption Wizard
**Purpose:** Discovers encrypted WhatsApp database containers (`msgstore.db.crypt14`, dated backups `msgstore-YYYY-MM-DD.1.db.crypt14`, and incremental backups `msgstore-increment-N-YYYY-MM-DD.1.db.crypt14`), checks encryption key availability across authorized local sources, enables safe non-destructive file acquisition, and performs AES-GCM decryption on working copies when prerequisites are met.

Accessible directly from:
- **Option [5] -> [E]**: Encrypted database wizard from Candidate Inspection.
- **Option [3]**: Automatic transition when only encrypted databases are discovered.
- **Option [6]**: Date Explorer decision flow (Case C).

#### 1. Candidate Screen & Key Status Interface:
```text
========================================================
       WRS — ENCRYPTED DATABASE CANDIDATES
========================================================

[1] msgstore.db.crypt14
    Format      : CRYPT14
    Encryption  : Encrypted candidate
    Key status  : Not found in accessible sources
    Validation  : Not yet decrypted

[2] msgstore-2026-10-28.1.db.crypt14
    Format      : CRYPT14
    Encryption  : Encrypted candidate
    Key status  : Required key material available
    Validation  : Decryption readiness not yet verified

--------------------------------------------------------
[1] Inspect selected candidate
[2] Check key availability
[3] Download/copy encrypted files
[4] Decrypt selected candidate (only if ready)
[5] Select multiple candidates
[6] Back
```

#### 2. Key-Availability Status Hierarchy:
WRS maintains honest, verifiable lifecycle states for every discovered candidate:
- `ENCRYPTED — KEY NOT CHECKED`: Candidate discovered; authorized key sources have not yet been queried.
- `ENCRYPTED — KEY NOT FOUND IN ACCESSIBLE SOURCES`: Authorized local sources scanned; matching key not accessible. On unrooted Android devices, the application sandbox boundary (`/data/data/com.whatsapp/files/key`) is clearly documented without falsely asserting the key does not exist.
- `ENCRYPTED — REQUIRED KEY MATERIAL AVAILABLE`: Legitimate, verified key material found in local case directory, adjacent path, or user-supplied file.
- `DECRYPTION READY — FORMAT SUPPORTED`: Container format (`CRYPT14` / `CRYPT15`) is supported and matching verified key is ready.
- `DECRYPTION UNSUPPORTED`: Identified format (e.g., legacy `CRYPT8`, `CRYPT10`, `CRYPT12`) is not supported for automated decryption.
- `DECRYPTION FAILED — SEE DETAILS`: Decryption attempted but failed due to invalid key, damaged ciphertext, or failed SQLite database verification.
- `DECRYPTED — DATABASE VALIDATION PASSED`: Working copy successfully decrypted with AES-GCM-256, decompressed with zlib, and validated via read-only SQLite integrity check (`PRAGMA integrity_check(5)`).

#### 3. Authorized Key Discovery Sources:
WRS inspects only documented, authorized locations:
1. **Adjacent Key Material**: A `key` file residing in the same directory as the encrypted database candidate.
2. **Local Recovery & Case Directories**: Previous legitimate acquisitions in `./recovery/`.
3. **User-Supplied Key Material**: Validated 158-byte WhatsApp key file, 32-byte raw AES key, or 64-character hex string provided by the user.
4. **Android Device Storage (ADB)**: Safe, read-only check of `/data/data/com.whatsapp/files/key` when root shell access is authorized. On standard non-rooted devices, WRS honors Android application sandbox boundaries without attempting unauthorized privilege escalation or brute force.

> [!NOTE]
> **Secret Redaction Policy**: WRS never prints, logs, or exports secret key bytes, raw tokens, or passwords to terminal output, case event logs, or JSON manifests. All references use non-reversible masked identifiers (e.g. `key_158b_...`).

#### 4. Safe Acquisition of Encrypted Databases (Option [3] & [5]):
Users can acquire and preserve encrypted databases for safekeeping even when decryption keys are unavailable:
- **Selection Modes**: Single candidate, multiple candidates (comma-separated or ranges), or all candidates.
- **Recovery Destination Policy**: Defaults on Enter to `<project_root>/recovery/<device_name>/<session>/databases/` (or `recovery/local_import/...` for local imports).
- **Overwrite Protection**: Destination filename collisions are automatically resolved with unique incremental suffixes (e.g., `msgstore_1.db.crypt14`). Original files are never overwritten.
- **Integrity Manifests**: Computes streaming SHA-256 hashes during transfer and generates `acquisition_manifest.json` and SQLite scan inventories.

#### 5. Working Copy Decryption & Database Validation (Option [4]):
- **Working Copy Safeguard**: Decryption is performed strictly on an isolated working copy in `<recovery_dir>/<device>/decrypted/`. Original encrypted source files are never altered or overwritten.
- **Decompression**: WhatsApp Crypt14/15 payloads are compressed with zlib inside the AES-GCM ciphertext; WRS decompresses the stream automatically.
- **Database Validation**: Decrypted output must pass SQLite header verification (`SQLite format 3\x00`) and read-only schema integrity check (`PRAGMA integrity_check(5)`).
- **Post-Decryption Analysis**: Validated databases are registered in `ChatDatabaseRegistry`, immediately unlocking chat timeline discovery, date-range filtering, and HTML/JSON/CSV/TXT export.

---

### Option [6]: View Available Chat Dates (Automatic Discovery & Date Range Explorer)
**Purpose:** Automatically detects, evaluates, and selects readable WhatsApp databases across local directories, persistent registries, and connected Android devices, then parses authentic message timestamps into chronological timelines and calendars.

#### 1. Automatic Database Discovery Priority Order:
When Option [6] (or Option [3]) is selected, WRS automatically searches the following locations without demanding manual path entry:
1. **Persistent Candidate Registry**: `recovery/database_registry.json` containing previously cataloged databases (with automatic detection and flagging of stale, moved, or deleted files).
2. **Acquisition & Recovery Output**: Local `./recovery/` directory and historical extraction folders.
3. **Configured Local Search Paths**: User-selected directories configured in `config/settings.json`.
4. **Connected Android Device External Storage (via ADB)**: Read-only inspection over ADB when a device is connected and authorized.
5. **Common Standard WhatsApp Backup Locations**:
   - `/sdcard/Android/media/com.whatsapp/WhatsApp/Databases/`
   - `/sdcard/WhatsApp/Databases/`
6. **WhatsApp Business Backup Locations**:
   - `/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/`
   - `/sdcard/Android/media/com.whatsapp.w4b/WhatsApp/Databases/`

#### 2. Automatic Selection Decision Flow:
- **Case A: Exactly One Readable Database Exists**
  - Automatically selects the candidate and proceeds immediately to Chat Date Discovery.
  - Confirms candidate filename, source, size, verified message count, and timestamp span.
- **Case B: Multiple Readable Databases Exist**
  - Displays a structured, numbered table displaying filenames, paths, sizes, verified message counts, and available date ranges.
  - Allows selecting any candidate `[1-N]`, choosing the newest valid candidate `[N]` based on verified filesystem metadata (with explicit disclaimer that newer files do not guarantee more complete history), manual import `[M]`, or back `[0]`.
- **Case C: Encrypted Candidates Exist (No Readable Database)**
  - Displays discovered encrypted candidates with format version (`CRYPT14`, `CRYPT15`) and key status.
  - Provides a dedicated 5-action resolution menu:
    ```text
    [1] Inspect database metadata
    [2] Check for supported decryption material
    [3] Scan additional accessible locations
    [4] Select an existing local database or backup
    [5] Back
    ```
- **Case D: No Database Candidates Discovered**
  - Executes a discovery pass across all configured and device paths before reporting the result.
  - Diagnoses and clearly distinguishes:
    - ADB executable not found / unavailable
    - Device disconnected
    - Device unauthorized (screen lock prompt required)
    - Device offline (unstable USB cable)
    - Android storage permission denied or inaccessible
  - Offers next actions: `[1] Rescan accessible locations`, `[2] Import or select a database manually`, `[0] Back`.

#### 3. Chat Date Discovery & Timeline Interface:
Once a readable database is selected, WRS opens it in read-only mode (`mode=ro`), parses message timestamps from `message` or `messages` tables, and displays:

```text
========================================================
              WRS — CHAT DATE DISCOVERY
========================================================

Database     : msgstore.db
Source       : Previously acquired database
Status       : Readable
Messages     : 4,821
Oldest date  : 14-03-2022 09:15
Newest date  : 28-10-2026 11:30

[1] View all available dates
[2] Select a custom date range
[3] Select conversations
[4] Export selected readable messages
[5] Rescan for other databases
[0] Back
```

#### 4. Date-Range Filtering (Inclusive & Strictly Validated):
- Under `[2] Select a custom date range`, user enters:
  - `Start date (DD-MM-YYYY): `
  - `End date   (DD-MM-YYYY): `
- Rigorously validated:
  - Format must be `DD-MM-YYYY`.
  - Rejects impossible calendar dates (e.g. 31-02-2024 or month > 12).
  - Rejects end dates preceding start dates.
  - Expands boundaries to inclusive intervals (`00:00:00.000` of start date to `23:59:59.999` of end date).
  - Filters message records matching the exact interval and exports to HTML, JSON, TXT, and CSV.

#### 5. Supported Formats & Decryption Limitations:
- **Directly Supported Readable Formats**: Unencrypted SQLite databases matching modern (`message`) or classic (`messages`) WhatsApp schemas.
- **Supported Encrypted Formats (with legitimate key material)**: WhatsApp Crypt14 and Crypt15 AES-GCM-256 databases (`msgstore.db.crypt14`, `msgstore.db.crypt15`) using a legitimate 158-byte WhatsApp key file (or 32-byte raw key for Crypt15).
- **Unsupported Formats / Known Limitations**:
  - Legacy Crypt8, Crypt10, and Crypt12 files: Can be identified and cataloged, but automated decryption is unsupported without legacy custom key-derivation material.
  - Private App Storage on Non-Rooted Devices: WhatsApp private databases at `/data/data/com.whatsapp/databases/` are protected by Android SELinux and sandbox permissions. WRS operates 100% safely and non-destructively; it does not attempt device rooting, exploits, or silent modifications. Private databases must be acquired via ADB backup or root access prior to analysis.
  - Zero Data Fabrication: Dates, message counts, and recovery states are never invented. If a database contains corrupted or zero timestamped messages, WRS explicitly explains why dates cannot be determined.

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
wrs/
├── wrs.py
├── src/
├── reports/
└── recovery/
    └── Vivo_V2217/
        └── scan_2026-10-28_12-30-00/
            ├── images/
            ├── videos/
            ├── audio/
            ├── documents/
            ├── databases/
            │   ├── msgstore.db.crypt14
            │   └── wa.db
            ├── chat_exports/
            │   ├── Alice_Smith.txt
            │   └── Alice_Smith.html
            ├── manifests/
            │   └── acquisition_manifest.json   # Cryptographic SHA-256 verification manifest
            ├── metadata/
            │   ├── device.json                 # Hardware & Android OS properties
            │   └── scan_inventory.db           # Persistent SQLite scan inventory
            └── logs/
                ├── case_events.jsonl           # Append-only audit log
                └── errors.json                 # Traversal / transfer errors

### Directory Requirements & Safety
- **Actual Device Name**: Directories are created under the detected device name (e.g. `Vivo_V2217`).
- **Device Name Sanitization**: Replaces spaces, slashes, and control characters with underscores to prevent path traversal.
- **Offline / Local Mode**: When no device is attached and local data is analyzed, `recovery/local_import/` is used instead of a fabricated device name.
- **Collision Safe / Zero Overwrite**: A new timestamped directory is created for each acquisition session (`scan_YYYY-MM-DD_HH-MM-SS`). If a directory already exists, a unique counter suffix (`_1`, `_2`) is appended. Existing sessions and original source files are **never overwritten**.
- **Segregated Structure**: Manifests and logs are kept in dedicated `manifests/` and `logs/` directories, completely separate from acquired evidence files.
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

WRS includes a comprehensive suite of **126 automated unit tests** (100% passing):

```bash
# Run full test suite with pytest
python3 -m pytest -v tests/

# Run with standard library unittest
python3 -m unittest discover tests
```

### Test Coverage Summary:
- `test_ui.py` *(UI Enhancement)*: Validates terminal color policy (`NO_COLOR`, `TERM=dumb`, non-tty streams, `--no-color` CLI flag), reusable status formatting helpers (`[SUCCESS]`, `[INFO]`, `[WARNING]`, `[ERROR]`, `[SCAN]`, `[ACQUIRE]`), category selection active markers (`[●]` vs `[○]`), Rich structured tables and fallback, styled confirmation panels, and periodic non-tty progress callbacks without carriage return overwrites.
- `test_recovery_wizard.py` *(Phase 4)*: Category parsing (all, comma-separated e.g. `2,4,7`, `A`, `C`, `0`, `B`), storage category translation, real calendar date validation (rejecting `31-02-2024`, end < start, outside range, partial overlaps, inclusive boundaries), timeline extraction, available-date calendar counts, specific-date filtering, multiple conversation filtering, timezone-aware timestamp conversion, and multi-format chat exports.
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
