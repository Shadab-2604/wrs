"""Single-page HTML recovery viewer backend server for WRS.

Runs a lightweight, local-only HTTP server bound strictly to 127.0.0.1.
Provides REST APIs for file indexing, metadata inspection, media streaming with Range support,
safe text/pdf previews, individual file downloads, and atomic ZIP archive packaging.
"""

from __future__ import annotations

import html
import json
import logging
import mimetypes
import os
import re
import socket
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import zipfile
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .database import WhatsAppDatabaseAnalyzer
from .db_discovery import ChatDatabaseRegistry, inspect_sqlite_chat_dates
from .device import AdbExecutor, DeviceInfo
from .hashing import hash_local_file
from .utils import check_disk_space, format_bytes, format_timestamp, sanitize_filename

logger = logging.getLogger("wrs.server")


@dataclass
class ViewerFileItem:
    """Indexed file item exposed to the HTML recovery viewer."""

    id: str
    filename: str
    category: str
    size_bytes: int
    size_human: str
    source_location: str
    local_path: Optional[str]
    device_path: Optional[str]
    acquisition_status: str  # DISCOVERED, ACQUIRED, VERIFIED, FAILED
    verification_status: str  # VERIFIED, UNVERIFIED, FAILED
    sha256: Optional[str]
    is_accessible: bool
    is_previewable: bool
    preview_type: str  # image, audio, video, text, pdf, database, unsupported
    mime_type: str
    modified_time: Optional[str]
    is_encrypted: bool
    is_sqlite: bool
    db_metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to client-safe dictionary."""
        d = asdict(self)
        # Ensure we do not expose raw server absolute paths if not needed
        d["has_local_file"] = bool(self.local_path and Path(self.local_path).is_file())
        return d


@dataclass
class ViewerSession:
    """Metadata and inventory for an inspected recovery or discovery session."""

    session_id: str
    session_name: str
    session_dir: Optional[str]
    device_name: str
    device_serial: str
    device_status: str
    timestamp: str
    total_discovered: int = 0
    total_accessible: int = 0
    total_acquired: int = 0
    total_verified: int = 0
    total_size_bytes: int = 0
    total_size_human: str = "0 B"
    files: List[ViewerFileItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session overview to dictionary."""
        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "session_dir": self.session_dir,
            "device_name": self.device_name,
            "device_serial": self.device_serial,
            "device_status": self.device_status,
            "timestamp": self.timestamp,
            "total_discovered": self.total_discovered,
            "total_accessible": self.total_accessible,
            "total_acquired": self.total_acquired,
            "total_verified": self.total_verified,
            "total_size_bytes": self.total_size_bytes,
            "total_size_human": self.total_size_human,
            "file_count": len(self.files),
        }


def classify_preview_type(filename: str, mime: str) -> str:
    """Determine preview mechanism for a given file."""
    fn = filename.lower()
    if any(fn.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp")):
        return "image"
    if any(fn.endswith(ext) for ext in (".mp3", ".ogg", ".opus", ".wav", ".m4a", ".aac")):
        return "audio"
    if any(fn.endswith(ext) for ext in (".mp4", ".3gp", ".mkv", ".webm", ".mov")):
        return "video"
    if fn.endswith(".pdf"):
        return "pdf"
    if any(fn.endswith(ext) for ext in (".txt", ".csv", ".json", ".log", ".md", ".xml", ".html")):
        return "text"
    if any(fn.endswith(ext) for ext in (".crypt14", ".crypt15", ".crypt12", ".crypt8", ".db", ".sqlite")):
        return "database"
    if mime.startswith("image/"):
        return "image"
    if mime.startswith("audio/"):
        return "audio"
    if mime.startswith("video/"):
        return "video"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("text/"):
        return "text"
    return "unsupported"


def detect_mime(filepath: Path) -> str:
    """Safely detect MIME type using mimetypes or extension fallback."""
    fn = filepath.name.lower()
    if fn.endswith(".opus"):
        return "audio/ogg; codecs=opus"
    if fn.endswith(".crypt14") or fn.endswith(".crypt15"):
        return "application/x-whatsapp-crypt"
    if fn.endswith(".db"):
        return "application/x-sqlite3"

    m, _ = mimetypes.guess_type(str(filepath))
    return m or "application/octet-stream"


class RecoveryViewerServer(ThreadingHTTPServer):
    """Local-only multi-threaded HTTP server for WRS Recovery Viewer."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        recovery_root: Path,
        executor: Optional[AdbExecutor] = None,
        settings: Optional[Dict[str, Any]] = None,
        device: Optional[DeviceInfo] = None,
        discovery_manifest: Optional[Any] = None,
    ) -> None:
        super().__init__(server_address, RecoveryViewerRequestHandler)
        self.recovery_root = Path(recovery_root).resolve()
        self.executor = executor or AdbExecutor()
        self.settings = settings or {}
        self.device = device
        self.discovery_manifest = discovery_manifest
        self.staging_dir = self.recovery_root / ".staging"
        self.staging_dir.mkdir(parents=True, exist_ok=True)

        self.project_root = Path(__file__).resolve().parent.parent.parent
        self.templates_dir = self.project_root / "templates"
        self.static_dir = self.project_root / "static"

        # Inventory and Session State
        self.sessions: Dict[str, ViewerSession] = {}
        self.active_session_id: str = ""
        self.file_index: Dict[str, ViewerFileItem] = {}
        self._lock = threading.Lock()

        # Build initial catalog
        self.refresh_catalog()

    def refresh_catalog(self) -> None:
        """Scan recovery directory and manifests to index all sessions and files."""
        with self._lock:
            self.sessions.clear()
            self.file_index.clear()

            # 1. Inspect local recovery directory for sessions
            if self.recovery_root.is_dir():
                for dev_p in self.recovery_root.iterdir():
                    if not dev_p.is_dir() or dev_p.name.startswith("."):
                        continue
                    for sess_p in dev_p.iterdir():
                        if not sess_p.is_dir() or sess_p.name.startswith("."):
                            continue
                        session = self._index_session_directory(sess_p, dev_p.name)
                        if session:
                            self.sessions[session.session_id] = session

            # 2. If discovery manifest exists from current runtime scan, index it
            if self.discovery_manifest:
                live_sess = self._index_discovery_manifest(self.discovery_manifest)
                if live_sess:
                    self.sessions[live_sess.session_id] = live_sess

            # 3. If no session found, create default empty session
            if not self.sessions:
                empty_sess = ViewerSession(
                    session_id="empty_session",
                    session_name="No Scanned Data Available",
                    session_dir=None,
                    device_name=self.device.display_name if self.device else "No Connected Device",
                    device_serial=self.device.serial if self.device else "N/A",
                    device_status=self.device.state if self.device else "Disconnected",
                    timestamp=format_timestamp(),
                    total_discovered=0,
                    total_accessible=0,
                    total_acquired=0,
                    total_verified=0,
                    total_size_bytes=0,
                    total_size_human="0 B",
                    files=[],
                )
                self.sessions["empty_session"] = empty_sess

            # Set active session
            if not self.active_session_id or self.active_session_id not in self.sessions:
                self.active_session_id = next(iter(self.sessions.keys()))

            # Populate fast file index for active session
            self._update_file_index()

    def set_active_session(self, session_id: str) -> bool:
        """Switch active session."""
        with self._lock:
            if session_id in self.sessions:
                self.active_session_id = session_id
                self._update_file_index()
                return True
            return False

    def get_active_session(self) -> ViewerSession:
        """Return currently active session."""
        with self._lock:
            return self.sessions.get(self.active_session_id, next(iter(self.sessions.values())))

    def _update_file_index(self) -> None:
        """Map file IDs to FileItems for the active session."""
        self.file_index.clear()
        sess = self.sessions.get(self.active_session_id)
        if sess:
            for f in sess.files:
                self.file_index[f.id] = f

    def _index_session_directory(self, session_p: Path, device_folder: str) -> Optional[ViewerSession]:
        """Index a physical recovery session folder on disk."""
        session_id = f"{device_folder}_{session_p.name}"
        files: List[ViewerFileItem] = []
        file_counter = 1

        # Check for acquisition manifest
        manifest_map: Dict[str, dict] = {}
        for man_sub in ("manifests", "metadata"):
            man_file = session_p / man_sub / "acquisition_manifest.json"
            if man_file.is_file():
                try:
                    with open(man_file, "r", encoding="utf-8") as f:
                        for entry in json.load(f):
                            manifest_map[entry.get("destination_path", "")] = entry
                            manifest_map[Path(entry.get("destination_path", "")).name] = entry
                except Exception:
                    pass

        # Database registry for metadata
        reg_map: Dict[str, dict] = {}
        reg_file = self.recovery_root / "database_registry.json"
        if reg_file.is_file():
            try:
                with open(reg_file, "r", encoding="utf-8") as f:
                    for entry in json.load(f):
                        reg_map[entry.get("filename", "")] = entry
                        reg_map[entry.get("path", "")] = entry
            except Exception:
                pass

        # Scan subdirectories
        cat_map = {
            "images": "Images",
            "videos": "Videos",
            "audio": "Audio",
            "voice_notes": "Audio",
            "documents": "Documents",
            "databases": "Databases",
            "decrypted": "Databases",
        }

        total_bytes = 0
        total_acquired = 0
        total_verified = 0

        for sub, cat in cat_map.items():
            folder = session_p / sub
            if not folder.is_dir():
                continue
            for item in folder.rglob("*"):
                if not item.is_file() or item.name.startswith("."):
                    continue
                sz = item.stat().st_size
                mtime_str = datetime_str_from_mtime(item.stat().st_mtime)
                mime = detect_mime(item)
                ptype = classify_preview_type(item.name, mime)

                man_entry = manifest_map.get(str(item.resolve()), manifest_map.get(item.name, {}))
                sha = man_entry.get("destination_sha256")
                ver_status = man_entry.get("status", "UNVERIFIED")
                acq_status = "ACQUIRED"
                total_acquired += 1
                if ver_status == "VERIFIED":
                    total_verified += 1
                total_bytes += sz

                # DB metadata
                db_meta = None
                is_sqlite = False
                is_enc = False
                if cat == "Databases":
                    ident = WhatsAppDatabaseAnalyzer.identify_database(item)
                    is_sqlite = ident.is_sqlite
                    is_enc = ident.is_encrypted
                    reg_entry = reg_map.get(item.name, reg_map.get(str(item.resolve()), {}))
                    db_meta = {
                        "format_type": ident.format_type,
                        "tables": ident.tables,
                        "message_count": reg_entry.get("message_count", len(ident.tables)),
                        "oldest_timestamp": reg_entry.get("oldest_timestamp"),
                        "newest_timestamp": reg_entry.get("newest_timestamp"),
                        "key_status": reg_entry.get("key_status", "Key not checked"),
                        "decryption_status": reg_entry.get("decryption_status", "Not yet decrypted"),
                    }

                file_item = ViewerFileItem(
                    id=f"f_{file_counter}",
                    filename=item.name,
                    category=cat,
                    size_bytes=sz,
                    size_human=format_bytes(sz),
                    source_location=man_entry.get("source_path", str(item.relative_to(session_p))),
                    local_path=str(item.resolve()),
                    device_path=man_entry.get("source_path") if man_entry.get("source_path", "").startswith("/") else None,
                    acquisition_status=acq_status,
                    verification_status=ver_status,
                    sha256=sha,
                    is_accessible=True,
                    is_previewable=ptype != "unsupported",
                    preview_type=ptype,
                    mime_type=mime,
                    modified_time=mtime_str,
                    is_encrypted=is_enc,
                    is_sqlite=is_sqlite,
                    db_metadata=db_meta,
                )
                files.append(file_item)
                file_counter += 1

        sess = ViewerSession(
            session_id=session_id,
            session_name=f"{device_folder} — {session_p.name}",
            session_dir=str(session_p.resolve()),
            device_name=device_folder.replace("_", " "),
            device_serial=device_folder,
            device_status="Acquired Session",
            timestamp=datetime_str_from_mtime(session_p.stat().st_mtime),
            total_discovered=len(files),
            total_accessible=len(files),
            total_acquired=total_acquired,
            total_verified=total_verified,
            total_size_bytes=total_bytes,
            total_size_human=format_bytes(total_bytes),
            files=files,
        )
        return sess

    def _index_discovery_manifest(self, manifest: Any) -> Optional[ViewerSession]:
        """Index in-memory or persisted DiscoveryManifest candidates."""
        if not manifest:
            return None

        candidates = getattr(manifest, "candidates", [])
        if not candidates and isinstance(manifest, dict):
            candidates = manifest.get("candidates", [])

        sess_id = getattr(manifest, "session_id", "live_discovery")
        files: List[ViewerFileItem] = []
        file_counter = 1000

        total_bytes = 0
        total_discovered = 0
        total_accessible = 0

        for c in candidates:
            c_name = getattr(c, "filename", getattr(c, "name", "file"))
            c_path = getattr(c, "path", "")
            c_size = getattr(c, "size_bytes", 0)
            c_cat = getattr(c, "category", "Media")
            c_accessible = getattr(c, "is_accessible", True)
            c_device = getattr(c, "is_device", False)

            mime, _ = mimetypes.guess_type(c_name)
            mime = mime or "application/octet-stream"
            ptype = classify_preview_type(c_name, mime)

            total_discovered += 1
            if c_accessible:
                total_accessible += 1
            total_bytes += c_size

            local_p = None
            dev_p = None
            if c_device:
                dev_p = c_path
            elif Path(c_path).is_file():
                local_p = str(Path(c_path).resolve())

            file_item = ViewerFileItem(
                id=f"disc_{file_counter}",
                filename=c_name,
                category=c_cat,
                size_bytes=c_size,
                size_human=format_bytes(c_size),
                source_location=c_path,
                local_path=local_p,
                device_path=dev_p,
                acquisition_status="DISCOVERED" if not local_p else "ACQUIRED",
                verification_status="UNVERIFIED",
                sha256=getattr(c, "sha256", None),
                is_accessible=c_accessible,
                is_previewable=bool(local_p and ptype != "unsupported"),
                preview_type=ptype,
                mime_type=mime,
                modified_time=getattr(c, "modified_time", None),
                is_encrypted=getattr(c, "is_encrypted", False),
                is_sqlite=getattr(c, "is_sqlite", False),
            )
            files.append(file_item)
            file_counter += 1

        dev_name = getattr(manifest, "device_name", self.device.display_name if self.device else "Connected Device")
        dev_serial = getattr(manifest, "device_serial", self.device.serial if self.device else "device")
        dev_state = getattr(manifest, "device_state", "Connected")

        sess = ViewerSession(
            session_id=sess_id,
            session_name=f"Live Scan: {dev_name} ({sess_id})",
            session_dir=None,
            device_name=dev_name,
            device_serial=dev_serial,
            device_status=dev_state,
            timestamp=getattr(manifest, "timestamp", format_timestamp()),
            total_discovered=total_discovered,
            total_accessible=total_accessible,
            total_acquired=sum(1 for f in files if f.acquisition_status == "ACQUIRED"),
            total_verified=0,
            total_size_bytes=total_bytes,
            total_size_human=format_bytes(total_bytes),
            files=files,
        )
        return sess

    def acquire_file_to_staging(self, file_item: ViewerFileItem) -> Tuple[bool, Optional[Path], str]:
        """Safely acquire remote file from Android device via ADB to local staging."""
        if file_item.local_path and Path(file_item.local_path).is_file():
            return True, Path(file_item.local_path), "File already available locally."

        if not file_item.device_path:
            return False, None, "File has no remote device path and does not exist locally."

        if not self.device or not self.device.is_accessible:
            return False, None, "Connected Android device is not accessible to acquire remote file."

        clean_fn = sanitize_filename(file_item.filename)
        staged_target = self.staging_dir / f"{file_item.id}_{clean_fn}"

        pull_res = self.executor.run_cmd(["pull", file_item.device_path, str(staged_target)], serial=self.device.serial, timeout=120)
        if pull_res.returncode == 0 and staged_target.is_file():
            file_item.local_path = str(staged_target.resolve())
            file_item.acquisition_status = "ACQUIRED"
            file_item.is_previewable = classify_preview_type(file_item.filename, file_item.mime_type) != "unsupported"
            h, _, _ = hash_local_file(staged_target)
            file_item.sha256 = h
            return True, staged_target, "File successfully acquired from device."

        return False, None, f"Failed to acquire file from device: {pull_res.stderr.strip() or 'ADB error'}"


def datetime_str_from_mtime(mtime: float) -> str:
    """Format mtime to readable string."""
    try:
        from datetime import datetime
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "Unknown"


class RecoveryViewerRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the WRS Recovery Viewer."""

    server: RecoveryViewerServer

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard BaseHTTPRequestHandler stderr noise."""
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)

    def _set_security_headers(self, content_type: str = "application/json") -> None:
        """Enforce strict local-only Content Security Policy and security headers."""
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "object-src 'self'; "
            "connect-src 'self'; "
            "font-src 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:" + str(self.server.server_port))

    def _send_json_response(self, data: Any, status: int = 200) -> None:
        """Send formatted JSON response."""
        encoded = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._set_security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_error_json(self, message: str, status: int = 400) -> None:
        """Send structured JSON error message."""
        self._send_json_response({"error": True, "message": message}, status=status)

    def do_OPTIONS(self) -> None:
        """Handle preflight requests for localhost origin."""
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_security_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        """Dispatch GET requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # 1. Frontend Web Pages
        if path == "/":
            self._serve_viewer_html()
            return
        elif path.startswith("/static/"):
            self._serve_static_asset(path[len("/static/"):])
            return

        # 2. REST APIs
        if path == "/api/status":
            sess = self.server.get_active_session()
            data = sess.to_dict()
            data["sessions_available"] = [s.to_dict() for s in self.server.sessions.values()]
            data["active_session_id"] = self.server.active_session_id
            self._send_json_response(data)
            return

        elif path == "/api/sessions":
            data = [s.to_dict() for s in self.server.sessions.values()]
            self._send_json_response({"sessions": data, "active_session_id": self.server.active_session_id})
            return

        elif path == "/api/files":
            sess = self.server.get_active_session()
            files_data = [f.to_dict() for f in sess.files]
            self._send_json_response({"session_id": sess.session_id, "count": len(files_data), "files": files_data})
            return

        # /api/files/<file_id>
        m_file = re.match(r"^/api/files/([^/]+)$", path)
        if m_file:
            fid = m_file.group(1)
            file_item = self.server.file_index.get(fid)
            if not file_item:
                self._send_error_json(f"File item not found: {fid}", 404)
                return
            self._send_json_response(file_item.to_dict())
            return

        # /api/files/<file_id>/preview
        m_prev = re.match(r"^/api/files/([^/]+)/preview$", path)
        if m_prev:
            fid = m_prev.group(1)
            self._handle_file_preview(fid)
            return

        # /api/files/<file_id>/download
        m_down = re.match(r"^/api/files/([^/]+)/download$", path)
        if m_down:
            fid = m_down.group(1)
            self._handle_file_download(fid)
            return

        # /api/files/<file_id>/chat_data
        m_chat = re.match(r"^/api/files/([^/]+)/chat_data$", path)
        if m_chat:
            fid = m_chat.group(1)
            self._handle_database_chat_data(fid)
            return

        self._send_error_json(f"Not found: {path}", 404)

    def do_POST(self) -> None:
        """Dispatch POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        if path == "/api/sessions/select":
            sid = payload.get("session_id", "")
            if self.server.set_active_session(sid):
                self._send_json_response({"success": True, "active_session_id": sid})
            else:
                self._send_error_json(f"Session not found: {sid}", 404)
            return

        elif path == "/api/download/selected":
            file_ids = payload.get("file_ids", [])
            self._handle_zip_download_selected(file_ids)
            return

        elif path == "/api/download/all":
            category = payload.get("category")
            self._handle_zip_download_all(category)
            return

        elif path == "/api/acquire":
            file_id = payload.get("file_id", "")
            file_item = self.server.file_index.get(file_id)
            if not file_item:
                self._send_error_json(f"File item not found: {file_id}", 404)
                return
            ok, p, msg = self.server.acquire_file_to_staging(file_item)
            if ok:
                self._send_json_response({"success": True, "message": msg, "file": file_item.to_dict()})
            else:
                self._send_error_json(msg, 500)
            return

        self._send_error_json(f"Not found: {path}", 404)

    def _serve_viewer_html(self) -> None:
        """Serve main single-page viewer HTML template."""
        tmpl_file = self.server.templates_dir / "recovery_viewer.html"
        if not tmpl_file.is_file():
            self._send_error_json("Viewer HTML template not found on server", 500)
            return

        content = tmpl_file.read_bytes()
        self.send_response(HTTPStatus.OK)
        self._set_security_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_static_asset(self, subpath: str) -> None:
        """Safely serve static CSS and JS assets without path traversal."""
        safe_subpath = os.path.normpath(subpath).lstrip("/\\")
        asset_file = (self.server.static_dir / safe_subpath).resolve()

        if not str(asset_file).startswith(str(self.server.static_dir.resolve())):
            self._send_error_json("Access denied: path traversal prevented", 403)
            return

        if not asset_file.is_file():
            self._send_error_json("Asset not found", 404)
            return

        mime, _ = mimetypes.guess_type(str(asset_file))
        if asset_file.suffix == ".css":
            mime = "text/css"
        elif asset_file.suffix == ".js":
            mime = "application/javascript"

        content = asset_file.read_bytes()
        self.send_response(HTTPStatus.OK)
        self._set_security_headers(f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_file_preview(self, fid: str) -> None:
        """Stream file bytes for in-browser media players, image viewers, and text previews."""
        file_item = self.server.file_index.get(fid)
        if not file_item:
            self._send_error_json(f"File item not found: {fid}", 404)
            return

        # If file is on device, try acquiring to staging
        if not file_item.local_path or not Path(file_item.local_path).is_file():
            if file_item.device_path:
                ok, _, msg = self.server.acquire_file_to_staging(file_item)
                if not ok:
                    self._send_error_json(f"Cannot preview remote file: {msg}", 404)
                    return
            else:
                self._send_error_json("File is not accessible on disk", 404)
                return

        local_p = Path(file_item.local_path).resolve()
        if not self._validate_safe_path(local_p):
            self._send_error_json("Path traversal violation", 403)
            return

        # Text files can be returned as clean escaped payload or plain text
        if file_item.preview_type == "text":
            try:
                text_content = local_p.read_text(encoding="utf-8", errors="replace")
                # Truncate if gigantic (e.g. > 500KB) for safety
                truncated = False
                if len(text_content) > 500000:
                    text_content = text_content[:500000] + "\n\n... [TRUNCATED FOR BROWSER PERFORMANCE] ..."
                    truncated = True
                self._send_json_response({
                    "id": file_item.id,
                    "filename": file_item.filename,
                    "truncated": truncated,
                    "content": text_content,
                })
                return
            except Exception as e:
                self._send_error_json(f"Failed to read text file: {e}", 500)
                return

        # Stream binary file (image, audio, video, pdf) with Range support
        self._stream_file_range(local_p, file_item.mime_type)

    def _handle_file_download(self, fid: str) -> None:
        """Serve individual file as an attachment download."""
        file_item = self.server.file_index.get(fid)
        if not file_item:
            self._send_error_json(f"File item not found: {fid}", 404)
            return

        if not file_item.local_path or not Path(file_item.local_path).is_file():
            if file_item.device_path:
                ok, _, msg = self.server.acquire_file_to_staging(file_item)
                if not ok:
                    self._send_error_json(f"Cannot download remote file: {msg}", 404)
                    return
            else:
                self._send_error_json("File not accessible on disk", 404)
                return

        local_p = Path(file_item.local_path).resolve()
        if not self._validate_safe_path(local_p):
            self._send_error_json("Path traversal violation", 403)
            return

        safe_fn = sanitize_filename(file_item.filename)
        sz = local_p.stat().st_size

        self.send_response(HTTPStatus.OK)
        self._set_security_headers("application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{safe_fn}"')
        self.send_header("Content-Length", str(sz))
        self.end_headers()

        with open(local_p, "rb") as f:
            while chunk := f.read(65536):
                try:
                    self.wfile.write(chunk)
                except BrokenPipeError:
                    break

    def _handle_database_chat_data(self, fid: str) -> None:
        """Inspect and return sample messages for a readable SQLite chat database."""
        file_item = self.server.file_index.get(fid)
        if not file_item or not file_item.local_path:
            self._send_error_json("Database file not accessible", 404)
            return

        db_p = Path(file_item.local_path).resolve()
        if not self._validate_safe_path(db_p) or not db_p.is_file():
            self._send_error_json("Invalid database file path", 400)
            return

        ident = WhatsAppDatabaseAnalyzer.identify_database(db_p)
        if not ident.is_sqlite or ident.is_encrypted:
            self._send_json_response({
                "is_sqlite": ident.is_sqlite,
                "is_encrypted": ident.is_encrypted,
                "format_type": ident.format_type,
                "notes": ident.notes,
                "messages": [],
            })
            return

        # Extract top 50 sample messages safely in read-only mode
        raw_msgs = WhatsAppDatabaseAnalyzer.extract_raw_messages(db_p)
        sample = raw_msgs[:50]
        self._send_json_response({
            "is_sqlite": True,
            "is_encrypted": False,
            "format_type": ident.format_type,
            "total_messages": len(raw_msgs),
            "tables": ident.tables,
            "messages": sample,
        })

    def _handle_zip_download_selected(self, file_ids: List[str]) -> None:
        """Package explicitly selected files into a ZIP archive and stream it."""
        selected_items: List[ViewerFileItem] = []
        for fid in file_ids:
            it = self.server.file_index.get(fid)
            if it:
                # If remote on device, stage it first
                if not it.local_path or not Path(it.local_path).is_file():
                    if it.device_path and self.server.device:
                        self.server.acquire_file_to_staging(it)
                if it.local_path and Path(it.local_path).is_file():
                    selected_items.append(it)

        if not selected_items:
            self._send_error_json("No accessible files selected for download.", 400)
            return

        self._package_and_send_zip(selected_items, "selected_recovered_files.zip")

    def _handle_zip_download_all(self, category: Optional[str] = None) -> None:
        """Package all eligible files from current scope into a ZIP archive."""
        sess = self.server.get_active_session()
        eligible_items: List[ViewerFileItem] = []

        for it in sess.files:
            if category and it.category.lower() != category.lower():
                continue
            if not it.local_path or not Path(it.local_path).is_file():
                if it.device_path and self.server.device:
                    self.server.acquire_file_to_staging(it)
            if it.local_path and Path(it.local_path).is_file():
                eligible_items.append(it)

        if not eligible_items:
            self._send_error_json("No accessible files found in the requested scope.", 400)
            return

        tag = f"all_{category.lower()}_files.zip" if category else "all_recovered_files.zip"
        self._package_and_send_zip(eligible_items, tag)

    def _package_and_send_zip(self, items: List[ViewerFileItem], download_filename: str) -> None:
        """Create a validated ZIP archive with internal manifest and collision prevention."""
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp_file:
            tmp_zip_path = Path(tmp_file.name)

        try:
            manifest_records: List[Dict[str, Any]] = []
            used_arcnames: Set[str] = set()

            with zipfile.ZipFile(tmp_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for item in items:
                    src_p = Path(item.local_path)
                    if not src_p.is_file():
                        continue

                    # Safe relative path inside ZIP
                    cat_folder = item.category.lower().replace(" ", "_")
                    safe_fn = sanitize_filename(item.filename)
                    arcname = f"{cat_folder}/{safe_fn}"

                    # Collision handling
                    counter = 1
                    stem, ext = os.path.splitext(safe_fn)
                    while arcname in used_arcnames:
                        arcname = f"{cat_folder}/{stem}_{counter}{ext}"
                        counter += 1
                    used_arcnames.add(arcname)

                    zf.write(src_p, arcname=arcname)
                    manifest_records.append({
                        "id": item.id,
                        "filename": item.filename,
                        "archive_path": arcname,
                        "category": item.category,
                        "size_bytes": item.size_bytes,
                        "sha256": item.sha256 or hash_local_file(src_p)[0],
                        "source_location": item.source_location,
                    })

                # Internal manifest
                manifest_payload = {
                    "package_type": "WRS Recovery Archive",
                    "generated_at": format_timestamp(),
                    "file_count": len(manifest_records),
                    "total_bytes": sum(r["size_bytes"] for r in manifest_records),
                    "files": manifest_records,
                }
                zf.writestr("archive_manifest.json", json.dumps(manifest_payload, indent=2))

            # Send ZIP
            zip_sz = tmp_zip_path.stat().st_size
            self.send_response(HTTPStatus.OK)
            self._set_security_headers("application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{download_filename}"')
            self.send_header("Content-Length", str(zip_sz))
            self.end_headers()

            with open(tmp_zip_path, "rb") as f:
                while chunk := f.read(65536):
                    try:
                        self.wfile.write(chunk)
                    except BrokenPipeError:
                        break

        finally:
            try:
                tmp_zip_path.unlink()
            except OSError:
                pass

    def _stream_file_range(self, local_p: Path, mime: str) -> None:
        """Stream a binary file with HTTP Range headers (RFC 7233)."""
        file_size = local_p.stat().st_size
        range_header = self.headers.get("Range")

        start = 0
        end = file_size - 1

        if range_header:
            m = re.match(r"^bytes=(\d+)-(\d*)$", range_header.strip())
            if m:
                start = int(m.group(1))
                if m.group(2):
                    end = int(m.group(2))
                if start >= file_size or end >= file_size or start > end:
                    self.send_response(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE)
                    self.send_header("Content-Range", f"bytes */{file_size}")
                    self.end_headers()
                    return

                content_len = (end - start) + 1
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self._set_security_headers(mime)
                self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
                self.send_header("Content-Length", str(content_len))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()

                with open(local_p, "rb") as f:
                    f.seek(start)
                    remaining = content_len
                    while remaining > 0:
                        chunk_to_read = min(65536, remaining)
                        chunk = f.read(chunk_to_read)
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except BrokenPipeError:
                            break
                        remaining -= len(chunk)
                return

        # Full file stream
        self.send_response(HTTPStatus.OK)
        self._set_security_headers(mime)
        self.send_header("Content-Length", str(file_size))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

        with open(local_p, "rb") as f:
            while chunk := f.read(65536):
                try:
                    self.wfile.write(chunk)
                except BrokenPipeError:
                    break

    def _validate_safe_path(self, local_p: Path) -> bool:
        """Validate that path resides strictly inside approved project directories."""
        res_p = local_p.resolve()
        approved_roots = [
            self.server.recovery_root.resolve(),
            self.server.project_root.resolve(),
            Path(tempfile.gettempdir()).resolve(),
        ]
        return any(str(res_p).startswith(str(r)) for r in approved_roots)


def find_available_port(start_port: int = 8080, max_attempts: int = 50) -> int:
    """Find an available port starting at start_port on 127.0.0.1."""
    for p in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    # Fallback to ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_recovery_viewer_server(
    recovery_root: Path | str,
    executor: Optional[AdbExecutor] = None,
    settings: Optional[Dict[str, Any]] = None,
    device: Optional[DeviceInfo] = None,
    discovery_manifest: Optional[Any] = None,
    port: Optional[int] = None,
    open_browser: bool = True,
) -> Tuple[RecoveryViewerServer, threading.Thread, str]:
    """Start the Recovery Viewer server in a background thread and return (server, thread, url)."""
    rec_path = Path(recovery_root).resolve()
    chosen_port = port or find_available_port(8080)

    server = RecoveryViewerServer(
        server_address=("127.0.0.1", chosen_port),
        recovery_root=rec_path,
        executor=executor,
        settings=settings,
        device=device,
        discovery_manifest=discovery_manifest,
    )

    url = f"http://127.0.0.1:{chosen_port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            logger.warning("Could not automatically launch browser.")

    return server, thread, url
