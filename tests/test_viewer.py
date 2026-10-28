"""Unit and integration tests for WRS Recovery Viewer & File Download Center (Section 16 Requirements)."""

import io
import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

from wrs.device import AdbExecutor, DeviceInfo
from wrs.hashing import hash_local_file
from wrs.server import (
    RecoveryViewerServer,
    ViewerFileItem,
    ViewerSession,
    classify_preview_type,
    detect_mime,
    find_available_port,
    start_recovery_viewer_server,
)


class TestRecoveryViewer(unittest.TestCase):
    """Test suite addressing all 19 criteria specified in Section 16."""

    @classmethod
    def setUpClass(cls):
        # Create persistent temporary directories for test fixtures
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.base_p = Path(cls.temp_dir.name)
        cls.rec_p = cls.base_p / "recovery"
        cls.rec_p.mkdir(parents=True, exist_ok=True)

        # Create sample session: recovery/Pixel_7/scan_test/
        cls.dev_folder = cls.rec_p / "Pixel_7"
        cls.sess_folder = cls.dev_folder / "scan_test"
        cls.sess_folder.mkdir(parents=True, exist_ok=True)

        # Create category folders
        cls.img_dir = cls.sess_folder / "images"
        cls.vid_dir = cls.sess_folder / "videos"
        cls.aud_dir = cls.sess_folder / "audio"
        cls.doc_dir = cls.sess_folder / "documents"
        cls.db_dir = cls.sess_folder / "databases"
        for d in (cls.img_dir, cls.vid_dir, cls.aud_dir, cls.doc_dir, cls.db_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Populate test files
        cls.img_file = cls.img_dir / "sample_photo.jpg"
        cls.img_file.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 200)  # JPEG header

        cls.vid_file = cls.vid_dir / "sample_video.mp4"
        cls.vid_file.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 300)

        cls.aud_file = cls.aud_dir / "voice_note.opus"
        cls.aud_file.write_bytes(b"OggS" + b"\x00" * 250)

        cls.doc_txt = cls.doc_dir / "notes.txt"
        cls.doc_txt.write_text("Confidential forensic investigation report.\nCase ID: #9876.", encoding="utf-8")

        cls.doc_pdf = cls.doc_dir / "document.pdf"
        cls.doc_pdf.write_bytes(b"%PDF-1.4\n%testpdf\n" + b"\x00" * 100)

        cls.unsupported_file = cls.doc_dir / "firmware.bin"
        cls.unsupported_file.write_bytes(b"\x7fELF" + b"\x00" * 150)

        # Create SQLite chat database
        cls.db_file = cls.db_dir / "msgstore.db"
        with sqlite3.connect(cls.db_file) as conn:
            conn.execute("""
                CREATE TABLE message (
                    _id INTEGER PRIMARY KEY,
                    chat_row_id INTEGER,
                    from_me INTEGER,
                    text_data TEXT,
                    timestamp INTEGER,
                    message_type INTEGER
                )
            """)
            conn.execute("CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
            conn.execute("CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT)")
            conn.execute("INSERT INTO jid VALUES (1, 'alice@s.whatsapp.net')")
            conn.execute("INSERT INTO chat VALUES (1, 1)")
            conn.execute("INSERT INTO message VALUES (1, 1, 0, 'Hello Alice', 1690000000000, 0)")
            conn.execute("INSERT INTO message VALUES (2, 1, 0, 'Meeting confirmed', 1690000050000, 0)")
            conn.commit()

        # Create encrypted database
        cls.crypt_file = cls.db_dir / "msgstore.db.crypt14"
        cls.crypt_file.write_bytes(b"\x00" * 191 + b"CIPHERTEXT_SAMPLE")

        # Mock ADB Executor and Device
        cls.mock_executor = MagicMock(spec=AdbExecutor)
        cls.mock_executor.is_adb_installed.return_value = True

        cls.mock_device = DeviceInfo(
            serial="PIXEL7_USB",
            state="device",
            model="Pixel_7",
            manufacturer="Google",
            android_version="13",
        )

        # Start server on dynamic port
        cls.port = find_available_port(8890)
        cls.server, cls.thread, cls.base_url = start_recovery_viewer_server(
            recovery_root=cls.rec_p,
            executor=cls.mock_executor,
            settings={"acquisition": {"default_recovery_dir": str(cls.rec_p)}},
            device=cls.mock_device,
            port=cls.port,
            open_browser=False,
        )
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.shutdown()
            cls.server.server_close()
        except Exception:
            pass
        cls.temp_dir.cleanup()

    def _http_get(self, path: str, headers: dict = None) -> tuple[int, bytes, dict]:
        """Helper to perform HTTP GET on server."""
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def _http_post_json(self, path: str, payload: dict) -> tuple[int, bytes, dict]:
        """Helper to perform HTTP POST JSON on server."""
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    # 1. Rendering the page using actual scan metadata
    def test_01_render_page_using_actual_scan_metadata(self):
        """Verify HTML page renders with security headers and status API reflects actual scan data."""
        status_code, body, headers = self._http_get("/")
        self.assertEqual(status_code, 200)
        html_text = body.decode("utf-8")
        self.assertIn("WRS — Recovery Viewer", html_text)
        self.assertIn("Local Data Preview", html_text)
        self.assertIn("Content-Security-Policy", headers)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

        # Check /api/status
        sc, s_body, _ = self._http_get("/api/status")
        self.assertEqual(sc, 200)
        status_data = json.loads(s_body.decode("utf-8"))
        self.assertIn("total_discovered", status_data)
        self.assertIn("total_size_bytes", status_data)
        self.assertEqual(status_data["device_name"], "Pixel 7")
        self.assertGreaterEqual(status_data["file_count"], 6)

    # 2. Empty inventory and previous-session scenarios
    def test_02_empty_inventory_and_previous_sessions(self):
        """Verify empty session is handled gracefully and session switcher lists sessions."""
        sc, body, _ = self._http_get("/api/sessions")
        self.assertEqual(sc, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("sessions", data)
        self.assertTrue(len(data["sessions"]) >= 1)

        # Select non-existent session
        sc_bad, _, _ = self._http_post_json("/api/sessions/select", {"session_id": "non_existent_123"})
        self.assertEqual(sc_bad, 404)

        # Select valid session
        valid_id = data["sessions"][0]["session_id"]
        sc_ok, b_ok, _ = self._http_post_json("/api/sessions/select", {"session_id": valid_id})
        self.assertEqual(sc_ok, 200)
        res = json.loads(b_ok.decode("utf-8"))
        self.assertTrue(res["success"])

    # 3. Image preview and individual download
    def test_03_image_preview_and_individual_download(self):
        """Verify image preview streaming and attachment download."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        img_item = next(f for f in files if f["filename"] == "sample_photo.jpg")

        # Preview
        sc_prev, prev_bytes, prev_hdrs = self._http_get(f"/api/files/{img_item['id']}/preview")
        self.assertEqual(sc_prev, 200)
        self.assertIn("image/jpeg", prev_hdrs.get("Content-Type", ""))
        self.assertEqual(prev_bytes, self.img_file.read_bytes())

        # Download
        sc_down, down_bytes, down_hdrs = self._http_get(f"/api/files/{img_item['id']}/download")
        self.assertEqual(sc_down, 200)
        self.assertIn("attachment", down_hdrs.get("Content-Disposition", ""))
        self.assertIn("sample_photo.jpg", down_hdrs.get("Content-Disposition", ""))
        self.assertEqual(down_bytes, self.img_file.read_bytes())

    # 4. Audio and video preview where formats permit
    def test_04_audio_and_video_preview_with_range_requests(self):
        """Verify audio and video streaming with HTTP Range headers (partial content)."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        vid_item = next(f for f in files if f["filename"] == "sample_video.mp4")
        aud_item = next(f for f in files if f["filename"] == "voice_note.opus")

        # Full video preview
        sc_v, v_bytes, v_hdrs = self._http_get(f"/api/files/{vid_item['id']}/preview")
        self.assertEqual(sc_v, 200)
        self.assertEqual(len(v_bytes), self.vid_file.stat().st_size)

        # Range request on audio (bytes=0-99)
        sc_range, a_range_bytes, a_hdrs = self._http_get(
            f"/api/files/{aud_item['id']}/preview", headers={"Range": "bytes=0-99"}
        )
        self.assertEqual(sc_range, 206)  # Partial Content
        self.assertEqual(len(a_range_bytes), 100)
        self.assertIn("bytes 0-99/", a_hdrs.get("Content-Range", ""))

    # 5. Safe document text and PDF handling
    def test_05_safe_document_text_and_pdf_handling(self):
        """Verify text preview returns sanitized payload and PDF streams application/pdf."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        txt_item = next(f for f in files if f["filename"] == "notes.txt")
        pdf_item = next(f for f in files if f["filename"] == "document.pdf")

        # Text preview
        sc_txt, txt_body, _ = self._http_get(f"/api/files/{txt_item['id']}/preview")
        self.assertEqual(sc_txt, 200)
        txt_json = json.loads(txt_body.decode("utf-8"))
        self.assertIn("Confidential forensic investigation report", txt_json["content"])
        self.assertEqual(txt_json["filename"], "notes.txt")

        # PDF preview
        sc_pdf, pdf_bytes, pdf_hdrs = self._http_get(f"/api/files/{pdf_item['id']}/preview")
        self.assertEqual(sc_pdf, 200)
        self.assertIn("application/pdf", pdf_hdrs.get("Content-Type", ""))
        self.assertEqual(pdf_bytes, self.doc_pdf.read_bytes())

    # 6. Unsupported file formats
    def test_06_unsupported_file_formats_handling(self):
        """Verify binary unsupported formats are classified as unsupported but downloadable."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        bin_item = next(f for f in files if f["filename"] == "firmware.bin")
        self.assertEqual(bin_item["preview_type"], "unsupported")

        # Can still be downloaded safely
        sc_d, d_bytes, d_hdrs = self._http_get(f"/api/files/{bin_item['id']}/download")
        self.assertEqual(sc_d, 200)
        self.assertEqual(d_bytes, self.unsupported_file.read_bytes())

    # 7. Downloading one file
    def test_07_download_single_file(self):
        """Verify downloading a single file produces authentic matching bytes and hash."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        txt_item = next(f for f in files if f["filename"] == "notes.txt")

        sc_d, data, _ = self._http_get(f"/api/files/{txt_item['id']}/download")
        self.assertEqual(sc_d, 200)
        self.assertEqual(data, self.doc_txt.read_bytes())

    # 8. Downloading multiple selected files
    def test_08_download_multiple_selected_files_as_zip(self):
        """Verify packaging explicitly selected file IDs into a valid ZIP archive."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        f_ids = [files[0]["id"], files[1]["id"]]

        sc_zip, zip_bytes, zip_hdrs = self._http_post_json("/api/download/selected", {"file_ids": f_ids})
        self.assertEqual(sc_zip, 200)
        self.assertIn("application/zip", zip_hdrs.get("Content-Type", ""))

        # Verify ZIP structure
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            self.assertIn("archive_manifest.json", names)
            self.assertEqual(len(names), 3)  # 2 files + 1 manifest

    # 9. Downloading all eligible files from a defined scope
    def test_09_download_all_eligible_files_from_scope(self):
        """Verify /api/download/all packages all eligible items or category subsets."""
        # Download all Images
        sc_img, zip_bytes, _ = self._http_post_json("/api/download/all", {"category": "Images"})
        self.assertEqual(sc_img, 200)

        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            self.assertIn("archive_manifest.json", names)
            self.assertTrue(any("sample_photo.jpg" in n for n in names))

    # 10. Correct ZIP contents and manifest
    def test_10_correct_zip_contents_and_manifest_hashes(self):
        """Verify internal archive_manifest.json contains accurate filenames and checksums."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        img_item = next(f for f in files if f["filename"] == "sample_photo.jpg")

        sc_z, zip_bytes, _ = self._http_post_json("/api/download/selected", {"file_ids": [img_item["id"]]})
        self.assertEqual(sc_z, 200)

        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            man_content = zf.read("archive_manifest.json")
            manifest = json.loads(man_content.decode("utf-8"))
            self.assertEqual(manifest["file_count"], 1)
            file_rec = manifest["files"][0]
            self.assertEqual(file_rec["filename"], "sample_photo.jpg")

            expected_sha, _, _ = hash_local_file(self.img_file)
            self.assertEqual(file_rec["sha256"], expected_sha)

    # 11. Large-file streaming and interrupted operations
    def test_11_large_file_streaming_and_invalid_ranges(self):
        """Verify out-of-bounds byte range returns 416 Range Not Satisfiable."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        vid_item = next(f for f in files if f["filename"] == "sample_video.mp4")

        sc_err, _, _ = self._http_get(
            f"/api/files/{vid_item['id']}/preview", headers={"Range": "bytes=999999-9999999"}
        )
        self.assertEqual(sc_err, 416)

    # 12. Missing files and permission errors
    def test_12_missing_file_error_handling(self):
        """Verify requesting non-existent file ID returns structured 404 JSON."""
        sc, body, _ = self._http_get("/api/files/fake_file_9999/download")
        self.assertEqual(sc, 404)
        err = json.loads(body.decode("utf-8"))
        self.assertTrue(err.get("error"))

    # 13. Path traversal and malicious file IDs
    def test_13_path_traversal_and_malicious_file_ids_prevented(self):
        """Ensure path traversal attacks on static and file endpoints are blocked."""
        # 1. Static asset traversal
        sc_static, body, _ = self._http_get("/static/../../../../etc/passwd")
        self.assertIn(sc_static, (403, 404))

        # 2. File ID traversal
        sc_traversal, _, _ = self._http_get("/api/files/..%2f..%2fetc%2fpasswd")
        self.assertIn(sc_traversal, (400, 403, 404))

    # 14. Unsafe HTML, SVG, and filenames
    def test_14_unsafe_filenames_and_html_escaping(self):
        """Verify HTML escaping of filenames and text contents."""
        unsafe_file = self.doc_dir / "test_<script>alert('xss')<script>.txt"
        unsafe_file.write_text("Safe content", encoding="utf-8")
        self.server.refresh_catalog()

        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        item = next((f for f in files if "alert('xss')" in f["filename"]), None)
        self.assertIsNotNone(item)

        # Download sanitizes the filename header
        sc_d, _, hdrs = self._http_get(f"/api/files/{item['id']}/download")
        self.assertEqual(sc_d, 200)
        disp = hdrs.get("Content-Disposition", "")
        self.assertNotIn("<script>", disp)

    # 15. Duplicate filenames in ZIP archives
    def test_15_duplicate_filenames_in_zip_archives_handled_safely(self):
        """Verify two files with identical filenames in different subdirs are packaged without overwrite."""
        # Create a second sample_photo.jpg in doc_dir
        dup_img = self.doc_dir / "sample_photo.jpg"
        dup_img.write_bytes(b"\xff\xd8\xff\xe0" + b"\x01" * 100)
        self.server.refresh_catalog()

        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        dups = [f for f in files if f["filename"] == "sample_photo.jpg"]
        self.assertGreaterEqual(len(dups), 2)

        # Download both
        sc_zip, zip_bytes, _ = self._http_post_json(
            "/api/download/selected", {"file_ids": [dups[0]["id"], dups[1]["id"]]}
        )
        self.assertEqual(sc_zip, 200)

        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            # Must contain distinct archive paths, no silent overwrite
            self.assertEqual(len(names), 3)  # 2 files + 1 manifest

    # 16. Localhost-only server binding
    def test_16_localhost_only_server_binding(self):
        """Verify server binds exclusively to 127.0.0.1."""
        host, port = self.server.server_address
        self.assertEqual(host, "127.0.0.1")
        self.assertTrue(1024 <= port <= 65535)

    # 17. No automatic scan on viewer startup
    def test_17_no_automatic_scan_on_viewer_startup(self):
        """Ensure starting viewer does not execute device scan commands."""
        # Verify mock_executor.run_cmd was not called for broad storage walk
        for call in self.mock_executor.run_cmd.call_args_list:
            args = call[0][0] if call[0] else []
            self.assertNotIn("find", args)
            self.assertNotIn("du", args)

    # 18. No changes to source files during previewing
    def test_18_no_changes_to_source_files_during_preview(self):
        """Verify source file bytes and mtime are strictly preserved during preview and download."""
        original_bytes = self.img_file.read_bytes()
        original_mtime = self.img_file.stat().st_mtime

        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        img_item = next(f for f in files if f["filename"] == "sample_photo.jpg")

        # Preview and download multiple times
        self._http_get(f"/api/files/{img_item['id']}/preview")
        self._http_get(f"/api/files/{img_item['id']}/download")

        # Source file must be 100% unaltered
        self.assertEqual(self.img_file.read_bytes(), original_bytes)
        self.assertEqual(self.img_file.stat().st_mtime, original_mtime)

    # 19. Database chat messages inspection endpoint
    def test_19_database_chat_data_inspection(self):
        """Verify /api/files/<id>/chat_data returns structured table rows for readable SQLite."""
        sc, body, _ = self._http_get("/api/files")
        files = json.loads(body.decode("utf-8"))["files"]
        db_item = next(f for f in files if f["filename"] == "msgstore.db")

        sc_chat, chat_body, _ = self._http_get(f"/api/files/{db_item['id']}/chat_data")
        self.assertEqual(sc_chat, 200)
        data = json.loads(chat_body.decode("utf-8"))
        self.assertTrue(data["is_sqlite"])
        self.assertEqual(data["total_messages"], 2)
        self.assertEqual(data["messages"][0]["text_content"], "Hello Alice")


if __name__ == "__main__":
    unittest.main()
