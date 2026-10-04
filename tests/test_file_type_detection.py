# tests/test_file_type_detection.py
"""FileTypeDetector coverage — archive families, magic-byte detection,
and OOXML-vs-plain-zip discrimination."""
import os
import struct
import tempfile
import zipfile

import pytest

from app.utils.file_io import FileTypeDetector


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ── 7z magic bytes ──

class TestSevenZDetection:
    SEVEN_Z_MAGIC = b"\x37\x7A\xBC\xAF\x27\x1C"

    def test_7z_detected_as_archive(self, tmp_path):
        path = _write(tmp_path, "sample.7z", self.SEVEN_Z_MAGIC + b"\x00" * 32)
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "archive"
        assert result["type"] == "7z"

    def test_truncated_header_not_7z(self, tmp_path):
        path = _write(tmp_path, "short.7z", self.SEVEN_Z_MAGIC[:4])
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] != "archive" or result["type"] != "7z"


# ── Zip: plain zip vs OOXML ──

class TestZipDetection:
    def test_plain_zip_is_archive(self, tmp_path):
        zpath = tmp_path / "plain.zip"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("readme.txt", "hello")
        result = FileTypeDetector.detect_file_type(str(zpath))
        assert result["family"] == "archive"
        assert result["type"] == "zip"

    def test_docx_is_office_not_archive(self, tmp_path):
        zpath = tmp_path / "doc.docx"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<document/>")
        result = FileTypeDetector.detect_file_type(str(zpath))
        assert result["family"] == "office"
        assert result["type"] == "docx"

    def test_xlsx_is_office(self, tmp_path):
        zpath = tmp_path / "sheet.xlsx"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("xl/workbook.xml", "<workbook/>")
        result = FileTypeDetector.detect_file_type(str(zpath))
        assert result["family"] == "office"
        assert result["type"] == "xlsx"

    def test_pptx_is_office(self, tmp_path):
        zpath = tmp_path / "deck.pptx"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("ppt/presentation.xml", "<presentation/>")
        result = FileTypeDetector.detect_file_type(str(zpath))
        assert result["family"] == "office"
        assert result["type"] == "pptx"

    def test_docm_macro_enabled(self, tmp_path):
        zpath = tmp_path / "macro.docm"
        with zipfile.ZipFile(str(zpath), "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<document/>")
            z.writestr("word/vbaProject.bin", b"\x00" * 16)
        result = FileTypeDetector.detect_file_type(str(zpath))
        assert result["family"] == "office"
        assert result["type"] == "docm"

    def test_corrupted_zip(self, tmp_path):
        path = _write(tmp_path, "bad.zip", b"PK\x03\x04" + b"\xFF" * 20)
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "archive"
        assert result["type"] == "corrupted"


# ── Other magic bytes still work ──

class TestOtherFamilies:
    def test_mz_header_is_pe(self, tmp_path):
        pe_header = bytearray(512)
        pe_header[0:2] = b"MZ"
        pe_offset = 0x80
        struct.pack_into("<I", pe_header, 0x3C, pe_offset)
        pe_header[pe_offset:pe_offset+4] = b"PE\x00\x00"
        struct.pack_into("<HHIIIHH", pe_header, pe_offset + 4,
                         0x8664, 0, 0, 0, 0, 96, 0x0022)
        opt_start = pe_offset + 24
        pe_header[opt_start + 68:opt_start + 70] = struct.pack("<H", 3)
        path = _write(tmp_path, "test.exe", bytes(pe_header))
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "pe"

    def test_lnk_header(self, tmp_path):
        lnk_data = (
            b"\x4C\x00\x00\x00"
            + b"\x01\x14\x02\x00\x00\x00\x00\x00"
            + b"\xC0\x00\x00\x00\x00\x00\x00\x46"
            + b"\x00" * 56
        )
        path = _write(tmp_path, "test.lnk", lnk_data)
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "lnk"

    def test_unknown_bytes(self, tmp_path):
        path = _write(tmp_path, "mystery.bin", b"\xDE\xAD\xBE\xEF" + b"\x00" * 20)
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "unknown"

    def test_html_by_extension(self, tmp_path):
        path = _write(tmp_path, "page.html", b"<html></html>")
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "html"

    def test_script_by_extension(self, tmp_path):
        path = _write(tmp_path, "run.ps1", b"Write-Host 'hi'")
        result = FileTypeDetector.detect_file_type(path)
        assert result["family"] == "script"
        assert result["type"] == "ps1"
