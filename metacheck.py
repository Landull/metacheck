#!/usr/bin/env python3
"""
metacheck - forensic metadata extractor.

Pulls metadata out of images (JPEG, PNG, TIFF/DNG, WebP, HEIC), PDFs and
Office documents (DOCX/XLSX/PPTX and ODT/ODS/ODP), and flags the details that
matter in an investigation: GPS coordinates, editing software, timestamp
mismatches, embedded thumbnails, data appended after the end of a file,
PDF revisions and active content, and Office macros.

Standard library only. Python 3.8+.

https://github.com/Landull/metacheck
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import struct
import sys
import zipfile
import zlib
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

__version__ = "1.0.0"

MAX_READ = 512 * 1024 * 1024   # don't load files bigger than this into memory
MAX_INFLATE = 2 * 1024 * 1024  # cap on decompressed text chunks

# --------------------------------------------------------------------------
# Type detection
# --------------------------------------------------------------------------

EXPECTED_EXT = {
    "jpeg": {".jpg", ".jpeg", ".jpe", ".jfif"},
    "png": {".png"},
    "tiff": {".tif", ".tiff", ".dng", ".nef", ".cr2", ".arw", ".pef", ".srw"},
    "webp": {".webp"},
    "heif": {".heic", ".heif", ".avif", ".hif"},
    "pdf": {".pdf"},
    "zip": {".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
            ".odt", ".ods", ".odp", ".jar", ".apk", ".epub"},
    "gif": {".gif"},
    "mp4/mov": {".mp4", ".mov", ".m4v", ".m4a", ".3gp"},
}
OFFICE_EXTS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
               ".odt", ".ods", ".odp"}
SUPPORTED = {"jpeg", "png", "tiff", "webp", "heif", "pdf", "zip"}
HEIF_BRANDS = {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1", b"avif"}


def detect_type(head):
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "webp"
    if head[4:8] == b"ftyp":
        return "heif" if head[8:12] in HEIF_BRANDS else "mp4/mov"
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    return "unknown"


def name_signature(blob):
    """Name a few common file types for describing appended data."""
    sigs = [(b"PK\x03\x04", "ZIP archive"), (b"Rar!", "RAR archive"),
            (b"7z\xbc\xaf", "7-Zip archive"), (b"%PDF", "PDF"),
            (b"\xff\xd8\xff", "JPEG image"), (b"\x89PNG", "PNG image"),
            (b"MZ", "Windows executable"), (b"\x7fELF", "ELF executable")]
    for sig, label in sigs:
        if blob.startswith(sig):
            return label
    if b"SEFH" in blob[-16:] or b"SEFT" in blob[-16:]:
        return "Samsung camera trailer"
    return None


# --------------------------------------------------------------------------
# EXIF / TIFF
# --------------------------------------------------------------------------

EXIF_TAGS = {
    0x0100: "ImageWidth", 0x0101: "ImageHeight", 0x010E: "ImageDescription",
    0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x011A: "XResolution", 0x011B: "YResolution", 0x0128: "ResolutionUnit",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist",
    0x013C: "HostComputer", 0x8298: "Copyright",
    0x829A: "ExposureTime", 0x829D: "FNumber", 0x8822: "ExposureProgram",
    0x8827: "ISO", 0x9000: "ExifVersion", 0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized", 0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal", 0x9012: "OffsetTimeDigitized",
    0x9201: "ShutterSpeedValue", 0x9202: "ApertureValue",
    0x9204: "ExposureBiasValue", 0x9207: "MeteringMode", 0x9209: "Flash",
    0x920A: "FocalLength", 0x927C: "MakerNote", 0x9286: "UserComment",
    0x9290: "SubSecTime", 0x9291: "SubSecTimeOriginal",
    0x9292: "SubSecTimeDigitized", 0xA000: "FlashpixVersion",
    0xA001: "ColorSpace", 0xA002: "PixelXDimension", 0xA003: "PixelYDimension",
    0xA402: "ExposureMode", 0xA403: "WhiteBalance",
    0xA405: "FocalLengthIn35mmFilm", 0xA406: "SceneCaptureType",
    0xA420: "ImageUniqueID", 0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber", 0xA432: "LensSpecification",
    0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
}
GPS_TAGS = {
    0x00: "GPSVersionID", 0x01: "GPSLatitudeRef", 0x02: "GPSLatitude",
    0x03: "GPSLongitudeRef", 0x04: "GPSLongitude", 0x05: "GPSAltitudeRef",
    0x06: "GPSAltitude", 0x07: "GPSTimeStamp", 0x0C: "GPSSpeedRef",
    0x0D: "GPSSpeed", 0x10: "GPSImgDirectionRef", 0x11: "GPSImgDirection",
    0x12: "GPSMapDatum", 0x1B: "GPSProcessingMethod", 0x1D: "GPSDateStamp",
    0x1F: "GPSHPositioningError",
}
SUB_IFD_POINTERS = {0x8769, 0x8825, 0xA005}
ENUMS = {
    "Orientation": {1: "Normal", 2: "Mirrored", 3: "Rotated 180",
                    4: "Mirrored vertical", 5: "Mirrored, rotated 90 CCW",
                    6: "Rotated 90 CW", 7: "Mirrored, rotated 90 CW",
                    8: "Rotated 90 CCW"},
    "ResolutionUnit": {1: "None", 2: "inches", 3: "cm"},
    "ExposureProgram": {0: "Not defined", 1: "Manual", 2: "Normal program",
                        3: "Aperture priority", 4: "Shutter priority",
                        5: "Creative", 6: "Action", 7: "Portrait",
                        8: "Landscape"},
    "MeteringMode": {0: "Unknown", 1: "Average", 2: "Center-weighted",
                     3: "Spot", 4: "Multi-spot", 5: "Pattern", 6: "Partial",
                     255: "Other"},
    "ColorSpace": {1: "sRGB", 65535: "Uncalibrated"},
    "ExposureMode": {0: "Auto", 1: "Manual", 2: "Auto bracket"},
    "WhiteBalance": {0: "Auto", 1: "Manual"},
    "SceneCaptureType": {0: "Standard", 1: "Landscape", 2: "Portrait",
                         3: "Night"},
    "GPSAltitudeRef": {0: "Above sea level", 1: "Below sea level"},
}
TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8,
              11: 4, 12: 8}
INT_FORMATS = {3: "H", 4: "I", 8: "h", 9: "i", 11: "f", 12: "d"}


class TiffReader:
    """Minimal, bounds-checked TIFF/EXIF IFD reader."""

    def __init__(self, data):
        self.d = data
        if data[:2] == b"II":
            self.e = "<"
        elif data[:2] == b"MM":
            self.e = ">"
        else:
            raise ValueError("not a TIFF header")
        if len(data) < 8 or struct.unpack_from(self.e + "H", data, 2)[0] != 42:
            raise ValueError("bad TIFF magic number")
        self.seen = set()

    def first_ifd(self):
        return struct.unpack_from(self.e + "I", self.d, 4)[0]

    def read_ifd(self, off):
        """Return ({tag: (type, count, raw_bytes)}, next_ifd_offset)."""
        d = self.d
        if off in self.seen or off < 8 or off + 2 > len(d):
            return {}, 0
        self.seen.add(off)
        count = struct.unpack_from(self.e + "H", d, off)[0]
        if count > 2000:
            return {}, 0
        entries = {}
        for i in range(count):
            p = off + 2 + i * 12
            if p + 12 > len(d):
                break
            tag, typ, cnt = struct.unpack_from(self.e + "HHI", d, p)
            size = TYPE_SIZES.get(typ)
            if size is None:
                continue
            total = size * cnt
            if total > 32 * 1024 * 1024:
                continue
            vo = p + 8 if total <= 4 else struct.unpack_from(self.e + "I", d, p + 8)[0]
            if vo + total > len(d):
                continue
            entries[tag] = (typ, cnt, d[vo:vo + total])
        nxt = off + 2 + count * 12
        next_ifd = struct.unpack_from(self.e + "I", d, nxt)[0] if nxt + 4 <= len(d) else 0
        return entries, next_ifd

    def decode(self, typ, cnt, raw):
        if typ == 2:
            return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()
        if typ in (1, 6, 7):
            return raw
        if typ in (5, 10):
            f = "I" if typ == 5 else "i"
            nums = struct.unpack(self.e + f * (2 * cnt), raw)
            return [(nums[i], nums[i + 1]) for i in range(0, len(nums), 2)]
        return list(struct.unpack(self.e + INT_FORMATS[typ] * cnt, raw))


def _num(x):
    if isinstance(x, tuple):
        return 0.0 if x[1] == 0 else x[0] / x[1]
    return x


def fmt_value(name, val):
    """Turn a decoded EXIF value into something a person can read."""
    if isinstance(val, bytes):
        if name == "MakerNote":
            return f"<{len(val)} bytes, vendor-specific>"
        if name in ("UserComment", "GPSProcessingMethod"):
            enc = "utf-16" if val[:7] == b"UNICODE" else "utf-8"
            body = val[8:] if len(val) >= 8 else val
            return body.decode(enc, "replace").strip("\x00 ").strip()
        if name == "GPSVersionID":
            return ".".join(str(b) for b in val)
        if name.endswith("Version"):
            return val.decode("ascii", "replace").strip("\x00")
        if name in ENUMS and len(val) == 1:
            val = [val[0]]
        else:
            return val.hex() if len(val) <= 32 else f"<{len(val)} bytes>"
    if isinstance(val, str):
        return val
    if not val:
        return ""
    if len(val) == 1:
        v = val[0]
        if name in ENUMS and isinstance(v, int):
            return ENUMS[name].get(v, str(v))
        if name == "Flash" and isinstance(v, int):
            return "Fired" if v & 1 else "Did not fire"
        if name == "ExposureTime" and isinstance(v, tuple) and 0 < v[0] < v[1]:
            return f"1/{round(v[1] / v[0])} s"
        if name == "FNumber":
            return f"f/{_num(v):.1f}"
        if name == "FocalLength":
            return f"{_num(v):g} mm"
        if name == "GPSAltitude":
            return f"{_num(v):.1f} m"
    if name in ("GPSLatitude", "GPSLongitude") and len(val) == 3:
        d, m, s = (_num(x) for x in val)
        return f"{d:g}\u00b0 {m:g}' {s:.2f}\""
    if name == "GPSTimeStamp" and len(val) == 3:
        h, m, s = (_num(x) for x in val)
        return f"{int(h):02d}:{int(m):02d}:{s:05.2f} UTC"
    if len(val) > 16:
        return f"<{len(val)} values>"
    return ", ".join(f"{_num(x):.6g}" if isinstance(x, (tuple, float)) else str(x)
                     for x in val)


def handle_tiff(data, rec, ctx, all_tags=False, label="EXIF"):
    """Parse a TIFF/EXIF block into rec sections; stash raw values in ctx."""
    try:
        t = TiffReader(data)
    except (ValueError, struct.error) as e:
        rec["errors"].append(f"{label}: {e}")
        return
    raw = ctx.setdefault("exif", {})
    exif_sec = section(rec, label)
    gps_sec = section(rec, "GPS")

    def walk(entries, table, sec):
        for tag, (typ, cnt, rb) in sorted(entries.items()):
            if tag in SUB_IFD_POINTERS:
                continue
            name = table.get(tag)
            if name is None:
                if not all_tags:
                    continue
                name = f"Tag0x{tag:04X}"
            try:
                val = t.decode(typ, cnt, rb)
            except struct.error:
                continue
            raw[name] = val
            sec[name] = fmt_value(name, val)

    def pointer(entries, tag):
        if tag not in entries:
            return 0
        try:
            v = t.decode(*entries[tag])
            return v[0] if isinstance(v, list) and v else 0
        except struct.error:
            return 0

    try:
        ifd0, next_ifd = t.read_ifd(t.first_ifd())
        walk(ifd0, EXIF_TAGS, exif_sec)
        exif_off = pointer(ifd0, 0x8769)
        if exif_off:
            walk(t.read_ifd(exif_off)[0], EXIF_TAGS, exif_sec)
        gps_off = pointer(ifd0, 0x8825)
        if gps_off:
            walk(t.read_ifd(gps_off)[0], GPS_TAGS, gps_sec)
        if next_ifd:
            ifd1, _ = t.read_ifd(next_ifd)
            off, length = pointer(ifd1, 0x0201), pointer(ifd1, 0x0202)
            if off and length and off + length <= len(data):
                ctx["thumb"] = data[off:off + length]
    except struct.error as e:
        rec["errors"].append(f"{label}: truncated data ({e})")


def gps_decimal(raw):
    def conv(v, ref):
        if not isinstance(v, list) or len(v) < 3:
            return None
        d, m, s = (_num(x) for x in v[:3])
        x = d + m / 60 + s / 3600
        return round(-x if ref in ("S", "W") else x, 7)

    lat = conv(raw.get("GPSLatitude"), raw.get("GPSLatitudeRef"))
    lon = conv(raw.get("GPSLongitude"), raw.get("GPSLongitudeRef"))
    if lat is None or lon is None or (lat == 0 and lon == 0):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return lat, lon


# --------------------------------------------------------------------------
# XMP
# --------------------------------------------------------------------------

XMP_HEADER = b"http://ns.adobe.com/xap/1.0/\x00"
XMP_FIELDS = [
    "xmp:CreatorTool", "xmp:CreateDate", "xmp:ModifyDate", "xmp:MetadataDate",
    "photoshop:DateCreated", "dc:creator", "dc:title", "dc:description",
    "dc:rights", "photoshop:Credit", "photoshop:City", "photoshop:Country",
    "Iptc4xmpCore:Location", "Iptc4xmpExt:DigitalSourceType",
    "exif:GPSLatitude", "exif:GPSLongitude", "aux:SerialNumber",
    "aux:Lens", "exifEX:BodySerialNumber", "xmpMM:DocumentID",
    "xmpMM:OriginalDocumentID", "xmpMM:InstanceID", "pdf:Producer",
    "pdf:Keywords",
]


def handle_xmp(text, rec, ctx):
    sec = section(rec, "XMP")
    ctx["xmp_text"] = ctx.get("xmp_text", "") + text
    for f in XMP_FIELDS:
        val = None
        m = re.search(re.escape(f) + r'="([^"]*)"', text)
        if m:
            val = m.group(1)
        else:
            m = re.search(r"<" + re.escape(f) + r"\b[^>]*>(.*?)</" + re.escape(f) + ">",
                          text, re.S)
            if m:
                items = re.findall(r"<rdf:li[^>]*>(.*?)</rdf:li>", m.group(1), re.S)
                val = "; ".join(i.strip() for i in items) if items else m.group(1).strip()
        if val:
            sec[f] = html.unescape(re.sub(r"<[^>]+>", "", val)).strip()

    # Edit history: each <rdf:li stEvt:action=... stEvt:softwareAgent=...>
    hist = re.search(r"<xmpMM:History>(.*?)</xmpMM:History>", text, re.S)
    if hist:
        n = 0
        for attrs in re.findall(r"<rdf:li\b([^>]*)>", hist.group(1)):
            a = dict(re.findall(r'stEvt:(\w+)="([^"]*)"', attrs))
            if not a:
                continue
            n += 1
            parts = [a.get("when", ""), a.get("action", ""),
                     ("by " + a["softwareAgent"]) if a.get("softwareAgent") else "",
                     ("(" + a["changed"] + ")") if a.get("changed") else ""]
            sec[f"History {n}"] = html.unescape(" ".join(p for p in parts if p))
            if a.get("softwareAgent"):
                ctx.setdefault("software", []).append(html.unescape(a["softwareAgent"]))
    if sec.get("xmp:CreatorTool"):
        ctx.setdefault("software", []).append(sec["xmp:CreatorTool"])


# --------------------------------------------------------------------------
# Format parsers
# --------------------------------------------------------------------------

SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
               0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def jpeg_walk(data):
    """Yield (marker, payload, offset) for header segments; stop at SOS."""
    i, n = 2, len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            yield ("error", i, None)
            return
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD8 or 0xD0 <= m <= 0xD7 or m == 0x01:
            i += 2
            continue
        if m == 0xD9:
            return
        seglen = struct.unpack_from(">H", data, i + 2)[0]
        if seglen < 2:
            yield ("error", i, None)
            return
        if i + 2 + seglen > n:
            yield (m, data[i + 4:], i)  # parse what survives
            yield ("truncated", i, None)
            return
        yield (m, data[i + 4:i + 2 + seglen], i)
        if m == 0xDA:
            return
        i += 2 + seglen


def jpeg_dims(data):
    for m, p, _ in jpeg_walk(data):
        if m in SOF_MARKERS and len(p) >= 5:
            h, w = struct.unpack(">HH", p[1:5])
            return w, h
    return None


def parse_jpeg(data, rec, ctx, opts):
    sec = section(rec, "JPEG")
    sos = None
    for m, p, off in jpeg_walk(data):
        if m == "error":
            rec["errors"].append(f"JPEG: marker structure broken at offset {p}")
            break
        if m == "truncated":
            ctx["truncated"] = True
            rec["findings"].append(f"JPEG is truncated - a segment at offset {p:,} runs "
                                   f"past the end of the file (incomplete copy or carved file?)")
            break
        if m == 0xDA:
            sos = off
        elif m == 0xE0 and p.startswith(b"JFIF\x00") and len(p) >= 7:
            sec["JFIF version"] = f"{p[5]}.{p[6]:02d}"
        elif m == 0xE1 and p.startswith(b"Exif\x00\x00"):
            handle_tiff(p[6:], rec, ctx, opts.all_tags)
        elif m == 0xE1 and p.startswith(XMP_HEADER):
            handle_xmp(p[len(XMP_HEADER):].decode("utf-8", "replace"), rec, ctx)
        elif m == 0xE2 and p.startswith(b"MPF\x00"):
            ctx["mpf"] = True
            sec["Multi-picture (MPF)"] = "present (extra images stored after the main one)"
        elif m == 0xE2 and p.startswith(b"ICC_PROFILE\x00"):
            sec["ICC profile"] = "present"
        elif m == 0xED and p.startswith(b"Photoshop 3.0\x00"):
            sec["Photoshop/IPTC block"] = f"present ({len(p)} bytes)"
        elif m == 0xFE:
            sec["Comment"] = p.decode("utf-8", "replace").strip("\x00 ")
        elif m in SOF_MARKERS and len(p) >= 5:
            h, w = struct.unpack(">HH", p[1:5])
            sec["Dimensions"] = f"{w} x {h}"
            sec["Encoding"] = "Progressive" if m in (0xC2, 0xC6, 0xCA, 0xCE) else "Baseline"
            ctx["dims"] = (w, h)
    if sos is not None:
        eoi = data.find(b"\xff\xd9", sos)
        if eoi != -1 and eoi + 2 < len(data):
            ctx["trailing"] = (eoi + 2, data[eoi + 2:])


def parse_png(data, rec, ctx, opts):
    sec = section(rec, "PNG")
    text = section(rec, "PNG text")
    i, n = 8, len(data)
    while i + 8 <= n:
        length, ctype = struct.unpack_from(">I4s", data, i)
        body = data[i + 8:i + 8 + length]
        if ctype == b"IHDR" and len(body) >= 8:
            w, h = struct.unpack(">II", body[:8])
            sec["Dimensions"] = f"{w} x {h}"
            ctx["dims"] = (w, h)
        elif ctype in (b"tEXt", b"zTXt", b"iTXt"):
            key, _, rest = body.partition(b"\x00")
            key = key.decode("latin-1")
            if ctype == b"tEXt":
                val = rest.decode("latin-1", "replace")
            elif ctype == b"zTXt":
                val = inflate(rest[1:]).decode("latin-1", "replace")
            else:
                compressed = rest[:1] == b"\x01"
                rest = rest[2:]
                _lang, _, rest = rest.partition(b"\x00")
                _tkey, _, txt = rest.partition(b"\x00")
                val = (inflate(txt) if compressed else txt).decode("utf-8", "replace")
            if key == "XML:com.adobe.xmp":
                handle_xmp(val, rec, ctx)
            else:
                text[key] = val
                if key.lower() == "software":
                    ctx.setdefault("software", []).append(val)
                if key.lower() in ("parameters", "prompt", "workflow", "dream", "sd-metadata"):
                    ctx["ai_png_key"] = key
        elif ctype == b"eXIf":
            handle_tiff(body, rec, ctx, opts.all_tags)
        elif ctype == b"tIME" and len(body) >= 7:
            y, mo, d, hh, mi, s = struct.unpack(">HBBBBB", body[:7])
            sec["Last modified (tIME)"] = f"{y:04d}-{mo:02d}-{d:02d} {hh:02d}:{mi:02d}:{s:02d} UTC"
        elif ctype == b"pHYs" and len(body) >= 9:
            px, py, unit = struct.unpack(">IIB", body[:9])
            if unit == 1:
                sec["Resolution"] = f"{px * 0.0254:.0f} x {py * 0.0254:.0f} dpi"
        elif ctype == b"iCCP":
            sec["ICC profile"] = body.partition(b"\x00")[0].decode("latin-1")
        elif ctype == b"caBX":
            ctx["c2pa"] = True
        elif ctype == b"IEND":
            end = i + 12 + length
            if end < n:
                ctx["trailing"] = (end, data[end:])
            break
        i += 12 + length


def parse_tiff_file(data, rec, ctx, opts):
    handle_tiff(data, rec, ctx, opts.all_tags)
    raw = ctx.get("exif", {})
    w, h = raw.get("ImageWidth"), raw.get("ImageHeight")
    if isinstance(w, list) and isinstance(h, list) and w and h:
        ctx["dims"] = (w[0], h[0])
    # XMP lives in tag 700 for TIFF; a byte search is simpler and good enough
    m = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.S)
    if m:
        handle_xmp(m.group(0).decode("utf-8", "replace"), rec, ctx)


def parse_webp(data, rec, ctx, opts):
    sec = section(rec, "WebP")
    i, n = 12, len(data)
    while i + 8 <= n:
        fourcc, size = struct.unpack_from("<4sI", data, i)
        body = data[i + 8:i + 8 + size]
        if fourcc == b"VP8X" and len(body) >= 10:
            w = 1 + int.from_bytes(body[4:7], "little")
            h = 1 + int.from_bytes(body[7:10], "little")
            sec["Dimensions"] = f"{w} x {h}"
            ctx["dims"] = (w, h)
        elif fourcc == b"EXIF":
            handle_tiff(body[6:] if body.startswith(b"Exif\x00\x00") else body,
                        rec, ctx, opts.all_tags)
        elif fourcc == b"XMP ":
            handle_xmp(body.decode("utf-8", "replace"), rec, ctx)
        i += 8 + size + (size & 1)


def parse_heif(data, rec, ctx, opts):
    # Best effort: HEIC stores EXIF as an item whose payload starts with
    # "Exif\0\0" followed by a TIFF header, so search for that directly.
    section(rec, "HEIF")["Parsing"] = "best effort (EXIF/XMP located by signature)"
    m = re.search(rb"Exif\x00\x00(II\*\x00|MM\x00\*)", data[:16 * 1024 * 1024])
    if m:
        handle_tiff(data[m.start() + 6:], rec, ctx, opts.all_tags)
    x = re.search(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.S)
    if x:
        handle_xmp(x.group(0).decode("utf-8", "replace"), rec, ctx)


# ---- PDF -----------------------------------------------------------------

PDF_INFO_KEYS = ["Title", "Author", "Subject", "Keywords", "Creator",
                 "Producer", "CreationDate", "ModDate"]
PDF_RISK_NAMES = {
    "JavaScript": "embedded JavaScript", "JS": "embedded JavaScript",
    "OpenAction": "an action that runs when the file opens",
    "AA": "automatic actions", "Launch": "a Launch action (can start programs)",
    "EmbeddedFile": "embedded files", "SubmitForm": "a form that submits data",
    "RichMedia": "rich media (Flash/video)", "XFA": "an XFA form",
}
PDF_ESCAPES = {ord("n"): b"\n", ord("r"): b"\r", ord("t"): b"\t",
               ord("b"): b"\b", ord("f"): b"\f", ord("("): b"(",
               ord(")"): b")", ord("\\"): b"\\"}


def pdf_string(data, pos):
    """Decode a PDF literal (...) or hex <...> string starting at pos."""
    if data[pos:pos + 1] == b"(":
        out, depth, i = bytearray(), 0, pos
        while i < len(data) and i - pos < 65536:
            c = data[i]
            if c == 0x5C and i + 1 < len(data):
                nxt = data[i + 1]
                if nxt in PDF_ESCAPES:
                    out += PDF_ESCAPES[nxt]
                    i += 2
                    continue
                m = re.match(rb"[0-7]{1,3}", data[i + 1:i + 4])
                if m:
                    out.append(int(m.group(), 8) & 0xFF)
                    i += 1 + len(m.group())
                    continue
                i += 2  # line continuation or unknown escape
                continue
            if c == 0x28:
                depth += 1
                if depth > 1:
                    out.append(c)
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    break
                out.append(c)
            else:
                out.append(c)
            i += 1
        raw = bytes(out)
    else:
        end = data.find(b">", pos)
        hexstr = re.sub(rb"\s", b"", data[pos + 1:end])
        if len(hexstr) % 2:
            hexstr += b"0"
        try:
            raw = bytes.fromhex(hexstr.decode("ascii"))
        except ValueError:
            return ""
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", "replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace")
    return raw.decode("latin-1")


def pdf_date(s):
    m = re.match(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+\-])?(\d{2})?'?(\d{2})?", s)
    if not m:
        return s
    y, mo, d, h, mi, sec, tz, th, tm = m.groups()
    out = f"{y}-{mo or '01'}-{d or '01'} {h or '00'}:{mi or '00'}:{sec or '00'}"
    if tz == "Z":
        out += " UTC"
    elif tz:
        out += f" {tz}{th or '00'}:{tm or '00'}"
    return out


def parse_pdf(data, rec, ctx, opts):
    sec = section(rec, "PDF")
    F = rec["findings"]
    m = re.match(rb"%PDF-(\d\.\d)", data)
    if m:
        sec["Version"] = m.group(1).decode()
    sec["Pages (approx.)"] = str(len(re.findall(rb"/Type\s*/Page\b", data)))
    eofs = data.count(b"%%EOF")
    sec["Revisions (%%EOF markers)"] = str(eofs)
    if b"/Encrypt" in data:
        sec["Encrypted"] = "yes (metadata strings may be unreadable)"
    if b"/ByteRange" in data and b"/Sig" in data:
        sec["Digital signature"] = "present"

    # Document Info dictionaries: one per revision when edited incrementally.
    history = {k: [] for k in PDF_INFO_KEYS}
    refs = []
    for r in re.findall(rb"/Info\s+(\d+)\s+(\d+)\s+R", data):
        if r not in refs:
            refs.append(r)
    bodies = []
    for num, gen in refs:
        pat = rb"(?<![0-9])" + num + rb"\s+" + gen + rb"\s+obj\b(.*?)endobj"
        for om in re.finditer(pat, data, re.S):
            bodies.append((om.start(1), om.group(1)))
    bodies.sort()
    for start, body in bodies:
        for key in PDF_INFO_KEYS:
            km = re.search(rb"/" + key.encode() + rb"\s*(\(|<(?!<))", body)
            if km:
                val = pdf_string(data, start + km.start(1)).strip("\x00 ")
                if key in ("CreationDate", "ModDate"):
                    val = pdf_date(val)
                if val and (not history[key] or history[key][-1] != val):
                    history[key].append(val)
    for key in PDF_INFO_KEYS:
        vals = history[key]
        if vals:
            sec[key] = vals[-1]
            if len(vals) > 1:
                sec[key + " (earlier values)"] = " | ".join(vals[:-1])
                if key != "ModDate":  # ModDate is expected to change on every save
                    F.append(f"PDF {key} changed between revisions: "
                             f"{' -> '.join(vals)}")

    xm = re.findall(rb"<x:xmpmeta.*?</x:xmpmeta>", data, re.S)
    if xm:
        handle_xmp(xm[-1].decode("utf-8", "replace"), rec, ctx)

    if eofs > 1:
        F.append(f"PDF was saved {eofs} times incrementally - earlier versions "
                 f"of the content may still be recoverable from the file")
    if sec.get("CreationDate") and sec.get("ModDate") and \
            sec["CreationDate"][:19] != sec["ModDate"][:19]:
        F.append(f"PDF modified after creation ({sec['CreationDate']} -> {sec['ModDate']})")

    found = []
    for name, desc in PDF_RISK_NAMES.items():
        if re.search(rb"/" + name.encode() + rb"(?![A-Za-z])", data) and desc not in found:
            found.append(desc)
    if found:
        sec["Active content"] = ", ".join(found)
        F.append("PDF contains " + ", ".join(found) + " - review before opening")
    if re.search(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}", data):
        F.append("PDF uses hex-escaped names (#xx) - a common obfuscation trick")

    last = data.rfind(b"%%EOF")
    if last != -1:
        tail = data[last + 5:]
        if tail.strip(b"\r\n\x00 "):
            ctx["trailing"] = (last + 5, tail)


# ---- Office (OOXML / OpenDocument) ----------------------------------------

def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _xml(z, name, limit=5 * 1024 * 1024):
    try:
        if z.getinfo(name).file_size > limit:
            return None
        return ET.fromstring(z.read(name))
    except (KeyError, ET.ParseError, zipfile.BadZipFile, RuntimeError):
        return None


def parse_zip(path, rec, ctx, opts):
    F = rec["findings"]
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        rec["errors"].append(f"ZIP: {e}")
        return
    with z:
        names = set(z.namelist())
        sec = section(rec, "Document")
        if "docProps/core.xml" in names or "[Content_Types].xml" in names:
            rec["type"] = "office (OOXML)"
            core = _xml(z, "docProps/core.xml")
            if core is not None:
                for el in core:
                    if el.text and el.text.strip():
                        sec[_local(el.tag)] = el.text.strip()
            app = _xml(z, "docProps/app.xml")
            if app is not None:
                for el in app:
                    if el.text and el.text.strip() and len(el) == 0:
                        sec[_local(el.tag)] = el.text.strip()
            custom = _xml(z, "docProps/custom.xml")
            if custom is not None:
                for prop in custom:
                    val = next((c.text for c in prop if c.text), None)
                    if prop.get("name") and val:
                        sec["custom: " + prop.get("name")] = val
            macros = sorted(n for n in names if n.lower().endswith("vbaproject.bin"))
            if macros:
                sec["Macros"] = ", ".join(macros)
                F.append("Document contains VBA macros (" + ", ".join(macros) + ")")
            ext = [n for n in names if "externalLinks/" in n or n.endswith("oleObject1.bin")]
            if ext:
                F.append("Document contains external links or embedded OLE objects")
            for rels in (n for n in names if n.endswith(".rels")):
                try:
                    if z.getinfo(rels).file_size < 1024 * 1024 and \
                            b'TargetMode="External"' in z.read(rels) and \
                            b"attachedTemplate" in z.read(rels):
                        F.append("Document loads a remote template (seen in template-injection attacks)")
                        break
                except (KeyError, RuntimeError):
                    pass
            creator, modifier = sec.get("creator"), sec.get("lastModifiedBy")
            if creator and modifier and creator != modifier:
                F.append(f"Created by '{creator}' but last modified by '{modifier}'")
            if sec.get("Template") and sec["Template"].lower() not in ("normal.dotm", "normal"):
                F.append(f"Built from template: {sec['Template']}")
        elif "meta.xml" in names:
            rec["type"] = "office (OpenDocument)"
            meta = _xml(z, "meta.xml")
            if meta is not None:
                for el in meta.iter():
                    if el.text and el.text.strip() and len(el) == 0 and _local(el.tag) != "meta":
                        sec[_local(el.tag)] = el.text.strip()
                    if _local(el.tag) == "document-statistic":
                        for k, v in el.attrib.items():
                            sec[_local(k)] = v
            if any(n.startswith("Basic/") or n.startswith("Scripts/") for n in names):
                F.append("Document contains macros/scripts")
            c, m = sec.get("initial-creator"), sec.get("creator")
            if c and m and c != m:
                F.append(f"Created by '{c}' but last modified by '{m}'")
        else:
            rec["type"] = "zip"
            sec["Entries"] = str(len(names))
            stamps = [dt.datetime(*i.date_time) for i in z.infolist()
                      if i.date_time[0] >= 1980]
            if stamps:
                sec["Oldest entry"] = min(stamps).isoformat(sep=" ")
                sec["Newest entry"] = max(stamps).isoformat(sep=" ")
            if z.comment:
                sec["Archive comment"] = z.comment.decode("utf-8", "replace")


PARSERS = {"jpeg": parse_jpeg, "png": parse_png, "tiff": parse_tiff_file,
           "webp": parse_webp, "heif": parse_heif, "pdf": parse_pdf}


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

EDITORS = ["photoshop", "lightroom", "gimp", "snapseed", "picsart", "facetune",
           "affinity", "pixelmator", "paint.net", "canva", "luminar",
           "capture one", "darktable", "rawtherapee", "afterlight", "vsco",
           "fotor", "polarr", "meitu", "airbrush", "photopea", "krita",
           "acdsee", "topaz", "remini", "faceapp", "lensa", "photoroom"]
IMAGE_TYPES = {"jpeg", "png", "tiff", "webp", "heif"}


def section(rec, name):
    return rec["sections"].setdefault(name, {})


def inflate(blob):
    try:
        return zlib.decompressobj().decompress(blob, MAX_INFLATE)
    except zlib.error:
        return b""


def ts(t):
    return dt.datetime.fromtimestamp(t).astimezone().isoformat(sep=" ", timespec="seconds")


def file_section(rec, path, st, data, opts):
    sec = section(rec, "File")
    sec["Path"] = os.path.abspath(path)
    sec["Size"] = f"{st.st_size:,} bytes"
    sec["Detected type"] = rec["type"]
    sec["Modified"] = ts(st.st_mtime)
    sec["Accessed"] = ts(st.st_atime)
    if hasattr(st, "st_birthtime"):
        sec["Created"] = ts(st.st_birthtime)
        sec["Metadata changed"] = ts(st.st_ctime)
    elif os.name == "nt":
        sec["Created"] = ts(st.st_ctime)
    else:
        sec["Inode changed"] = ts(st.st_ctime)
    if not opts.no_hash:
        h = hashlib.sha256()
        if data is not None:
            h.update(data)
        else:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
        sec["SHA-256"] = h.hexdigest()


def post_analyze(rec, ctx, data, opts):
    F = rec["findings"]
    ftype = rec["type"]
    raw = ctx.get("exif", {})
    path = rec["file"]

    ext = os.path.splitext(path)[1].lower()
    expected = EXPECTED_EXT.get(ftype if ftype in EXPECTED_EXT else "zip"
                                if ftype.startswith("office") else ftype)
    if ext and expected and ext not in expected:
        F.append(f"Extension '{ext}' does not match the file's contents ({ftype})")

    gps = gps_decimal(raw)
    if gps:
        lat, lon = gps
        g = section(rec, "GPS")
        g["Decimal"] = f"{lat}, {lon}"
        g["Map"] = f"https://www.google.com/maps?q={lat},{lon}"
        ctx["gps"] = gps
        F.append(f"GPS location embedded: {lat}, {lon}")

    if ftype in IMAGE_TYPES:
        for sw in dict.fromkeys(ctx.get("software", []) +
                                ([raw["Software"]] if isinstance(raw.get("Software"), str) else [])):
            hit = next((e for e in EDITORS if e in sw.lower()), None)
            if hit:
                F.append(f"Processed with editing software: {sw}")

        dto, dtm = raw.get("DateTimeOriginal"), raw.get("DateTime")
        if isinstance(dto, str) and isinstance(dtm, str) and dto and dtm and dto != dtm:
            F.append(f"Modified after capture (taken {dto}, last saved {dtm})")

        ids = [f"{k}={raw[k]}" for k in ("BodySerialNumber", "LensSerialNumber",
                                          "CameraOwnerName") if raw.get(k)]
        if section(rec, "XMP").get("aux:SerialNumber"):
            ids.append("aux:SerialNumber=" + rec["sections"]["XMP"]["aux:SerialNumber"])
        if ids:
            F.append("Device-identifying details present: " + ", ".join(ids))

        if not raw and not ctx.get("xmp_text") and not rec["sections"].get("PNG text") \
                and not ctx.get("truncated"):
            F.append("No EXIF or XMP metadata - it may have been stripped "
                     "(typical of social media and messaging apps)")

        thumb = ctx.get("thumb")
        if thumb:
            section(rec, "EXIF")["Embedded thumbnail"] = f"{len(thumb):,} bytes"
            F.append("Embedded thumbnail present - it can show the image as it "
                     "looked before later edits")
            td, md = jpeg_dims(thumb) if thumb.startswith(b"\xff\xd8") else None, ctx.get("dims")
            if td and md and td[1] and md[1]:
                r1, r2 = td[0] / td[1], md[0] / md[1]
                if abs(r1 - r2) / r2 > 0.05 and abs(r1 - 1 / r2) / (1 / r2) > 0.05:
                    F.append(f"Thumbnail shape ({td[0]}x{td[1]}) does not match the image "
                             f"({md[0]}x{md[1]}) - the image may have been cropped")
            if opts.thumbs:
                os.makedirs(opts.thumbs, exist_ok=True)
                base = os.path.basename(path)
                out = os.path.join(opts.thumbs, base + ".thumb.jpg")
                n = 1
                while os.path.exists(out):
                    out = os.path.join(opts.thumbs, f"{base}.thumb{n}.jpg")
                    n += 1
                with open(out, "wb") as f:
                    f.write(thumb)
                section(rec, "EXIF")["Thumbnail saved to"] = out

        if ctx.get("ai_png_key"):
            F.append(f"PNG text chunk '{ctx['ai_png_key']}' looks like AI image-generator settings")

    if data is not None:
        if b"trainedAlgorithmicMedia" in data:
            F.append("Labelled as AI-generated (IPTC digital source type 'trainedAlgorithmicMedia')")
        if ctx.get("c2pa") or (b"c2pa" in data and b"jumb" in data):
            F.append("Content Credentials (C2PA) manifest present - verify it with a C2PA tool")

    if ctx.get("trailing"):
        off, tail = ctx["trailing"]
        what = name_signature(tail)
        desc = f"{len(tail):,} bytes of data after the end of the file at offset {off:,}"
        if what:
            desc += f" (looks like: {what})"
        if ftype == "jpeg" and ctx.get("mpf"):
            desc += " - expected here, MPF says extra images are stored there"
        F.append(desc)


def analyze(path, opts):
    rec = {"file": path, "type": None, "sections": {}, "findings": [], "errors": []}
    ctx = {}
    try:
        st = os.stat(path)
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError as e:
        rec["type"] = "unreadable"
        rec["errors"].append(str(e))
        return rec, ctx
    rec["type"] = detect_type(head)
    rec["sections"]["File"] = {}  # keep File first in output

    data = None
    if rec["type"] in PARSERS:
        if st.st_size > MAX_READ:
            rec["errors"].append(f"file larger than {MAX_READ // 2**20} MB, metadata not parsed")
        else:
            with open(path, "rb") as f:
                data = f.read()
            try:
                PARSERS[rec["type"]](data, rec, ctx, opts)
            except Exception as e:  # malformed input should never kill a batch run
                rec["errors"].append(f"parser error: {type(e).__name__}: {e}")
    elif rec["type"] == "zip":
        parse_zip(path, rec, ctx, opts)
    elif rec["type"] != "unknown":
        rec["errors"].append(f"metadata parsing for {rec['type']} files is not supported yet")

    file_section(rec, path, st, data, opts)
    try:
        post_analyze(rec, ctx, data, opts)
    except Exception as e:
        rec["errors"].append(f"analysis error: {type(e).__name__}: {e}")
    rec["sections"] = {k: v for k, v in rec["sections"].items() if v}
    return rec, ctx


# --------------------------------------------------------------------------
# Input / output
# --------------------------------------------------------------------------

def iter_files(paths, recurse):
    """Yield (path, explicitly_named)."""
    for p in paths:
        if os.path.isdir(p):
            if recurse:
                for root, dirs, files in os.walk(p):
                    dirs.sort()
                    for name in sorted(files):
                        yield os.path.join(root, name), False
            else:
                for name in sorted(os.listdir(p)):
                    full = os.path.join(p, name)
                    if os.path.isfile(full):
                        yield full, False
        elif os.path.exists(p):
            yield p, True
        else:
            print(f"metacheck: {p}: no such file or directory", file=sys.stderr)


def worth_scanning(path):
    try:
        with open(path, "rb") as f:
            t = detect_type(f.read(64))
    except OSError:
        return False
    if t == "zip":
        return os.path.splitext(path)[1].lower() in OFFICE_EXTS
    return t in SUPPORTED


def clip(v, n=400):
    v = v.replace("\r", "").replace("\n", " \u21b5 ")
    return v if len(v) <= n else v[:n] + f"... [{len(v) - n} more chars]"


def write_text(recs, out, findings_only):
    for rec in recs:
        if findings_only and not rec["findings"]:
            continue
        out.write(f"==> {rec['file']}  [{rec['type']}]\n")
        if not findings_only:
            for name, fields in rec["sections"].items():
                out.write(f"  [{name}]\n")
                width = min(max(len(k) for k in fields), 30)
                for k, v in fields.items():
                    out.write(f"    {k:<{width}}  {clip(str(v))}\n")
        if rec["findings"]:
            out.write("  Findings:\n")
            for f in rec["findings"]:
                out.write(f"    ! {f}\n")
        for e in rec["errors"]:
            out.write(f"  (error) {e}\n")
        out.write("\n")


def write_csv(recs, out, findings_only):
    w = csv.writer(out)
    w.writerow(["file", "type", "section", "field", "value"])
    for rec in recs:
        if not findings_only:
            for name, fields in rec["sections"].items():
                for k, v in fields.items():
                    w.writerow([rec["file"], rec["type"], name, k, v])
        for f in rec["findings"]:
            w.writerow([rec["file"], rec["type"], "Findings", "finding", f])
        for e in rec["errors"]:
            w.writerow([rec["file"], rec["type"], "Errors", "error", e])


def write_json(recs, out, findings_only):
    if findings_only:
        recs = [{"file": r["file"], "type": r["type"], "findings": r["findings"]}
                for r in recs if r["findings"]]
    json.dump(recs, out, indent=2, ensure_ascii=False)
    out.write("\n")


def write_kml(points, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>\n'
                '<name>metacheck GPS export</name>\n')
        for file, (lat, lon), when in points:
            f.write(f"<Placemark><name>{xml_escape(os.path.basename(file))}</name>"
                    f"<description>{xml_escape(file)}"
                    f"{(' - ' + xml_escape(when)) if when else ''}</description>"
                    f"<Point><coordinates>{lon},{lat},0</coordinates></Point></Placemark>\n")
        f.write("</Document></kml>\n")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="metacheck",
        description="Forensic metadata extractor for images, PDFs and Office documents.",
        epilog="examples:\n"
               "  metacheck.py photo.jpg\n"
               "  metacheck.py ~/Evidence --findings-only\n"
               "  metacheck.py ~/Evidence -f csv -o metadata.csv --kml locations.kml\n"
               "  metacheck.py photo.jpg --thumbs thumbs/",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="files or folders to examine")
    ap.add_argument("-n", "--no-recurse", action="store_true",
                    help="don't descend into subfolders")
    ap.add_argument("-f", "--format", choices=["text", "csv", "json"], default="text",
                    help="output format (default: text)")
    ap.add_argument("-o", "--output", help="write the report to this file instead of the screen")
    ap.add_argument("--findings-only", action="store_true",
                    help="only show files with findings, and only the findings")
    ap.add_argument("--thumbs", metavar="DIR",
                    help="save embedded EXIF thumbnails into DIR")
    ap.add_argument("--kml", metavar="FILE",
                    help="write every GPS location found to a KML file (Google Earth)")
    ap.add_argument("--all-tags", action="store_true",
                    help="include unnamed EXIF tags as Tag0xNNNN")
    ap.add_argument("--no-hash", action="store_true", help="skip SHA-256 hashing")
    ap.add_argument("-V", "--version", action="version", version=f"metacheck {__version__}")
    opts = ap.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    recs, points, skipped = [], [], 0
    for path, explicit in iter_files(opts.paths, not opts.no_recurse):
        if not explicit and not worth_scanning(path):
            skipped += 1
            continue
        rec, ctx = analyze(path, opts)
        recs.append(rec)
        if ctx.get("gps"):
            when = ctx.get("exif", {}).get("DateTimeOriginal")
            points.append((path, ctx["gps"], when if isinstance(when, str) else ""))

    writer = {"text": write_text, "csv": write_csv, "json": write_json}[opts.format]
    if opts.output:
        with open(opts.output, "w", encoding="utf-8", newline="") as out:
            writer(recs, out, opts.findings_only)
    else:
        writer(recs, sys.stdout, opts.findings_only)

    if opts.kml:
        write_kml(points, opts.kml)

    flagged = sum(1 for r in recs if r["findings"])
    summary = f"metacheck: {len(recs)} file(s) examined, {flagged} with findings"
    if skipped:
        summary += f", {skipped} unsupported file(s) skipped"
    if opts.kml:
        summary += f", {len(points)} location(s) written to {opts.kml}"
    if opts.output:
        summary += f", report saved to {opts.output}"
    print(summary, file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # output piped into head/less and closed early
        sys.stderr.close()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
