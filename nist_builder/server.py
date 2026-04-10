#!/usr/bin/env python3
"""
NIST biometric file builder – MCP server.

Exposes tools for constructing and manipulating NIST ANSI/NIST-ITL 1-2011
(Update 2015) transactions in Traditional encoding.

Usage (Claude Code MCP config):
  {
    "mcpServers": {
      "nist-builder": {
        "command": "python3",
        "args": ["/home/mweerden/Nist/mcp-nist-builder/server.py"]
      }
    }
  }
"""

import base64
import io
import struct
from datetime import date
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from nist_builder.encoder import (
    build_type1,
    build_type2,
    build_type3, build_type5, build_type6,   # legacy binary fingerprints
    build_type4,
    build_type9,
    build_type10,
    build_type13,                             # latent friction ridge
    build_type14,
    build_type15,
    build_type16,                             # user-defined variable-res
    build_type17,
    build_type19,                             # plantar
    build_variable_res_record,               # generic variable-res builder
    assemble_transaction,
    # constants
    IMP_LIVE_SCAN_PLAIN, IMP_LIVE_SCAN_ROLLED, IMP_NONLIVE_PLAIN,
    IMP_NONLIVE_ROLLED, IMP_LATENT_IMAGE, IMP_LATENT_TRACING,
    IMP_LATENT_PHOTO, IMP_LATENT_LIFT, IMP_SWIPE, IMP_UNKNOWN,
    FGP_UNKNOWN, FGP_RIGHT_THUMB, FGP_RIGHT_INDEX, FGP_RIGHT_MIDDLE,
    FGP_RIGHT_RING, FGP_RIGHT_LITTLE, FGP_LEFT_THUMB, FGP_LEFT_INDEX,
    FGP_LEFT_MIDDLE, FGP_LEFT_RING, FGP_LEFT_LITTLE,
    CGA_NONE, CGA_WSQ,
    COMPRESSION_JPEG, COMPRESSION_JPEGL, COMPRESSION_JP2, COMPRESSION_JP2L,
    COMPRESSION_PNG, COMPRESSION_NONE,
    COLOR_SPACE_GRAY, COLOR_SPACE_RGB, COLOR_SPACE_YCC,
    IMAGE_TYPE_FACE, IMAGE_TYPE_SMT, IMAGE_TYPE_SCAR,
)

app = Server("nist-builder")


# ---------------------------------------------------------------------------
# Streaming parser primitives  (shared by decoder and converter)
# ---------------------------------------------------------------------------

_FS, _GS, _RS, _US = 0x1C, 0x1D, 0x1E, 0x1F
_FS_b = bytes([_FS])

# Record classes — all NIST image-bearing types
_BINARY_TYPES       = {3, 4, 5, 6, 7, 8}               # pure binary, LEN in first 4 bytes, no FS
_ASCII_BINARY_TYPES = {10, 13, 14, 15, 16, 17, 19,
                       20, 21, 22, 98, 99}              # ASCII fields + binary field 999

# Sub-sets used for conversion logic
_FP_BINARY_TYPES = {3, 4, 5, 6}   # binary fingerprint types (18-byte header, same layout)
_VARRES_TYPES    = {13, 14, 15, 16, 19}  # variable-res ASCII+Binary family (fields 3-13 / 999)

# Type-4 CGA numeric → compression string used by build_type14
_CGA_STR = {0: "NONE", 1: "WSQ20", 2: "JPEGB", 3: "JPEGL",
            4: "JP2",  5: "JP2L",  7: "PNG"}

# Type-4/7/8 CGA byte → short compression hint for file-extension detection
_BINARY_CGA_HINT = {0: "NONE", 1: "WSQ", 2: "JPEGB", 3: "JPEGL",
                    4: "JP2",  5: "JP2L", 7: "PNG"}

# CGA string → binary CGA byte  (for Types 3-6; WSQ and WSQ20 both map to 1)
_BINARY_CGA_NUM = {"NONE": 0, "WSQ": 1, "WSQ20": 1,
                   "JPEGB": 2, "JPEGL": 3, "JP2": 4, "JP2L": 5, "PNG": 7}

# Allowed CGA strings (upper-case) per record type
# WSQ/WSQ20 both included; checking uses _cga_matches() which treats them as equal.
_ALLOWED_CGA_BY_TYPE: dict[int, set[str]] = {
    3:  {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    4:  {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    5:  {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    6:  {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    7:  {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    8:  {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    10: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    13: {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    14: {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    15: {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    16: {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    17: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},          # no WSQ for iris
    19: {"NONE", "WSQ", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    20: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    21: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    22: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    98: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
    99: {"NONE", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"},
}


def _cga_matches(a: str, b: str) -> bool:
    """True if a and b refer to the same compression (WSQ and WSQ20 are equivalent)."""
    a, b = a.upper(), b.upper()
    if a == b:
        return True
    return a in {"WSQ", "WSQ20"} and b in {"WSQ", "WSQ20"}


def _detect_ext(data: bytes, compression_hint: str = "") -> str:
    """Detect image file extension from magic bytes, falling back to hint string."""
    if len(data) >= 2 and data[:2] == b"\xff\xd8":
        return ".jpg"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return ".png"
    if len(data) >= 2 and data[:2] in (b"\xff\xa0", b"\xff\xa8",
                                        b"\xff\xa4", b"\xff\xa3", b"\xff\xa2"):
        return ".wsq"
    if len(data) >= 8 and data[4:8] == b"jP  ":
        return ".jp2"
    if len(data) >= 2 and data[:2] == b"BM":
        return ".bmp"
    hint = compression_hint.upper()
    if "WSQ"  in hint: return ".wsq"
    if "JPEG" in hint: return ".jpg"
    if "PNG"  in hint: return ".png"
    if "JP2"  in hint: return ".jp2"
    return ".bin"


def _get_ascii_field(rec_bytes: bytes, rt: int, fnum: int) -> str:
    """Return the value of field rt.fnum from an ASCII/ASCII+Binary record."""
    tag    = f"{rt}.{fnum:03d}:".encode()
    gs_tag = bytes([_GS]) + tag
    if rec_bytes.startswith(tag):
        end = rec_bytes.find(bytes([_GS]))
        return rec_bytes[len(tag):(end if end >= 0 else None)].decode(errors="replace")
    idx = rec_bytes.find(gs_tag)
    if idx < 0:
        return ""
    start = idx + 1 + len(tag)
    end   = rec_bytes.find(bytes([_GS]), start)
    return rec_bytes[start:(end if end >= 0 else None)].decode(errors="replace")


def _extract_varres_fields(rec: bytes, rt: int) -> dict[int, str]:
    """
    Extract the standard variable-res fields (3-13) from an ASCII+Binary record.
    Returns {field_number: value_string} – missing fields have empty string values.
    """
    return {fnum: _get_ascii_field(rec, rt, fnum) for fnum in range(3, 14)}


def _extract_img999(rec: bytes, rt: int) -> bytes:
    """Extract the binary payload from field xx.999 of an ASCII+Binary record."""
    tag = bytes([_GS]) + f"{rt}.999:".encode()
    gp  = rec.find(tag)
    return rec[gp + len(tag):] if gp >= 0 else b""


def _varres_from_fields(to_type: int, idc: int,
                        f: dict[int, str], img: bytes) -> bytes:
    """
    Build a variable-res record of *to_type* from a field-dict (keys = field numbers).
    Used by the converter to re-wrap the same image payload in a different record type.
    """
    def _int(key: int, default: int) -> int:
        v = f.get(key, "")
        return int(v) if v else default

    imp = _int(3, IMP_LIVE_SCAN_PLAIN)
    src = f.get(4) or "UNKNOWN"
    dat = f.get(5) or "00000000"
    hll = _int(6, 0);  vll = _int(7, 0)
    slc = _int(8, 1);  hps = _int(9, 500);  vps = _int(10, 500)
    cga = f.get(11) or "NONE"
    bpx = _int(12, 8)
    pos_s = f.get(13, "")
    pos   = int(pos_s) if pos_s else None

    return build_variable_res_record(
        to_type,
        idc=idc, src=src, capture_date=dat,
        hll=hll, vll=vll, scale_units=slc,
        h_pixel_scale=hps, v_pixel_scale=vps,
        compression=cga, image_data=img,
        impression_type=imp, position=pos, bpx=bpx,
    )


def _parse_t1(data: bytes) -> tuple[bytes, int, list[tuple[int, int]]]:
    """
    Parse the Type-1 record (always the first ASCII record).
    Returns (t1_bytes_without_FS, next_pos, [(rt, idc), ...]) where the list
    is derived from the CNT field and covers all records after Type-1.
    """
    fs_pos = data.index(_FS)
    t1 = data[:fs_pos]
    order: list[tuple[int, int]] = []
    for f in t1.split(bytes([_GS])):
        if f.startswith(b"1.003:"):
            # CNT subfields: first is "1<US>00" (Type-1 itself), skip it
            for sf in f[6:].split(bytes([_RS]))[1:]:
                parts = sf.split(bytes([_US]))
                try:
                    order.append((int(parts[0]), int(parts[1]) if len(parts) > 1 else 0))
                except (ValueError, IndexError):
                    pass
            break
    return t1, fs_pos + 1, order


def _parse_binary_record(data: bytes, pos: int) -> tuple[bytes, int]:
    """Pure-binary record (Type 4/7/8): LEN in first 4 bytes, no FS. Returns (rec, next_pos)."""
    rec_len = struct.unpack(">I", data[pos:pos + 4])[0]
    return data[pos:pos + rec_len], pos + rec_len


def _parse_ascii_binary_record(data: bytes, pos: int) -> tuple[bytes, int]:
    """
    ASCII+Binary record: LEN is in the xx.001 field and includes the trailing FS.
    Returns (rec_bytes_WITHOUT_trailing_FS, next_pos_after_FS).
    """
    sep = pos
    while sep < len(data) and data[sep] not in (_FS, _GS):
        sep += 1
    colon = data.index(b":", pos, sep + 1)
    rec_len = int(data[colon + 1:sep])          # LEN includes trailing FS
    return data[pos:pos + rec_len - 1], pos + rec_len


def _parse_ascii_record(data: bytes, pos: int) -> tuple[bytes, int]:
    """ASCII-only record: terminated by FS. Returns (rec_bytes_without_FS, next_pos)."""
    fs_pos = data.index(_FS, pos)
    return data[pos:fs_pos], fs_pos + 1


def _t1_field(t1_bytes: bytes, tag: str) -> str:
    """Return the value of a named field in Type-1 bytes (no trailing FS)."""
    prefix = tag.encode() + b":"
    for f in t1_bytes.split(bytes([_GS])):
        if f.startswith(prefix):
            return f[len(prefix):].decode(errors="replace")
    return ""


def _rebuild_type1_cnt(t1_bytes: bytes, old_rt: int, new_rt: int) -> bytes:
    """
    Return updated Type-1 bytes WITH trailing FS:
    - Replace every CNT entry 'old_rt<US>IDC' → 'new_rt<US>IDC'.
    - Recompute the LEN field (digit count may change).
    """
    GS_b = bytes([_GS])
    RS_b = bytes([_RS])
    US_b = bytes([_US])

    fields = t1_bytes.split(GS_b)
    updated: list[bytes | None] = []
    for f in fields:
        if f.startswith(b"1.001:"):
            updated.append(None)    # placeholder; recomputed below
        elif f.startswith(b"1.003:"):
            val = f[6:]
            val = val.replace(RS_b + str(old_rt).encode() + US_b,
                              RS_b + str(new_rt).encode() + US_b)
            updated.append(b"1.003:" + val)
        else:
            updated.append(f)

    # body_rest = everything except the LEN field, joined by GS
    body_rest = GS_b.join(f for f in updated if f is not None)

    # Full record: "1.001:NNN" GS body_rest FS  — iterate to stabilise digit count
    for d in range(3, 10):
        total = 6 + d + 1 + len(body_rest) + 1   # "1.001:" + d digits + GS + rest + FS
        if len(str(total)) == d:
            len_field = f"1.001:{total}".encode()
            all_fields = [len_field if f is None else f for f in updated]
            return GS_b.join(all_fields) + _FS_b
    raise ValueError("LEN digit count did not converge for Type-1")


# ---------------------------------------------------------------------------
# Image transcoding helpers
# ---------------------------------------------------------------------------

def _transcode_image(
    src_data: bytes,
    src_cga: str,
    dst_cga: str,
    hll: int = 0,
    vll: int = 0,
    bpx: int = 8,
) -> bytes:
    """
    Re-encode image bytes from one NIST compression format to another.

    src_cga / dst_cga: NIST compression strings, e.g. "WSQ20", "PNG", "JPEGB".
    hll / vll / bpx  : required only when src_cga is "NONE" (raw pixels).

    Returns the re-encoded image bytes.
    """
    from PIL import Image as _Image

    src = src_cga.upper()
    dst = dst_cga.upper()

    if _cga_matches(src, dst):
        return src_data  # already in target format

    # ─── Decode ─────────────────────────────────────────────────────────────
    if src == "NONE":
        if hll <= 0 or vll <= 0:
            raise ValueError("hll and vll are required for NONE (raw) source compression")
        if bpx == 1:
            mode = "1"
        elif bpx == 16:
            mode = "I;16"
        else:
            mode = "L"
        img = _Image.frombytes(mode, (hll, vll), src_data[:hll * vll * max(1, bpx // 8)])
    elif src in ("WSQ", "WSQ20"):
        import wsq  # noqa: F401 – registers the WSQ PIL plugin
        img = _Image.open(io.BytesIO(src_data))
        img.load()
    else:
        img = _Image.open(io.BytesIO(src_data))
        img.load()

    # ─── Encode ─────────────────────────────────────────────────────────────
    if dst == "NONE":
        if img.mode != "L":
            img = img.convert("L")
        return img.tobytes()

    buf = io.BytesIO()
    if dst == "PNG":
        img.save(buf, format="PNG")
    elif dst == "JPEGB":
        if img.mode not in ("L", "RGB", "CMYK", "YCbCr"):
            img = img.convert("RGB")
        img.save(buf, format="JPEG", quality=95)
    elif dst == "JPEGL":
        # PIL has no true lossless JPEG encoder; quality=100 is the best approximation
        if img.mode not in ("L", "RGB", "CMYK", "YCbCr"):
            img = img.convert("RGB")
        img.save(buf, format="JPEG", quality=100)
    elif dst == "JP2":
        img.save(buf, format="JPEG2000")
    elif dst == "JP2L":
        img.save(buf, format="JPEG2000", irreversible=False)
    elif dst in ("WSQ", "WSQ20"):
        raise ValueError(
            "WSQ encoding is not supported: the wsq Python package (v0.8) only decodes "
            "WSQ files. Choose PNG, JPEGB, JP2, or JP2L as the target compression."
        )
    else:
        raise ValueError(f"Unsupported target compression: {dst_cga!r}")

    return buf.getvalue()


def _rebuild_binary_record_with_new_image(
    rec: bytes, new_cga_byte: int, new_img: bytes
) -> bytes:
    """
    Rebuild a binary Type-3/4/5/6 record (no FS terminator) with an updated
    CGA byte and new image data.  The 13 bytes between LEN and CGA are unchanged.
    """
    new_len = 18 + len(new_img)
    return (
        struct.pack(">I", new_len)   # LEN  (4 bytes, big-endian)
        + rec[4:17]                   # IDC, IMP, FGP[6], ISR, HLL, VLL  (13 bytes)
        + bytes([new_cga_byte])       # CGA  (1 byte)
        + new_img
    )


def _rebuild_ascii_binary_with_new_image(
    rec_bytes: bytes, rt: int, new_cga: str, new_img: bytes
) -> bytes:
    """
    Return a rebuilt ASCII+Binary record (WITH trailing FS) with an updated
    CGA string (field rt.011) and image payload (field rt.999). LEN is recomputed.

    rec_bytes: as returned by _parse_ascii_binary_record (WITHOUT trailing FS).
    """
    GS_b    = bytes([_GS])
    FS_b    = bytes([_FS])
    tag_999 = f"{rt}.999:".encode()

    # ── Split at field 999 ──────────────────────────────────────────────────
    gp = rec_bytes.find(GS_b + tag_999)
    if gp < 0:
        raise ValueError(f"Field {rt}.999 not found in Type-{rt} record")

    # Individual ASCII fields (list of bytes), last element is NOT field 999
    ascii_fields = list(rec_bytes[:gp].split(GS_b))

    # ── Update CGA (field rt.011) ───────────────────────────────────────────
    cga_tag = f"{rt}.011:".encode()
    for i, f in enumerate(ascii_fields):
        if f.startswith(cga_tag):
            ascii_fields[i] = cga_tag + new_cga.encode()
            break   # there is exactly one CGA field

    # ── Recompute LEN (field rt.001) ────────────────────────────────────────
    # Full rebuilt record:
    #   ascii_fields[0]  GS  ascii_fields[1] ... GS  ascii_fields[-1]
    #   GS  tag_999  new_img  FS
    # = ascii_fields[0]  +  rest_after_field0
    len_tag = f"{rt}.001:".encode()
    # rest_after_field0 = GS + (fields[1:] joined by GS) + GS + tag_999 + new_img + FS
    rest = (
        GS_b
        + (GS_b.join(ascii_fields[1:]) + GS_b if len(ascii_fields) > 1 else b"")
        + tag_999 + new_img + FS_b
    )

    for d in range(3, 12):
        total = len(len_tag) + d + len(rest)   # "rt.001:" + d digits + rest
        if len(str(total)) == d:
            ascii_fields[0] = len_tag + str(total).encode()
            return ascii_fields[0] + rest

    raise ValueError(f"LEN digit count did not converge for Type-{rt}")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _decode_image(image_b64: str | None, image_path: str | None) -> bytes:
    """Return image bytes from either a base64 string or a file path."""
    if image_path:
        return Path(image_path).read_bytes()
    if image_b64:
        return base64.b64decode(image_b64)
    raise ValueError("Provide either image_b64 or image_path")


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS: list[Tool] = [
    Tool(
        name="nist_build_transaction",
        description=(
            "Build a complete NIST ANSI/NIST-ITL 1-2011 biometric transaction "
            "file (Traditional encoding) and write it to disk. "
            "Always requires a Type-1 header and at least one content record. "
            "Returns the path of the generated file."
        ),
        inputSchema={
            "type": "object",
            "required": ["output_path", "type1", "records"],
            "properties": {
                "output_path": {
                    "type": "string",
                    "description": "Absolute or relative path for the output .nist file."
                },
                "type1": {
                    "type": "object",
                    "description": "Type-1 transaction header parameters.",
                    "required": ["tot", "dai", "ori", "tcn"],
                    "properties": {
                        "tot": {"type": "string", "description": "Type of Transaction (e.g. 'CAR', 'SRE', 'IDV', 'CPS')."},
                        "dai": {"type": "string", "description": "Destination Agency Identifier (e.g. 'FBI')."},
                        "ori": {"type": "string", "description": "Originating Agency Identifier (e.g. 'USTEST0001')."},
                        "tcn": {"type": "string", "description": "Transaction Control Number (unique per transaction)."},
                        "dat": {"type": "string", "description": "Date YYYYMMDD. Defaults to today."},
                        "ver": {"type": "string", "description": "Version number, default '0502'."},
                        "nsr": {"type": "string", "description": "Native scanning resolution (e.g. '19.69'). Default '00.00'."},
                        "ntr": {"type": "string", "description": "Nominal transmitting resolution (e.g. '19.69'). Default '00.00'."},
                        "pry": {"type": "integer", "description": "Priority 1-9 (optional)."},
                        "tcr": {"type": "string", "description": "Transaction control reference (optional)."},
                        "dom": {"type": "string", "description": "Domain name, default 'NORAM'."},
                        "gmt": {"type": "string", "description": "Greenwich Mean Time string (optional)."},
                    }
                },
                "records": {
                    "type": "array",
                    "description": "List of content records to include in the transaction.",
                    "items": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": {
                                "type": "integer",
                                "description": "Record type: 2=user text, 3/4/5/6=binary FP, 9=minutiae, 10=face/body, 13=latent, 14=fingerprint, 15=palm, 16=user-defined, 17=iris, 19=plantar."
                            },
                            "idc": {
                                "type": "integer",
                                "description": "Information Designation Character (0-99). Defaults to sequential."
                            },
                            "user_fields": {
                                "type": "object",
                                "description": "Type-2 only: mapping of field_number (string) -> value."
                            },
                            "src": {"type": "string", "description": "Source agency identifier."},
                            "capture_date": {"type": "string", "description": "Capture date YYYYMMDD."},
                            "hll": {"type": "integer", "description": "Horizontal line length (pixels)."},
                            "vll": {"type": "integer", "description": "Vertical line length (pixels)."},
                            "scale_units": {"type": "integer", "description": "Scale units: 1=PPI, 2=PPCM."},
                            "h_pixel_scale": {"type": "integer", "description": "Horizontal pixels per scale unit."},
                            "v_pixel_scale": {"type": "integer", "description": "Vertical pixels per scale unit."},
                            "compression": {
                                "type": "string",
                                "description": "Compression: 'NONE', 'WSQ20', 'JPEGB', 'JPEGL', 'JP2', 'JP2L', 'PNG'."
                            },
                            "image_path": {"type": "string", "description": "Path to image file on disk."},
                            "image_b64": {"type": "string", "description": "Base64-encoded image data."},
                            "impression_type": {
                                "type": "integer",
                                "description": "IMP: 0=live scan plain, 1=rolled, 2=nonlive plain, 3=nonlive rolled, 4=latent, 8=swipe, 9=unknown."
                            },
                            "finger_position": {
                                "type": "integer",
                                "description": "FGP: 0=unknown, 1=R.Thumb … 10=L.Little."
                            },
                            "isr": {"type": "integer", "description": "Type-4 ISR byte."},
                            "image_type": {"type": "string", "description": "Type-10 image type: 'FACE', 'SMT', etc."},
                            "color_space": {"type": "string", "description": "Color space: 'GRAY', 'RGB', 'YCC'."},
                            "pose": {"type": "string", "description": "Type-10 pose code."},
                            "sap": {"type": "string", "description": "Subject acquisition profile (Type-10)."},
                            "amp": {"type": "string", "description": "Amputated/bandaged code (Type-14/15)."},
                            "palm_position": {"type": "integer", "description": "Palm position code (Type-15)."},
                            "plantar_position": {"type": "integer", "description": "Plantar position code (Type-19)."},
                            "user_defined_type": {"type": "string", "description": "User-defined image type string (Type-16, field 16.003)."},
                            "bpx": {"type": "integer", "description": "Bits per pixel, default 8. Mandatory for Type-13."},
                            "eye_color": {"type": "string", "description": "Eye color code (Type-17)."},
                            "frd": {"type": "string", "description": "Friction ridge detail (Type-9)."},
                            "minutiae": {
                                "type": "array",
                                "description": "Type-9 minutiae list.",
                                "items": {"type": "object"}
                            },
                            "extra_fields": {
                                "type": "object",
                                "description": "Additional fields: mapping field_number (string) -> value."
                            },
                        }
                    }
                }
            }
        },
    ),
    Tool(
        name="nist_describe_record_types",
        description=(
            "Return a concise reference of NIST record types, their purpose, "
            "mandatory fields, and typical use cases. "
            "For authoritative field-level details or to resolve errors/ambiguities, "
            "consult the spec PDFs in /home/mweerden/Nist/ — primary spec: "
            "NIST.SP.500-290e3.pdf (ANSI/NIST-ITL 1-2011 Update 2015, 616 pp); "
            "key sections: §5.3 p85 record types, §8.1 p164 Type-1 fields, "
            "Annex B p554 Traditional encoding. "
            "Historical versions (2000/2007/2011/2013) and the INTERPOL profile "
            "(NIST INTERPOL standard v6.00.01.pdf) are also available in that folder."
        ),
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="nist_decode_file",
        description=(
            "Read a NIST .nist file and return a human-readable summary of "
            "all its records and fields. Binary payloads (image data) are "
            "reported by size rather than content."
        ),
        inputSchema={
            "type": "object",
            "required": ["file_path"],
            "properties": {
                "file_path": {"type": "string", "description": "Path to the .nist file to inspect."}
            }
        },
    ),
    Tool(
        name="nist_extract_images",
        description=(
            "Extract all image payloads from a NIST file and save them to a "
            "directory. Works for all image-bearing record types: "
            "Type-4/7/8 (binary) and Type-10/13/14/15/16/17 (ASCII+Binary). "
            "Files are named type{TT}_idc{NN}.{ext} with extensions detected "
            "from magic bytes. Returns a list of extracted files."
        ),
        inputSchema={
            "type": "object",
            "required": ["file_path", "output_dir"],
            "properties": {
                "file_path":  {"type": "string", "description": "Path to the source .nist file."},
                "output_dir": {"type": "string", "description": "Directory to write extracted images into (created if needed)."},
            }
        },
    ),
    Tool(
        name="nist_convert_record_type",
        description=(
            "Convert records of one type to another within an existing NIST file "
            "and write the result to a new file. The Type-1 CNT field is updated "
            "automatically.\n\n"
            "Supported conversions:\n"
            "  Binary FP → Variable-res  : 3/4/5/6 → 13/14/15/16/19\n"
            "  Variable-res → Variable-res: 13/14/15/16/19 → any other in that set\n\n"
            "Binary fingerprint types: 3=low-res, 4=500ppi, 5=binary, 6=user-defined.\n"
            "Variable-res types: 13=latent, 14=fingerprint, 15=palm, "
            "16=user-defined, 19=plantar.\n"
            "SRC and capture date for binary→variable-res are taken from Type-1 ORI/DAT."
        ),
        inputSchema={
            "type": "object",
            "required": ["input_path", "output_path", "from_type", "to_type"],
            "properties": {
                "input_path":  {"type": "string", "description": "Path to the source .nist file."},
                "output_path": {"type": "string", "description": "Path for the converted output .nist file."},
                "from_type":   {"type": "integer", "description": "Source record type (e.g. 4)."},
                "to_type":     {"type": "integer", "description": "Target record type (e.g. 14)."},
            }
        },
    ),
    Tool(
        name="nist_recode_image_compression",
        description=(
            "Re-encode image payloads in a NIST file from one compression format "
            "to another, keeping the record type unchanged. Works for all "
            "image-bearing record types where the target compression is permitted "
            "by the NIST standard.\n\n"
            "Supported source/target formats: NONE (raw), WSQ20 (WSQ), "
            "JPEGB, JPEGL, JP2, JP2L, PNG.\n\n"
            "Per-type restrictions:\n"
            "  WSQ/WSQ20 allowed only for fingerprint/friction-ridge types "
            "(3,4,5,6,7,13,14,15,16,19).\n"
            "  Face, iris, source imagery (10,17,20,21,22) accept JPEG/JP2/PNG/NONE.\n\n"
            "Note: WSQ encoding (→WSQ) is not supported (decode-only library). "
            "Use PNG, JPEGB, JP2, or JP2L as the target.\n\n"
            "Records with a compression that already matches the target, or for "
            "which the target is not permitted, are copied verbatim with a note "
            "in the returned log."
        ),
        inputSchema={
            "type": "object",
            "required": ["input_path", "output_path", "to_compression"],
            "properties": {
                "input_path": {
                    "type": "string",
                    "description": "Path to the source .nist file."
                },
                "output_path": {
                    "type": "string",
                    "description": "Path for the re-encoded output .nist file."
                },
                "to_compression": {
                    "type": "string",
                    "description": (
                        "Target compression format: 'PNG', 'JPEGB', 'JPEGL', "
                        "'JP2', 'JP2L', or 'NONE' (raw pixels)."
                    )
                },
                "from_compression": {
                    "type": "string",
                    "description": (
                        "Optional: only recode records whose current compression "
                        "matches this value (e.g. 'WSQ20'). If omitted, all "
                        "image-bearing records are candidates."
                    )
                },
                "record_types": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": (
                        "Optional: limit re-encoding to these record types "
                        "(e.g. [4, 14]). If omitted, all image-bearing types "
                        "are processed."
                    )
                },
            }
        },
    ),
]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    if name == "nist_build_transaction":
        return await _handle_build_transaction(arguments)
    if name == "nist_describe_record_types":
        return [TextContent(type="text", text=_record_type_reference())]
    if name == "nist_decode_file":
        return [TextContent(type="text", text=_decode_nist_file(arguments["file_path"]))]
    if name == "nist_extract_images":
        return [TextContent(type="text", text=_handle_extract_images(arguments))]
    if name == "nist_convert_record_type":
        return _handle_convert_record_type(arguments)
    if name == "nist_recode_image_compression":
        return _handle_recode_image_compression(arguments)
    raise ValueError(f"Unknown tool: {name}")


async def _handle_build_transaction(args: dict) -> list[TextContent]:
    output_path = args["output_path"]
    t1_args = args["type1"]
    raw_records = args["records"]

    # Assign IDCs sequentially if not specified
    for i, rec in enumerate(raw_records):
        if "idc" not in rec:
            rec["idc"] = i

    cnt_records = [(1, 0)] + [(r["type"], r["idc"]) for r in raw_records]

    t1 = build_type1(
        tot=t1_args["tot"],
        dai=t1_args["dai"],
        ori=t1_args["ori"],
        tcn=t1_args["tcn"],
        records=cnt_records,
        dat=t1_args.get("dat"),
        ver=t1_args.get("ver", "0502"),
        nsr=t1_args.get("nsr", "00.00"),
        ntr=t1_args.get("ntr", "00.00"),
        pry=t1_args.get("pry"),
        tcr=t1_args.get("tcr"),
        dom=t1_args.get("dom"),
        gmt=t1_args.get("gmt"),
    )

    built: list[bytes] = [t1]

    for rec in raw_records:
        rt = rec["type"]
        idc = rec["idc"]
        extra_fields = {int(k): v for k, v in (rec.get("extra_fields") or {}).items()}

        if rt == 2:
            uf = {int(k): v for k, v in (rec.get("user_fields") or {}).items()}
            built.append(build_type2(idc=idc, user_fields=uf or None))

        elif rt in (3, 5, 6):
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            builder = {3: build_type3, 5: build_type5, 6: build_type6}[rt]
            built.append(builder(
                idc=idc,
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                finger_position=rec.get("finger_position", FGP_UNKNOWN),
                hll=rec["hll"],
                vll=rec["vll"],
                compression=rec.get("compression", CGA_NONE),
                isr=rec.get("isr", 0),
            ))

        elif rt == 4:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type4(
                idc=idc,
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                finger_position=rec.get("finger_position", FGP_UNKNOWN),
                hll=rec["hll"],
                vll=rec["vll"],
                compression=rec.get("compression", CGA_NONE),
                isr=rec.get("isr", 0),
            ))

        elif rt == 9:
            built.append(build_type9(
                idc=idc,
                imp=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                fgp=rec.get("finger_position", FGP_UNKNOWN),
                src=rec["src"],
                frd=rec.get("frd"),
                minutiae=rec.get("minutiae"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 10:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type10(
                idc=idc,
                image_type=rec.get("image_type", IMAGE_TYPE_FACE),
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                color_space=rec.get("color_space", COLOR_SPACE_RGB),
                compression=rec.get("compression", COMPRESSION_JPEG),
                image_data=img,
                sap=rec.get("sap"),
                pose=rec.get("pose"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 14:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type14(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_NONE),
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                finger_position=rec.get("finger_position"),
                amp=rec.get("amp"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 15:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type15(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_NONE),
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                palm_position=rec.get("palm_position"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 13:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type13(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_NONE),
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LATENT_IMAGE),
                finger_position=rec.get("finger_position"),
                bpx=rec.get("bpx", 8),
                extra_fields=extra_fields or None,
            ))

        elif rt == 16:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type16(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_NONE),
                image_data=img,
                user_defined_type=rec.get("user_defined_type"),
                position=rec.get("finger_position"),
                bpx=rec.get("bpx"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 17:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type17(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_JPEG),
                image_data=img,
                eye_color=rec.get("eye_color"),
                extra_fields=extra_fields or None,
            ))

        elif rt == 19:
            img = _decode_image(rec.get("image_b64"), rec.get("image_path"))
            built.append(build_type19(
                idc=idc,
                src=rec["src"],
                capture_date=rec.get("capture_date", date.today().strftime("%Y%m%d")),
                hll=rec["hll"],
                vll=rec["vll"],
                scale_units=rec.get("scale_units", 1),
                h_pixel_scale=rec.get("h_pixel_scale", 500),
                v_pixel_scale=rec.get("v_pixel_scale", 500),
                compression=rec.get("compression", COMPRESSION_NONE),
                image_data=img,
                impression_type=rec.get("impression_type", IMP_LIVE_SCAN_PLAIN),
                plantar_position=rec.get("plantar_position"),
                bpx=rec.get("bpx"),
                extra_fields=extra_fields or None,
            ))

        else:
            raise ValueError(f"Record type {rt} not yet supported by this server.")

    transaction = assemble_transaction(built)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(transaction)

    summary = (
        f"NIST transaction written to: {out.resolve()}\n"
        f"  Total size : {len(transaction):,} bytes\n"
        f"  Records    : 1 (Type-1) + {len(raw_records)} content record(s)\n"
        f"  Record list: Type-1" +
        "".join(f", Type-{r['type']} (IDC={r['idc']})" for r in raw_records)
    )
    return [TextContent(type="text", text=summary)]


def _handle_extract_images(args: dict) -> str:
    """Extract all image payloads from a NIST file to a directory."""
    nist_path = args["file_path"]
    out_dir   = Path(args["output_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)

    data = Path(nist_path).read_bytes()
    t1_bytes, pos, record_order = _parse_t1(data)

    results: list[dict] = []

    for rt, idc in record_order:
        if rt in _BINARY_TYPES:
            rec, pos = _parse_binary_record(data, pos)
            if len(rec) < 18:
                continue
            cga_byte = rec[17]
            img_data = rec[18:]
            cga_hint = _BINARY_CGA_HINT.get(cga_byte, "")
            ext      = _detect_ext(img_data, cga_hint)
            fname    = f"type{rt:02d}_idc{idc:02d}{ext}"
            (out_dir / fname).write_bytes(img_data)
            results.append({
                "file": fname, "rt": rt, "idc": idc,
                "size": len(img_data),
                "compression": cga_hint or f"CGA={cga_byte}",
            })

        elif rt in _ASCII_BINARY_TYPES:
            rec, pos = _parse_ascii_binary_record(data, pos)
            compression = _get_ascii_field(rec, rt, 11)   # CGA field
            # Locate field 999 binary payload
            tag_999    = f"{rt}.999:".encode()
            gs_tag_999 = bytes([_GS]) + tag_999
            gp = rec.find(gs_tag_999)
            if gp < 0:
                continue
            img_data = rec[gp + 1 + len(tag_999):]
            ext      = _detect_ext(img_data, compression)
            fname    = f"type{rt:02d}_idc{idc:02d}{ext}"
            (out_dir / fname).write_bytes(img_data)
            results.append({
                "file": fname, "rt": rt, "idc": idc,
                "size": len(img_data),
                "compression": compression,
            })

        else:
            _, pos = _parse_ascii_record(data, pos)   # skip non-image records

    lines = [
        f"Extracted {len(results)} image(s) from {nist_path}",
        f"Output directory: {out_dir.resolve()}\n",
        f"{'File':<44} {'Bytes':>10}  Compression",
        "-" * 70,
    ]
    for r in results:
        lines.append(f"  {r['file']:<42} {r['size']:>10,}  {r['compression']}")
    return "\n".join(lines)


def _handle_convert_record_type(args: dict) -> list[TextContent]:
    """
    Convert all records of from_type to to_type within a NIST file.

    Supported paths:
      Binary FP (3/4/5/6) → Variable-res (13/14/15/16/19)
      Variable-res         → different variable-res type
    """
    input_path  = args["input_path"]
    output_path = args["output_path"]
    from_type   = int(args["from_type"])
    to_type     = int(args["to_type"])

    from_is_fp_bin = from_type in _FP_BINARY_TYPES
    from_is_vr     = from_type in _VARRES_TYPES
    to_is_vr       = to_type   in _VARRES_TYPES

    if not ((from_is_fp_bin or from_is_vr) and to_is_vr):
        raise ValueError(
            f"Conversion Type-{from_type} → Type-{to_type} is not supported.\n"
            f"Supported: binary FP (3/4/5/6) → variable-res (13/14/15/16/19), "
            f"or variable-res → different variable-res."
        )
    if from_is_vr and from_type == to_type:
        raise ValueError("from_type and to_type are identical — nothing to convert.")

    data = Path(input_path).read_bytes()
    t1_bytes, pos, record_order = _parse_t1(data)

    # SRC and date from Type-1 (used as fallback for binary→variable-res)
    src_val = _t1_field(t1_bytes, "1.008") or "UNKNOWN"
    fcd_val = _t1_field(t1_bytes, "1.005") or date.today().strftime("%Y%m%d")

    out: list[bytes]  = [_rebuild_type1_cnt(t1_bytes, from_type, to_type)]
    converted = 0
    log_lines: list[str] = []

    for rt, idc in record_order:
        if rt == from_type:
            if from_is_fp_bin:
                # ── Binary fingerprint → variable-res ──────────────────────
                rec, pos = _parse_binary_record(data, pos)
                imp     = rec[5]
                fgp6    = rec[6:12]
                isr     = rec[12]
                hll     = struct.unpack(">H", rec[13:15])[0]
                vll     = struct.unpack(">H", rec[15:17])[0]
                cga_num = rec[17]
                img     = rec[18:]
                slc, hps, vps = {1: (1, 500, 500),
                                  2: (1, 1000, 1000)}.get(isr, (1, 500, 500))
                fgp_val = next((b for b in fgp6 if b), 0)
                fields  = {
                    3: str(imp), 4: src_val, 5: fcd_val,
                    6: str(hll), 7: str(vll), 8: str(slc),
                    9: str(hps), 10: str(vps),
                    11: _CGA_STR.get(cga_num, "NONE"),
                    12: "8",
                    13: str(fgp_val) if fgp_val else "",
                }
                new_rec = _varres_from_fields(to_type, idc, fields, img)
                log_lines.append(
                    f"  Type-{from_type} IDC={idc}  FGP={fgp_val}  {hll}×{vll}  "
                    f"CGA={_CGA_STR.get(cga_num,'?')}  "
                    f"{len(img):,}B → Type-{to_type} {len(new_rec):,}B"
                )

            else:
                # ── Variable-res → variable-res ────────────────────────────
                rec, pos = _parse_ascii_binary_record(data, pos)
                fields  = _extract_varres_fields(rec, from_type)
                img     = _extract_img999(rec, from_type)
                new_rec = _varres_from_fields(to_type, idc, fields, img)
                hll = fields.get(6, "?"); vll = fields.get(7, "?")
                log_lines.append(
                    f"  Type-{from_type} IDC={idc}  {hll}×{vll}  "
                    f"CGA={fields.get(11,'?')}  "
                    f"{len(img):,}B → Type-{to_type} {len(new_rec):,}B"
                )

            out.append(new_rec)
            converted += 1

        elif rt in _BINARY_TYPES:
            rec, pos = _parse_binary_record(data, pos)
            out.append(rec)                       # binary records have no FS

        elif rt in _ASCII_BINARY_TYPES:
            rec, pos = _parse_ascii_binary_record(data, pos)
            out.append(rec + _FS_b)

        else:
            rec, pos = _parse_ascii_record(data, pos)
            out.append(rec + _FS_b)

    result  = b"".join(out)
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(result)

    summary = (
        f"NIST conversion: Type-{from_type} → Type-{to_type}\n"
        f"  Input : {input_path}  ({len(data):,} bytes)\n"
        f"  Output: {out_path.resolve()}  ({len(result):,} bytes)\n"
        f"  Converted: {converted} record(s)\n"
        + "\n".join(log_lines)
    )
    return [TextContent(type="text", text=summary)]


# ---------------------------------------------------------------------------
# Image compression re-encoder
# ---------------------------------------------------------------------------

def _handle_recode_image_compression(args: dict) -> list[TextContent]:
    """
    Re-encode image payloads in a NIST file from one compression to another,
    keeping record types unchanged.  Validates per-type allowed compressions.
    """
    input_path     = args["input_path"]
    output_path    = args["output_path"]
    dst_cga        = args["to_compression"].upper().strip()
    src_cga_filter = (args.get("from_compression") or "").upper().strip() or None
    type_filter    = {int(t) for t in (args.get("record_types") or [])} or None

    data = Path(input_path).read_bytes()
    t1_bytes, pos, record_order = _parse_t1(data)

    out: list[bytes] = [t1_bytes + _FS_b]   # Type-1 is never modified
    converted  = 0
    skipped    = 0
    log_lines: list[str] = []

    for rt, idc in record_order:

        # ── Records excluded by type filter ──────────────────────────────────
        if type_filter and rt not in type_filter:
            if rt in _BINARY_TYPES:
                rec, pos = _parse_binary_record(data, pos)
                out.append(rec)
            elif rt in _ASCII_BINARY_TYPES:
                rec, pos = _parse_ascii_binary_record(data, pos)
                out.append(rec + _FS_b)
            else:
                rec, pos = _parse_ascii_record(data, pos)
                out.append(rec + _FS_b)
            continue

        # ── Binary image records (Types 3-8) ─────────────────────────────────
        if rt in _BINARY_TYPES:
            rec, pos = _parse_binary_record(data, pos)
            if len(rec) < 18:
                out.append(rec)
                continue

            cga_byte = rec[17]
            src_cga  = _CGA_STR.get(cga_byte, "NONE")   # e.g. "WSQ20", "PNG"
            img      = rec[18:]
            hll      = struct.unpack(">H", rec[13:15])[0]
            vll      = struct.unpack(">H", rec[15:17])[0]

            # Filter by source compression?
            if src_cga_filter and not _cga_matches(src_cga, src_cga_filter):
                out.append(rec)
                skipped += 1
                continue

            # Already in target format?
            if _cga_matches(src_cga, dst_cga):
                out.append(rec)
                skipped += 1
                continue

            # Validate that dst_cga is allowed for this record type
            allowed = _ALLOWED_CGA_BY_TYPE.get(rt, set())
            if not any(_cga_matches(dst_cga, a) for a in allowed):
                out.append(rec)
                log_lines.append(
                    f"  SKIP Type-{rt} IDC={idc}: "
                    f"'{dst_cga}' not permitted for this record type"
                )
                skipped += 1
                continue

            try:
                new_img      = _transcode_image(img, src_cga, dst_cga, hll=hll, vll=vll, bpx=8)
                new_cga_byte = _BINARY_CGA_NUM.get(dst_cga, 0)
                new_rec      = _rebuild_binary_record_with_new_image(rec, new_cga_byte, new_img)
                out.append(new_rec)
                log_lines.append(
                    f"  Type-{rt} IDC={idc}: {src_cga} → {dst_cga}  "
                    f"{len(img):,} B → {len(new_img):,} B  ({hll}×{vll})"
                )
                converted += 1
            except Exception as exc:
                out.append(rec)
                log_lines.append(f"  SKIP Type-{rt} IDC={idc}: {exc}")
                skipped += 1

        # ── ASCII+Binary image records (Types 10, 13-17, 19-22, …) ───────────
        elif rt in _ASCII_BINARY_TYPES:
            rec, pos = _parse_ascii_binary_record(data, pos)
            src_cga  = _get_ascii_field(rec, rt, 11).upper()   # CGA field
            img      = _extract_img999(rec, rt)

            # Filter by source compression?
            if src_cga_filter and not _cga_matches(src_cga, src_cga_filter):
                out.append(rec + _FS_b)
                skipped += 1
                continue

            # Already in target format?
            if _cga_matches(src_cga, dst_cga):
                out.append(rec + _FS_b)
                skipped += 1
                continue

            # Validate dst_cga is allowed for this record type
            allowed = _ALLOWED_CGA_BY_TYPE.get(rt, set())
            if not any(_cga_matches(dst_cga, a) for a in allowed):
                out.append(rec + _FS_b)
                log_lines.append(
                    f"  SKIP Type-{rt} IDC={idc}: "
                    f"'{dst_cga}' not permitted for this record type"
                )
                skipped += 1
                continue

            hll_s = _get_ascii_field(rec, rt, 6)
            vll_s = _get_ascii_field(rec, rt, 7)
            bpx_s = _get_ascii_field(rec, rt, 12)
            hll   = int(hll_s) if hll_s else 0
            vll   = int(vll_s) if vll_s else 0
            # Field 12 is BPX (bits per pixel) for Types 13-19+, but CSP (color space
            # string like "RGB") for Type-10 — guard against non-numeric values.
            try:
                bpx = int(bpx_s) if bpx_s else 8
            except ValueError:
                bpx = 8

            try:
                new_img = _transcode_image(img, src_cga, dst_cga, hll=hll, vll=vll, bpx=bpx)
                # Canonical CGA field string for ASCII+Binary records: use WSQ20 not WSQ
                dst_cga_field = "WSQ20" if _cga_matches(dst_cga, "WSQ20") else dst_cga
                new_rec = _rebuild_ascii_binary_with_new_image(rec, rt, dst_cga_field, new_img)
                out.append(new_rec)
                log_lines.append(
                    f"  Type-{rt} IDC={idc}: {src_cga} → {dst_cga_field}  "
                    f"{len(img):,} B → {len(new_img):,} B  ({hll}×{vll})"
                )
                converted += 1
            except Exception as exc:
                out.append(rec + _FS_b)
                log_lines.append(f"  SKIP Type-{rt} IDC={idc}: {exc}")
                skipped += 1

        # ── Pure-ASCII records (Type-2, 9, …) – never carry image data ───────
        else:
            rec, pos = _parse_ascii_record(data, pos)
            out.append(rec + _FS_b)

    result   = b"".join(out)
    out_path = Path(output_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(result)

    src_filter_note = f" (from {src_cga_filter})" if src_cga_filter else ""
    summary = (
        f"NIST image re-encoding → {dst_cga}{src_filter_note}\n"
        f"  Input : {input_path}  ({len(data):,} bytes)\n"
        f"  Output: {out_path.resolve()}  ({len(result):,} bytes)\n"
        f"  Converted: {converted} record(s)   Kept/skipped: {skipped}\n"
        + ("\n".join(log_lines) if log_lines else "  (no log entries)")
    )
    return [TextContent(type="text", text=summary)]


# ---------------------------------------------------------------------------
# Reference text
# ---------------------------------------------------------------------------

def _record_type_reference() -> str:
    return """NIST ANSI/NIST-ITL 1-2011 Record Type Reference
=================================================

SPEC FILES  (consult when errors or ambiguities arise)
------------------------------------------------------
Primary:   /home/mweerden/Nist/NIST.SP.500-290e3.pdf  (2015 Update, 616 pp)
           §5.3 p85 record types | §8.1 p164 Type-1 fields | Annex B p554 encoding
Also:      ANSI NIST ITL 1-2011 Update 2015.pdf  (alternate copy)
History:   ANSI NIST ITL 1-2011 Update 2013.pdf | 1-2011.pdf | 1-2007.pdf | 1-2000.pdf
Interop:   NIST INTERPOL standard v6.00.01.pdf  (cross-border exchange profile)
All files in: /home/mweerden/Nist/

STRUCTURE
---------
A transaction = Type-1 record + 1..999 content records.
Encoding: Traditional (ASCII fields + binary for Types 4/7/8).

SEPARATORS (ASCII control characters)
--------------------------------------
  FS  0x1C  File Separator   – ends each record (replaces last GS)
  GS  0x1D  Group Separator  – between fields within a record
  RS  0x1E  Record Separator – between subfields within a field
  US  0x1F  Unit Separator   – between information items within a subfield

Field format (ASCII records): TT.FFF:value<GS>TT.FFF:value...<FS>
LEN field (xx.001): total byte count of the record including the trailing FS.

RECORD TYPES
------------
Type-1  Transaction Information (MANDATORY, always first, ASCII only)
  Mandatory: LEN(1.001) VER(1.002) CNT(1.003) TOT(1.004) DAT(1.005)
             DAI(1.007) ORI(1.008) TCN(1.009) NSR(1.011) NTR(1.012)
  VER = 0502 (2015 update), 0501 (2013), 0500 (2011)
  CNT = list of (record_type, IDC) for all records
  DAT = YYYYMMDD
  NSR/NTR = "00.00" when no Type-4 records present

Type-2  User-defined Descriptive Text (ASCII only)
  Mandatory: LEN(2.001) IDC(2.002)
  Use for subject metadata, case info, demographics, etc.

Type-4  High-resolution Grayscale Fingerprint Image (BINARY, 500ppi)
  Fixed binary layout (18-byte header + image data):
    LEN(4b) IDC(1b) IMP(1b) FGP(6b) ISR(1b) HLL(2b) VLL(2b) CGA(1b) DATA
  No FS terminator. Cannot be changed between standard versions.

Type-7  User-defined Image (BINARY) – legacy

Type-8  Signature Image (BINARY) – binary or vectored signature

Type-9  Minutiae Data (ASCII)
  Mandatory: LEN IDC IMP FGP SRC
  Contains friction ridge feature data and EFS extended features.

Type-10 Photographic Body Part Imagery – face, SMT (ASCII+Binary)
  Mandatory: LEN IDC IMT(image type) SRC PHD(date) HLL VLL SLC
             THPS TVPS CGA CSP(color space)
  image_type: FACE, SMT, SCAR, MARK, TATOO, etc.
  compression: JPEGB, JPEGL, JP2, JP2L, PNG, NONE
  color_space: GRAY, RGB, YCC

Type-13 Latent Friction Ridge Image (ASCII+Binary) – latent prints

Type-14 Variable-resolution Fingerprint Image (ASCII+Binary) – preferred over Type-4
  Mandatory: LEN IDC IMP SRC DAT HLL VLL SLC THPS TVPS CGA BPX FGP
  compression: NONE, WSQ20, JPEGB, JPEGL, JP2, JP2L, PNG
  BPX: bits per pixel (typically 8 for grayscale)

Type-15 Variable-resolution Palm Print Image (ASCII+Binary)

Type-17 Iris Image (ASCII+Binary)
  Mandatory: LEN IDC SRC DAT HLL VLL SLC THPS TVPS CGA

Type-18 DNA Data (ASCII+Binary)
Type-19 Variable-resolution Plantar (foot sole) Image (ASCII+Binary)
Type-20 Source Representation (ASCII+Binary) – original source imagery
Type-21 Associated Context (ASCII+Binary) – contextual imagery
Type-22 Non-photographic Imagery (ASCII+Binary) – IR, X-ray, etc.
Type-98 Information Assurance (ASCII+Binary) – digital signatures/hashes
Type-99 CBEFF Biometric Data (ASCII+Binary) – other biometric formats

IDC (Information Designation Character)
----------------------------------------
  Each content record has an IDC (0-99).
  IDC links records of the same biometric sample (e.g. Type-14 + Type-9).
  Must be sequential with no gaps; listed in CNT field of Type-1.

IMPRESSION TYPE CODES (IMP)
----------------------------
  0  Live scan plain           4  Latent image
  1  Live scan rolled          5  Latent tracing
  2  Non-live scan plain       6  Latent photo
  3  Non-live scan rolled      7  Latent lift
  8  Swipe                     9  Unknown

FINGER POSITION CODES (FGP)
-----------------------------
  0=Unknown  1=R.Thumb  2=R.Index  3=R.Middle  4=R.Ring  5=R.Little
  6=L.Thumb  7=L.Index  8=L.Middle 9=L.Ring   10=L.Little
"""


# ---------------------------------------------------------------------------
# File decoder (for inspection) — streaming parser, handles all record types
# ---------------------------------------------------------------------------

def _decode_nist_file(file_path: str) -> str:
    data = Path(file_path).read_bytes()
    n = len(data)

    def _fmt(raw: bytes) -> str:
        return (raw.replace(bytes([_US]), b"<US>")
                   .replace(bytes([_RS]), b"<RS>")
                   .replace(bytes([_GS]), b"<GS>")
                   .decode("ascii", errors="replace"))

    def _display_fields(rec_bytes: bytes, rt: int, lines: list) -> None:
        """Append decoded fields; handles binary payload in field 999."""
        tag_999    = f"{rt}.999:".encode()
        gs_tag_999 = bytes([_GS]) + tag_999
        gs_pos     = rec_bytes.find(gs_tag_999)
        ascii_part = rec_bytes[:gs_pos] if gs_pos >= 0 else rec_bytes
        for f in ascii_part.split(bytes([_GS])):
            if b":" in f:
                colon = f.index(b":")
                label = f[:colon].decode(errors="?")
                val   = _fmt(f[colon + 1:])
                if len(val) > 160:
                    val = val[:160] + "…"
                lines.append(f"  {label}: {val}")
        if gs_pos >= 0:
            payload_size = len(rec_bytes) - gs_pos - 1 - len(tag_999)
            lines.append(f"  {rt}.999: <binary payload, {payload_size:,} bytes>")

    try:
        t1_bytes, pos, record_order = _parse_t1(data)
    except (ValueError, IndexError) as exc:
        return f"Error: could not parse Type-1 record in {file_path}: {exc}"

    lines = [
        f"NIST file: {file_path}  ({n:,} bytes)",
        f"Records: 1 (Type-1) + {len(record_order)} content record(s)\n",
        f"--- Record 1: Type-1  ({len(t1_bytes) + 1:,} bytes) ---",
    ]
    _display_fields(t1_bytes, 1, lines)
    lines.append("")

    for rec_num, (rt, idc) in enumerate(record_order, 2):
        if pos >= n:
            lines.append(
                f"  <truncated: {len(record_order) - rec_num + 2} record(s) missing>"
            )
            break
        try:
            if rt in _BINARY_TYPES:
                rec, pos = _parse_binary_record(data, pos)
                rec_len  = len(rec)
                lines.append(
                    f"--- Record {rec_num}: Type-{rt}  IDC={idc}  ({rec_len:,} bytes, binary) ---"
                )
                if rec_len >= 18:
                    hll = struct.unpack(">H", rec[13:15])[0]
                    vll = struct.unpack(">H", rec[15:17])[0]
                    lines.append(
                        f"  IDC={rec[4]}  IMP={rec[5]}  FGP[0]={rec[6]}  ISR={rec[12]}"
                    )
                    lines.append(
                        f"  HLL={hll}  VLL={vll}  CGA={rec[17]}  "
                        f"Image: {rec_len - 18:,} bytes"
                    )

            elif rt in _ASCII_BINARY_TYPES:
                rec, pos = _parse_ascii_binary_record(data, pos)
                lines.append(
                    f"--- Record {rec_num}: Type-{rt}  IDC={idc}  "
                    f"({len(rec) + 1:,} bytes incl. FS) ---"
                )
                _display_fields(rec, rt, lines)

            else:
                rec, pos = _parse_ascii_record(data, pos)
                lines.append(
                    f"--- Record {rec_num}: Type-{rt}  IDC={idc}  "
                    f"({len(rec) + 1:,} bytes incl. FS) ---"
                )
                _display_fields(rec, rt, lines)

        except Exception as exc:
            lines.append(
                f"--- Record {rec_num}: Type-{rt}  IDC={idc}  <parse error: {exc}> ---"
            )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


def run():
    """Entry point for the `nist-builder-mcp` console script."""
    import asyncio
    asyncio.run(main())


if __name__ == "__main__":
    run()
