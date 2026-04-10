"""
NIST ANSI/NIST-ITL 1-2011 (Update 2015) Traditional Encoding.

Separator bytes (ASCII control characters):
  FS  0x1C  28  File Separator     – separates records in transaction
  GS  0x1D  29  Group Separator    – separates fields within a record
  RS  0x1E  30  Record Separator   – separates subfields within a field
  US  0x1F  31  Unit Separator     – separates information items within a subfield

Field format for ASCII records: "TT.FFF:data" where TT = record type, FFF = field number.
Binary records (Types 4, 7, 8): raw bytes, fixed layout, no field labels/separators.
"""

from __future__ import annotations
from datetime import date, datetime
from typing import Any
import struct

FS = b"\x1c"  # File Separator  (separates records)
GS = b"\x1d"  # Group Separator (separates fields)
RS = b"\x1e"  # Record Separator (separates subfields)
US = b"\x1f"  # Unit Separator  (separates information items)


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _field(record_type: int, field_num: int, value: str | bytes) -> bytes:
    """Encode a single ASCII field: 'TT.FFF:value'."""
    label = f"{record_type}.{field_num:03d}:".encode("ascii")
    if isinstance(value, str):
        return label + value.encode("ascii")
    return label + value


def _join_fields(*parts: bytes) -> bytes:
    """Join fields with GS separator."""
    return GS.join(parts)


def _us(*items: str) -> str:
    """Join information items within a subfield with US."""
    return "\x1f".join(items)


def _rs(*subfields: str) -> str:
    """Join subfields within a field with RS."""
    return "\x1e".join(subfields)


# ---------------------------------------------------------------------------
# CNT field (1.003) helpers
# ---------------------------------------------------------------------------

def _build_cnt(records: list[tuple[int, int]]) -> str:
    """
    Build Field 1.003 (CNT – Transaction Content).

    records: list of (record_type, idc) pairs for all records including Type-1.
    Type-1 is always the first entry with IDC omitted (just the count of
    subsequent records is encoded in the first subfield).

    CNT format:
      First subfield:   record_type US count_of_remaining_records
      Remaining subfields (one per record): record_type US idc
    """
    # records[0] is Type-1 itself; the rest are the actual content records
    non_type1 = records[1:]
    first = _us("1", str(len(non_type1)))
    rest = [_us(str(rt), str(idc)) for rt, idc in non_type1]
    return _rs(first, *rest)


# ---------------------------------------------------------------------------
# Type-1 record (ASCII)
# ---------------------------------------------------------------------------

def build_type1(
    *,
    tot: str,
    dai: str,
    ori: str,
    tcn: str,
    records: list[tuple[int, int]],  # (record_type, idc) for all records
    dat: str | None = None,          # YYYYMMDD; defaults to today
    ver: str = "0502",
    nsr: str = "00.00",
    ntr: str = "00.00",
    pry: int | None = None,
    tcr: str | None = None,
    dom: str | None = None,
    gmt: str | None = None,
) -> bytes:
    """
    Build a Type-1 Transaction Information Record (Traditional encoding).

    Mandatory fields: LEN, VER, CNT, TOT, DAT, DAI, ORI, TCN, NSR, NTR.
    """
    if dat is None:
        dat = date.today().strftime("%Y%m%d")

    cnt_val = _build_cnt(records)
    fields: list[bytes] = []

    # 1.001 – LEN (placeholder; recalculated at the end)
    len_placeholder = b"1.001:XXXXXXXXXX"
    fields.append(len_placeholder)

    # 1.002 – VER
    fields.append(_field(1, 2, ver))
    # 1.003 – CNT
    fields.append(_field(1, 3, cnt_val))
    # 1.004 – TOT
    fields.append(_field(1, 4, tot))
    # 1.005 – DAT
    fields.append(_field(1, 5, dat))
    # 1.006 – PRY (optional)
    if pry is not None:
        fields.append(_field(1, 6, str(pry)))
    # 1.007 – DAI
    fields.append(_field(1, 7, dai))
    # 1.008 – ORI
    fields.append(_field(1, 8, ori))
    # 1.009 – TCN
    fields.append(_field(1, 9, tcn))
    # 1.010 – TCR (optional)
    if tcr is not None:
        fields.append(_field(1, 10, tcr))
    # 1.011 – NSR
    fields.append(_field(1, 11, nsr))
    # 1.012 – NTR
    fields.append(_field(1, 12, ntr))
    # 1.013 – DOM (optional, default per spec is NORAM)
    if dom is None:
        dom = "NORAM"
    fields.append(_field(1, 13, dom))
    # 1.014 – GMT (optional)
    if gmt is not None:
        fields.append(_field(1, 14, gmt))

    # Join fields with GS, terminate record with FS
    body = GS.join(fields) + FS

    # Compute actual record length (number of bytes in body including FS)
    # The length includes the label "1.001:" and the length digits themselves.
    # We iterate: the length value affects the length of the LEN field which
    # may change its own digit count.  Two passes are sufficient.
    for _ in range(3):
        len_str = str(len(body))
        new_len_field = f"1.001:{len_str}".encode("ascii")
        body = new_len_field + body[len(len_placeholder):]
        # Re-join with the corrected first field
        # Actually we need to rebuild properly:
        fields[0] = new_len_field
        body = GS.join(fields) + FS

    return body


# ---------------------------------------------------------------------------
# Type-2 record (ASCII – user-defined text)
# ---------------------------------------------------------------------------

def build_type2(
    *,
    idc: int,
    user_fields: dict[int, str] | None = None,
) -> bytes:
    """
    Build a Type-2 User-defined Descriptive Text Record.

    user_fields: mapping of field_number -> value for any user-defined fields.
    """
    fields: list[bytes] = []
    len_placeholder = b"2.001:XXXXXXXXXX"
    fields.append(len_placeholder)
    fields.append(_field(2, 2, str(idc)))

    if user_fields:
        for fnum in sorted(user_fields):
            fields.append(_field(2, fnum, user_fields[fnum]))

    body = GS.join(fields) + FS
    for _ in range(3):
        len_str = str(len(body))
        new_len_field = f"2.001:{len_str}".encode("ascii")
        fields[0] = new_len_field
        body = GS.join(fields) + FS
    return body


# ---------------------------------------------------------------------------
# Type-4 record (Binary – 500ppi grayscale fingerprint)
# ---------------------------------------------------------------------------

# Impression type codes
IMP_LIVE_SCAN_PLAIN = 0
IMP_LIVE_SCAN_ROLLED = 1
IMP_NONLIVE_PLAIN = 2
IMP_NONLIVE_ROLLED = 3
IMP_LATENT_IMAGE = 4
IMP_LATENT_TRACING = 5
IMP_LATENT_PHOTO = 6
IMP_LATENT_LIFT = 7
IMP_SWIPE = 8
IMP_UNKNOWN = 9

# Compression algorithm codes for Type-4
CGA_NONE = 0
CGA_WSQ = 1

# Finger position codes (for FGP field, 6 bytes)
FGP_UNKNOWN = 0
FGP_RIGHT_THUMB = 1
FGP_RIGHT_INDEX = 2
FGP_RIGHT_MIDDLE = 3
FGP_RIGHT_RING = 4
FGP_RIGHT_LITTLE = 5
FGP_LEFT_THUMB = 6
FGP_LEFT_INDEX = 7
FGP_LEFT_MIDDLE = 8
FGP_LEFT_RING = 9
FGP_LEFT_LITTLE = 10


def build_type4(
    *,
    idc: int,
    image_data: bytes,
    impression_type: int = IMP_LIVE_SCAN_PLAIN,
    finger_position: int = FGP_UNKNOWN,
    hll: int,          # horizontal line length (pixels per line)
    vll: int,          # vertical line length (number of lines)
    compression: int = CGA_NONE,
    isr: int = 0,      # 0 = within Appendix F tolerance (500ppi ±1%)
) -> bytes:
    """
    Build a Type-4 binary grayscale fingerprint record.

    Binary layout (bytes 1-18 fixed header, then image data):
      Bytes 1-4:   LEN  (4 bytes, big-endian uint32)
      Byte  5:     IDC  (1 byte)
      Byte  6:     IMP  (1 byte, impression type)
      Bytes 7-12:  FGP  (6 bytes – first byte = finger pos, rest = 255)
      Byte  13:    ISR  (1 byte, 0=within tolerance, 1=outside)
      Bytes 14-15: HLL  (2 bytes, big-endian uint16)
      Bytes 16-17: VLL  (2 bytes, big-endian uint16)
      Byte  18:    CGA  (1 byte, compression algorithm)
      Bytes 19+:   DATA (image data)
    """
    total_len = 18 + len(image_data)
    header = (
        struct.pack(">I", total_len)
        + bytes([idc & 0xFF])
        + bytes([impression_type])
        + bytes([finger_position, 255, 255, 255, 255, 255])
        + bytes([isr])
        + struct.pack(">HH", hll, vll)
        + bytes([compression])
    )
    assert len(header) == 18
    return header + image_data


# ---------------------------------------------------------------------------
# ASCII/Binary record builder helper (Types 10, 13, 14, 15, 17, 19, etc.)
# ---------------------------------------------------------------------------

def _build_ascii_binary_record(
    record_type: int,
    idc: int,
    text_fields: dict[int, str],
    image_data: bytes | None,
) -> bytes:
    """
    Build a record that has ASCII text fields (with field labels) plus an
    optional binary payload in field 999.

    text_fields: mapping field_number -> string value (must not include 1 or 999).
    image_data:  raw bytes to place in field xxx.999, or None if no image.
    """
    fields: list[bytes] = []
    len_placeholder = f"{record_type}.001:XXXXXXXXXX".encode("ascii")
    fields.append(len_placeholder)
    fields.append(_field(record_type, 2, str(idc)))

    for fnum in sorted(text_fields):
        fields.append(_field(record_type, fnum, text_fields[fnum]))

    if image_data is not None:
        data_label = f"{record_type}.999:".encode("ascii")
        fields.append(data_label + image_data)

    body = GS.join(fields) + FS
    for _ in range(3):
        len_str = str(len(body))
        new_len_field = f"{record_type}.001:{len_str}".encode("ascii")
        fields[0] = new_len_field
        body = GS.join(fields) + FS
    return body


# ---------------------------------------------------------------------------
# Type-9 record (ASCII – Minutiae data)
# ---------------------------------------------------------------------------

def build_type9(
    *,
    idc: int,
    imp: int,                     # impression type
    fgp: int,                     # finger position
    src: str,
    frd: str | None = None,       # friction ridge detail
    minutiae: list[dict] | None = None,  # list of minutiae dicts
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """
    Build a Type-9 Minutiae record (ASCII).

    Each minutia dict: {'index': int, 'x': int, 'y': int,
                        'theta': int, 'quality': int, 'type': str}
    """
    tf: dict[int, str] = {}
    tf[3] = str(imp)
    tf[4] = str(fgp)
    tf[5] = src

    if frd is not None:
        tf[6] = frd

    if minutiae:
        # Field 9.012 or newer EFS fields; for simplicity use legacy format
        # Field 9.013: Minutiae – each subfield = index US x US y US theta US quality US type
        subfields = []
        for m in minutiae:
            subfields.append(_us(
                str(m.get("index", 0)),
                str(m.get("x", 0)),
                str(m.get("y", 0)),
                str(m.get("theta", 0)),
                str(m.get("quality", 0)),
                str(m.get("type", "A")),
            ))
        tf[13] = _rs(*subfields)

    if extra_fields:
        tf.update(extra_fields)

    return _build_ascii_binary_record(9, idc, tf, None)


# ---------------------------------------------------------------------------
# Type-10 record (ASCII+Binary – face/body part imagery)
# ---------------------------------------------------------------------------

IMAGE_TYPE_FACE = "FACE"
IMAGE_TYPE_SMT  = "SMT"
IMAGE_TYPE_SCAR = "SCAR"

COLOR_SPACE_GRAY = "GRAY"
COLOR_SPACE_RGB  = "RGB"
COLOR_SPACE_YCC  = "YCC"

COMPRESSION_JPEG   = "JPEGB"
COMPRESSION_JPEGL  = "JPEGL"
COMPRESSION_JP2    = "JP2"
COMPRESSION_JP2L   = "JP2L"
COMPRESSION_PNG    = "PNG"
COMPRESSION_NONE   = "NONE"


def build_type10(
    *,
    idc: int,
    image_type: str,       # e.g. "FACE", "SMT"
    src: str,
    capture_date: str,     # YYYYMMDD
    hll: int,
    vll: int,
    scale_units: int,      # 1=PPI, 2=PPCM
    h_pixel_scale: int,    # pixels per scale unit horizontal
    v_pixel_scale: int,    # pixels per scale unit vertical
    color_space: str,      # e.g. "GRAY", "RGB"
    compression: str,      # e.g. "JPEGB", "NONE"
    image_data: bytes,
    sap: str | None = None,          # subject acquisition profile
    pose: str | None = None,         # pose code
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """
    Build a Type-10 Photographic Body Part Imagery Record.
    """
    tf: dict[int, str] = {}
    tf[3]  = image_type
    tf[4]  = src
    tf[5]  = capture_date
    tf[6]  = str(hll)
    tf[7]  = str(vll)
    tf[8]  = str(scale_units)
    tf[9]  = str(h_pixel_scale)
    tf[10] = str(v_pixel_scale)
    tf[11] = compression
    tf[12] = color_space
    if sap:
        tf[13] = sap
    if pose:
        tf[20] = pose
    if extra_fields:
        tf.update(extra_fields)

    return _build_ascii_binary_record(10, idc, tf, image_data)


# ---------------------------------------------------------------------------
# Type-14 record (ASCII+Binary – variable-resolution fingerprint)
# ---------------------------------------------------------------------------

def build_type14(
    *,
    idc: int,
    src: str,
    capture_date: str,     # YYYYMMDD
    hll: int,
    vll: int,
    scale_units: int,      # 1=PPI, 2=PPCM
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,      # "NONE", "WSQ20", "JPEGB", "JPEGL", "JP2", "JP2L", "PNG"
    image_data: bytes,
    impression_type: int = IMP_LIVE_SCAN_PLAIN,
    finger_position: int | None = None,
    amp: str | None = None,          # amputated/bandaged code
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """
    Build a Type-14 Variable-Resolution Fingerprint Image Record.
    """
    tf: dict[int, str] = {}
    tf[3] = str(impression_type)
    tf[4] = src
    tf[5] = capture_date
    tf[6] = str(hll)
    tf[7] = str(vll)
    tf[8] = str(scale_units)
    tf[9] = str(h_pixel_scale)
    tf[10] = str(v_pixel_scale)
    tf[11] = compression
    if finger_position is not None:
        tf[13] = str(finger_position)
    if amp is not None:
        tf[18] = amp
    if extra_fields:
        tf.update(extra_fields)

    return _build_ascii_binary_record(14, idc, tf, image_data)


# ---------------------------------------------------------------------------
# Type-15 record (ASCII+Binary – palm print)
# ---------------------------------------------------------------------------

def build_type15(
    *,
    idc: int,
    src: str,
    capture_date: str,
    hll: int,
    vll: int,
    scale_units: int,
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,
    image_data: bytes,
    impression_type: int = IMP_LIVE_SCAN_PLAIN,
    palm_position: int | None = None,
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """Build a Type-15 Variable-Resolution Palm Print Image Record."""
    tf: dict[int, str] = {}
    tf[3] = str(impression_type)
    tf[4] = src
    tf[5] = capture_date
    tf[6] = str(hll)
    tf[7] = str(vll)
    tf[8] = str(scale_units)
    tf[9] = str(h_pixel_scale)
    tf[10] = str(v_pixel_scale)
    tf[11] = compression
    if palm_position is not None:
        tf[13] = str(palm_position)
    if extra_fields:
        tf.update(extra_fields)
    return _build_ascii_binary_record(15, idc, tf, image_data)


# ---------------------------------------------------------------------------
# Type-17 record (ASCII+Binary – iris image)
# ---------------------------------------------------------------------------

def build_type17(
    *,
    idc: int,
    src: str,
    capture_date: str,
    hll: int,
    vll: int,
    scale_units: int,
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,
    image_data: bytes,
    eye_color: str | None = None,
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """Build a Type-17 Iris Image Record."""
    tf: dict[int, str] = {}
    tf[4] = src
    tf[5] = capture_date
    tf[6] = str(hll)
    tf[7] = str(vll)
    tf[8] = str(scale_units)
    tf[9] = str(h_pixel_scale)
    tf[10] = str(v_pixel_scale)
    tf[11] = compression
    if eye_color:
        tf[16] = eye_color
    if extra_fields:
        tf.update(extra_fields)
    return _build_ascii_binary_record(17, idc, tf, image_data)


# ---------------------------------------------------------------------------
# Type-3, 5, 6 records (Binary – legacy fingerprint images, same layout as Type-4)
# ---------------------------------------------------------------------------

def build_type3(*args, **kwargs) -> bytes:
    """Type-3 Low-resolution grayscale fingerprint (same 18-byte binary layout as Type-4)."""
    return build_type4(*args, **kwargs)


def build_type5(*args, **kwargs) -> bytes:
    """Type-5 Low-resolution binary fingerprint (same 18-byte binary layout as Type-4)."""
    return build_type4(*args, **kwargs)


def build_type6(*args, **kwargs) -> bytes:
    """Type-6 Low-resolution binary fingerprint, user-defined (same layout as Type-4)."""
    return build_type4(*args, **kwargs)


# ---------------------------------------------------------------------------
# Generic variable-resolution image record builder (Types 13-16, 19-22, …)
# ---------------------------------------------------------------------------

def build_variable_res_record(
    record_type: int,
    *,
    idc: int,
    src: str,
    capture_date: str,       # YYYYMMDD
    hll: int,
    vll: int,
    scale_units: int,        # 1=PPI, 2=PPCM
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,        # "NONE","WSQ20","JPEGB","JPEGL","JP2","JP2L","PNG"
    image_data: bytes,
    impression_type: int | None = None,  # field 3 (absent for some types like 17)
    position: int | None = None,         # field 13: FGP / PPD / PPN / etc.
    bpx: int | None = None,             # field 12: bits per pixel
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """
    Build any variable-resolution ASCII+Binary image record (Types 13-16, 17, 19-22).

    Standard field layout shared by all variable-res types:
      3: IMP/UDI (impression/type code – optional for some types)
      4: SRC     6-7: HLL,VLL    8-10: SLC,THPS,TVPS
      11: CGA    12: BPX         13: FGP/PPD/PPN/position code
    """
    tf: dict[int, str] = {}
    if impression_type is not None:
        tf[3]  = str(impression_type)
    tf[4]  = src
    tf[5]  = capture_date
    tf[6]  = str(hll)
    tf[7]  = str(vll)
    tf[8]  = str(scale_units)
    tf[9]  = str(h_pixel_scale)
    tf[10] = str(v_pixel_scale)
    tf[11] = compression
    if bpx is not None:
        tf[12] = str(bpx)
    if position is not None:
        tf[13] = str(position)
    if extra_fields:
        tf.update(extra_fields)
    return _build_ascii_binary_record(record_type, idc, tf, image_data)


# ---------------------------------------------------------------------------
# Type-13 record (ASCII+Binary – latent friction ridge image)
# ---------------------------------------------------------------------------

def build_type13(
    *,
    idc: int,
    src: str,
    capture_date: str,
    hll: int,
    vll: int,
    scale_units: int,
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,
    image_data: bytes,
    impression_type: int = IMP_LATENT_IMAGE,  # default 4 (latent)
    finger_position: int | None = None,
    bpx: int = 8,                             # BPX is mandatory for Type-13
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """Build a Type-13 Latent Friction Ridge Image Record."""
    return build_variable_res_record(
        13, idc=idc, src=src, capture_date=capture_date, hll=hll, vll=vll,
        scale_units=scale_units, h_pixel_scale=h_pixel_scale,
        v_pixel_scale=v_pixel_scale, compression=compression, image_data=image_data,
        impression_type=impression_type, position=finger_position, bpx=bpx,
        extra_fields=extra_fields,
    )


# ---------------------------------------------------------------------------
# Type-16 record (ASCII+Binary – user-defined variable-resolution image)
# ---------------------------------------------------------------------------

def build_type16(
    *,
    idc: int,
    src: str,
    capture_date: str,
    hll: int,
    vll: int,
    scale_units: int,
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,
    image_data: bytes,
    user_defined_type: str | None = None,  # field 16.003 (UDI)
    position: int | None = None,           # field 16.013
    bpx: int | None = None,
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """Build a Type-16 User-defined Variable-Resolution Image Record."""
    ef: dict[int, str] = {}
    if user_defined_type:
        ef[3] = user_defined_type
    if extra_fields:
        ef.update(extra_fields)
    return build_variable_res_record(
        16, idc=idc, src=src, capture_date=capture_date, hll=hll, vll=vll,
        scale_units=scale_units, h_pixel_scale=h_pixel_scale,
        v_pixel_scale=v_pixel_scale, compression=compression, image_data=image_data,
        impression_type=None, position=position, bpx=bpx,
        extra_fields=ef or None,
    )


# ---------------------------------------------------------------------------
# Type-19 record (ASCII+Binary – plantar / foot sole image)
# ---------------------------------------------------------------------------

def build_type19(
    *,
    idc: int,
    src: str,
    capture_date: str,
    hll: int,
    vll: int,
    scale_units: int,
    h_pixel_scale: int,
    v_pixel_scale: int,
    compression: str,
    image_data: bytes,
    impression_type: int = IMP_LIVE_SCAN_PLAIN,
    plantar_position: int | None = None,
    bpx: int | None = None,
    extra_fields: dict[int, str] | None = None,
) -> bytes:
    """Build a Type-19 Variable-Resolution Plantar Image Record."""
    return build_variable_res_record(
        19, idc=idc, src=src, capture_date=capture_date, hll=hll, vll=vll,
        scale_units=scale_units, h_pixel_scale=h_pixel_scale,
        v_pixel_scale=v_pixel_scale, compression=compression, image_data=image_data,
        impression_type=impression_type, position=plantar_position, bpx=bpx,
        extra_fields=extra_fields,
    )


# ---------------------------------------------------------------------------
# Transaction assembler
# ---------------------------------------------------------------------------

def assemble_transaction(records: list[bytes]) -> bytes:
    """
    Assemble multiple records into a complete NIST transaction.

    Records are already terminated with FS; simply concatenate them.
    The Type-1 record must be first.
    """
    return b"".join(records)
