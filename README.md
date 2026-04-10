# nist-builder-mcp

An MCP server for building, inspecting, and manipulating **NIST ANSI/NIST-ITL 1-2011
(Update 2015)** biometric transaction files in Traditional encoding — directly from
natural-language prompts via Claude.

## What is a NIST file?

The NIST/ITL standard defines a container format for sharing biometric data
(fingerprints, face images, iris scans, palm prints, minutiae, etc.) between agencies
and systems. A transaction file contains one mandatory **Type-1** header record plus
one or more content records.

## Installation

### From source
```bash
git clone https://github.com/mweerden-senstrack/nist-builder-mcp.git
cd nist-builder-mcp
pip install -e .
```

### From PyPI (once published)
```bash
pip install nist-builder-mcp
```

**Dependencies:** `mcp>=1.0.0`, `Pillow>=10.0`, `wsq>=0.8`

## Claude Code configuration

After installing, add to your Claude Code MCP config (`~/.claude.json` or Claude
Desktop `claude_desktop_config.json`) under `mcpServers`:

```json
"nist-builder": {
  "command": "nist-builder-mcp"
}
```

If running from source without installing:
```json
"nist-builder": {
  "command": "python3",
  "args": ["/path/to/nist-builder-mcp/server.py"]
}
```

## Tools

| Tool | Description |
|------|-------------|
| `nist_build_transaction` | Build and write a complete `.nist` file from record specifications |
| `nist_describe_record_types` | Reference for all record types, mandatory fields, and encoding rules |
| `nist_decode_file` | Inspect / pretty-print an existing `.nist` file — all record types |
| `nist_extract_images` | Extract all image payloads to files (`type{TT}_idc{NN}.ext`) |
| `nist_convert_record_type` | Convert records between types (e.g. binary Type-4 → variable-res Type-14) |
| `nist_recode_image_compression` | Re-encode image payloads to a different compression (e.g. WSQ → PNG) |

## Supported record types

| Type | Content | Encoding |
|------|---------|----------|
| 1 | Transaction information header (always auto-generated) | ASCII |
| 2 | User-defined descriptive text | ASCII |
| 3 | Low-resolution binary fingerprint (500 ppi) | Binary |
| 4 | High-resolution binary fingerprint (500/1000 ppi) | Binary |
| 5 | Low-resolution binary fingerprint (500 ppi) | Binary |
| 6 | High-resolution binary fingerprint (500/1000 ppi) | Binary |
| 9 | Minutiae data | ASCII |
| 10 | Photographic body-part imagery (face, SMT, scar, …) | ASCII+Binary |
| 13 | Latent friction ridge image | ASCII+Binary |
| 14 | Variable-resolution fingerprint image | ASCII+Binary |
| 15 | Variable-resolution palm print image | ASCII+Binary |
| 16 | User-defined variable-resolution image | ASCII+Binary |
| 17 | Iris image | ASCII+Binary |
| 19 | Plantar (foot) image | ASCII+Binary |

## Supported compressions

| Format | Code | Allowed record types |
|--------|------|---------------------|
| Uncompressed | `NONE` | all |
| WSQ (FBI wavelet) | `WSQ20` | 3–7, 13–16, 19 |
| JPEG baseline | `JPEGB` | all |
| JPEG lossless | `JPEGL` | all |
| JPEG 2000 | `JP2` | all |
| JPEG 2000 lossless | `JP2L` | all |
| PNG | `PNG` | all |

> **Note:** WSQ *decoding* (reading existing WSQ files) is fully supported.
> WSQ *encoding* (converting to WSQ) is not available — the `wsq` Python library
> is decode-only. Use `NBIS cwsq` if WSQ output is required.

## Example prompts for Claude

```
Build a NIST file at /tmp/enroll.nist with:
- TOT=IDV, originating agency=MYLAB, destination=CENTRALDB, TCN=CASE-001
- A Type-2 text record: first name JOHN, last name DOE, DOB 19801231
- A Type-14 fingerprint image from /data/right_index.wsq at 500 ppi
```

```
Decode and show me the contents of /tmp/enroll.nist
```

```
Convert all Type-4 fingerprint records in /tmp/enroll.nist to Type-14
and save to /tmp/enroll_v14.nist
```

```
Re-encode all WSQ fingerprint images in /tmp/enroll.nist to PNG
and save to /tmp/enroll_png.nist
```

## Key encoding facts

- **Separators**: FS=0x1C (between records), GS=0x1D (between fields),
  RS=0x1E (between subfields), US=0x1F (between info items)
- **Field format**: `TT.FFF:value`
- **LEN field** (`xx.001`): total byte count of the record including the trailing FS
- **Binary records** (Types 3–8): raw big-endian bytes, 18-byte header, no FS terminator
- **ASCII+Binary records** (Types 10, 13–17, 19): ASCII fields + binary field 999
- **VER**: `0502` for the 2015 update

## File structure

```
nist_builder/
  __init__.py
  encoder.py      # Pure-Python NIST encoder
  server.py       # MCP server with all tool definitions (canonical)
server.py         # Thin wrapper for running without install
pyproject.toml
README.md
```
