# Security Review: Third-Party Dependencies

This document lists every non-standard-library package pulled in by
`nist-builder-mcp`, what it does, how it is used here, and relevant
security considerations.

Audit performed with **pip-audit 2.10.0** against the PyPI OSV database.

---

## Known CVEs (audit results)

| Package | Version audited | CVE | Severity | Fixed in | Status |
|---------|----------------|-----|----------|----------|--------|
| Pillow | 10.2.0 | [CVE-2024-28219](https://nvd.nist.gov/vuln/detail/CVE-2024-28219) | Medium | 10.3.0 | **Fixed** — minimum bumped to `>=10.3.0` in `pyproject.toml` |

**CVE-2024-28219 detail:** Buffer overflow in `_imagingcms.c` — `strcpy` used
instead of `strncpy` in the ICC colour-management component. An attacker
supplying a maliciously crafted image with an embedded ICC profile could
trigger the overflow. In this project fingerprint/biometric images rarely
carry ICC profiles, but the vulnerable code path is reachable via Pillow's
`Image.open()`.

All other packages (mcp, wsq, and all transitives): **no known CVEs**.

---

## Runtime model

The server runs as a **stdio process** — it reads from stdin and writes to
stdout. No TCP ports are opened. No outbound network calls are made at
runtime. All file I/O is limited to paths explicitly passed by the MCP
client (Claude).

---

## Direct dependencies

### `mcp` ≥ 1.0.0 — Model Context Protocol SDK
| | |
|---|---|
| **Publisher** | Anthropic, PBC |
| **License** | MIT |
| **Installed version** | 1.26.0 |
| **Source** | https://github.com/modelcontextprotocol/python-sdk |

**Purpose:** Provides the `Server`, `Tool`, and `stdio_server` primitives that
expose tools over the MCP protocol.

**How used:** Server startup and tool dispatch only. The stdio transport is
used exclusively; the HTTP/SSE/WebSocket transports included in the package
are never invoked.

**Notes:** Pulls in a significant transitive dependency tree (see below) because
the SDK supports multiple transport modes. In stdio mode the HTTP stack
(uvicorn, starlette, httpx) is imported but idle.

---

### `Pillow` ≥ 10.3.0 — Python Imaging Library (fork)
| | |
|---|---|
| **Publisher** | Jeffrey A. Clark and contributors |
| **License** | HPND (Historical Permission Notice and Disclaimer — permissive) |
| **Minimum required** | 10.3.0 (bumped from 10.0 to exclude CVE-2024-28219) |
| **Source** | https://github.com/python-pillow/Pillow |

**Purpose:** Decodes and encodes image data (JPEG, JPEG 2000, PNG, raw pixels).

**How used:** Used only inside `_transcode_image()` when the
`nist_recode_image_compression` tool is called. Not loaded at import time —
imported lazily inside the function.

**Security considerations:**
- Pillow contains C extensions for image format parsing. Processing images from
  **untrusted NIST files** carries the same risk as processing any untrusted
  binary image data (historically: heap overflows in libjpeg/libpng wrappers).
- Pillow 10.x has an active CVE backlog; keep updated.
- Mitigant: input files are operator-supplied NIST transactions, not
  arbitrary untrusted content. The server does not expose an HTTP endpoint
  that could accept arbitrary uploads.

---

### `wsq` ≥ 0.8 — WSQ image codec (NBIS wrapper)
| | |
|---|---|
| **Publisher** | IDEMIA / open-source contributors |
| **License** | **CeCILL-C** (French copyleft, functionally similar to LGPL) |
| **Installed version** | 0.8 |
| **Source** | https://github.com/idemia/python-wsq |

**Purpose:** Decodes WSQ (Wavelet Scalar Quantization) fingerprint images —
the FBI/NIST standard compression for 8-bit grayscale fingerprints.

**How used:** Imported lazily inside `_transcode_image()` as a Pillow plugin.
Activates only when a source image has compression `WSQ` or `WSQ20`.
WSQ *encoding* is not supported by this library; the tool raises an error
if WSQ is requested as an output format.

**Security considerations:**
- Wraps the NBIS C library (FBI/NIST Biometric Image Software). The C layer
  parses untrusted binary WSQ streams; malformed files could trigger C-level
  memory errors.
- The CeCILL-C license has **copyleft implications**: if you distribute a
  modified version of this library you must release the modifications under
  CeCILL-C. Using it unmodified (as done here) carries no redistribution
  obligation beyond license notice retention.
- The `wsq` package on PyPI ships pre-built wheels; verify the wheel hashes
  against the published release if supply-chain integrity is required.

---

## Transitive dependencies (via `mcp`)

These are pulled in by the MCP SDK. They are not directly called by this
server's code.

| Package | Version | License | Role in mcp |
|---------|---------|---------|-------------|
| `anyio` | 4.13.0 | MIT | Async I/O abstraction |
| `httpx` | 0.28.1 | BSD-3-Clause | HTTP client (SSE/HTTP transport) |
| `httpx-sse` | 0.4.3 | MIT | SSE streaming for httpx |
| `jsonschema` | 4.26.0 | MIT | Tool input schema validation |
| `pydantic` | 2.12.5 | MIT | Message model validation |
| `pydantic-settings` | 2.13.1 | MIT | Config loading |
| `PyJWT` | 2.12.1 | MIT | JWT auth (HTTP transport) |
| `python-multipart` | 0.0.22 | Apache-2.0 | Multipart body parsing |
| `sse-starlette` | 3.3.3 | BSD-3-Clause | SSE server endpoint |
| `starlette` | 1.0.0 | BSD-3-Clause | ASGI framework |
| `typing_extensions` | 4.15.0 | PSF-2.0 | Backported type hints |
| `typing-inspection` | 0.4.2 | MIT | Runtime type inspection |
| `uvicorn` | 0.42.0 | BSD-3-Clause | ASGI server |
| `idna` | 3.7 | BSD-like | Internationalised domain names |

**Notes:**
- All transitive dependencies use permissive licenses (MIT, BSD, Apache, PSF).
- `uvicorn`, `starlette`, `httpx`, `PyJWT`, `python-multipart`, and
  `sse-starlette` are never invoked in stdio mode. They are imported by the
  MCP SDK at startup but remain idle.
- `jsonschema` and `pydantic` actively validate every tool call's input
  parameters before the handler runs.

---

## Standard library modules used

No security implications; all are part of the CPython distribution.

| Module | Purpose |
|--------|---------|
| `base64` | Encode/decode image bytes in tool I/O |
| `io` | In-memory byte buffers for image transcoding |
| `struct` | Parse big-endian integer fields in binary records |
| `datetime` | Generate `DAT` field (today's date) in Type-1 records |
| `pathlib` | Safe file path handling |
| `typing` | Type annotations only |
| `asyncio` | Entry-point event loop |

---

## Summary

| Concern | Status |
|---------|--------|
| Network exposure | None — stdio only |
| Outbound connections | None at runtime |
| File system access | Scoped to paths provided by the MCP client |
| C extensions | Pillow (libjpeg/libpng/…), wsq (NBIS) — both process operator-supplied files |
| Copyleft licenses | wsq (CeCILL-C) — unmodified use has no redistribution obligation |
| Permissive licenses | All other dependencies |
| Unused HTTP stack | Imported (via mcp) but never active in stdio mode |
