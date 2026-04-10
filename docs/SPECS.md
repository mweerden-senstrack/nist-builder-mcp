# NIST Specification Files

## Included (public domain — NIST Special Publication)

| File | Description |
|------|-------------|
| [`specs/NIST.SP.500-290e3.pdf`](specs/NIST.SP.500-290e3.pdf) | ANSI/NIST-ITL 1-2011 Update 2015 (616 pp) — **primary reference** |

Key sections:
- **§5.3 (p. 85)** — Record types overview
- **§8.1 (p. 164)** — Type-1 mandatory fields
- **Annex B (p. 554)** — Traditional encoding rules (separators, LEN computation, field format)

Official download: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-290e3.pdf

---

## Not included (obtain separately)

The following documents are ANSI or INTERPOL publications and are not freely
redistributable. Download them from their respective official sources.

### ANSI/NIST-ITL historical versions

| Document | Where to obtain |
|----------|----------------|
| ANSI/NIST-ITL 1-2011 Update 2015 | [ANSI Webstore](https://webstore.ansi.org) — search `NIST ITL 1-2011` |
| ANSI/NIST-ITL 1-2011 Update 2013 | ANSI Webstore — search `NIST ITL 1-2011` |
| ANSI/NIST-ITL 1-2011 | ANSI Webstore — search `NIST ITL 1-2011` |
| ANSI/NIST-ITL 1-2007 | ANSI Webstore — search `NIST ITL 1-2007` |
| ANSI/NIST-ITL 1-2000 | ANSI Webstore — search `NIST ITL 1-2000` |

> **Note:** NIST.SP.500-290e3.pdf (included above) is the NIST-published version of
> the 2015 Update and is functionally equivalent to the ANSI-branded edition.

### INTERPOL INT-I standard

| Document | Where to obtain |
|----------|----------------|
| NIST/INTERPOL INT-I v6.00.01 | [INTERPOL member portal](https://www.interpol.int) — requires membership access |

---

## Using specs with Claude

When the MCP tool encounters an error or ambiguous field, ask Claude to look up the
relevant section before guessing:

```
Using the spec at docs/specs/NIST.SP.500-290e3.pdf, look up field 14.013
and tell me what values are allowed.
```

```
Check Annex B of the NIST spec to confirm how the LEN field is computed
for ASCII+Binary records.
```
