# PackDetect

A command-line packer detection and unpacking tool for Windows PE binaries (`.exe`, `.dll`, `.sys`). Built for reverse engineers and malware analysts.

```
  ____            _     ____       _            _
 |  _ \ __ _  ___| | __| __ )  ___| |_ ___  ___| |_
 | |_) / _` |/ __| |/ /  _ \ / _ \ __/ _ \/ __| __|
 |  __/ (_| | (__|   <| |_) |  __/ ||  __/ (__| |_
 |_|   \__,_|\___|_|\_\____/ \___|\__\___|\___|\__|
```

---

## Features

- **Shannon entropy analysis** — per-section and whole-file entropy with colour-coded output
- **Signature database** — UPX, MPRESS, ASPack, PECompact, Themida/WinLicense, VMProtect, FSG, Petite, NSIS
- **Unknown packer detection** — structural heuristics that catch custom/obfuscated packers with no known signature
- **Auto-unpack** — calls `upx -d` or `mpress -decompress` via subprocess for supported packers
- **Batch mode** — scan an entire directory and get a summary table
- **JSON export** — machine-readable output for integration into pipelines
- **Rich UI + plain fallback** — beautiful coloured output with `rich`; degrades gracefully to plain ASCII with `--plain`
- **Zero PE-library dependencies** — the PE parser is pure stdlib `struct`; only `rich` is optional

---

## How it works

Detection runs in three layers, each feeding into a weighted confidence score:

```
┌─────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│   Layer 1       │   │   Layer 2        │   │   Layer 3            │
│ Entropy         │──▶│ Signature scan   │──▶│ Heuristics           │
│ Shannon H(x)    │   │ magic bytes +    │   │ EP location, import  │
│ per section     │   │ section names    │   │ count, size ratios   │
└─────────────────┘   └──────────────────┘   └──────────────────────┘
                                   │
                          Verdict + confidence%
```

**Layer 1 — Entropy:**
Shannon entropy (0–8 bits/byte). Packed/encrypted sections score above 7.0. Normal compiled code sits between 4.5–6.5.

**Layer 2 — Signatures:**
Searches for packer-specific magic bytes (e.g. `UPX!`) and known section names (e.g. `.MPRESS1`). Contributes up to 95% base confidence.

**Layer 3 — Heuristics (unknown packer detection):**
Structural anomalies that fire even when no signature matches:
- Virtual-only sections (raw_size ≈ 0, virtual_size >> 0) — packer decompression placeholder
- Entry point outside `.text`
- No import table — packed binaries rebuild their IAT dynamically
- Low raw/virtual size ratio across all sections
- Non-standard section names

---

## Installation

```bash
# Clone
git clone https://github.com/you/packdetect
cd packdetect

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Mac / Linux

# Install (editable mode — code changes apply instantly)
pip install -e .

# Or without Rich (plain ASCII mode only)
pip install -e . --no-deps
```

**Requirements:**
- Python 3.12+
- `rich >= 13.0` (optional — install for coloured output)
- `upx` on PATH (optional — required for auto-unpack of UPX binaries)
- `mpress` on PATH (optional — required for auto-unpack of MPRESS binaries)

---

## Quick start — test with the included real malware sample

This repository ships with a **real UPX-packed malware sample** inside `malware-lab/` so you can test the tool against a genuine packed binary immediately.

> ⚠️ **The sample is provided for static analysis only — do not execute it.**
> Keep it in an isolated folder or VM. It was obtained from [MalwareBazaar](https://bazaar.abuse.ch),
> a public malware repository maintained by abuse.ch for the security research community.

### Full scan with Rich output

```powershell
packdetect scan ..\..\malware-lab\7d7655e9446fd41dc1ae859435f39c250964532bc604c9bf6d737992430d645e.exe
```

### Plain ASCII output (no colours)

```powershell
packdetect scan ..\..\malware-lab\7d7655e9446fd41dc1ae859435f39c250964532bc604c9bf6d737992430d645e.exe --plain
```

### Save a JSON report

```powershell
packdetect scan ..\..\malware-lab\7d7655e9446fd41dc1ae859435f39c250964532bc604c9bf6d737992430d645e.exe --save-json
```

This writes a `.packdetect.json` report alongside the sample containing the full analysis — entropy per section, signature match, heuristic findings, and verdict.

### Attempt auto-unpack

Make sure `upx` is installed and on your PATH first ([download here](https://upx.github.io)), then:

```powershell
packdetect unpack ..\..\malware-lab\7d7655e9446fd41dc1ae859435f39c250964532bc604c9bf6d737992430d645e.exe
```

This calls `upx -d` under the hood and produces a `_unpacked.exe` next to the original. Re-scan the unpacked file to confirm the entropy dropped back to normal range (~5.x):

```powershell
packdetect scan ..\..\malware-lab\7d7655e9446fd41dc1ae859435f39c250964532bc604c9bf6d737992430d645e_unpacked.exe
```

### Expected output

```
╭──────────────────────── Verdict ─────────────────────────╮
│  ⚠  PACKED                                                │
│                                                            │
│  Confidence : ██████████  97%                             │
│  Risk level : HIGH                                        │
│  Packer     : UPX                                         │
╰────────────────────────────────────────────────────────────╯

  Section    Entropy    Bar                        Flag
  ─────────  ─────────  ─────────────────────────  ──────────
  UPX0       0.0000     ░░░░░░░░░░░░░░░░░░░░░░░░   NORMAL
  UPX1       7.88xx     ████████████████████████   HIGH
  .rsrc      3.4xxx     ██████████░░░░░░░░░░░░░░   NORMAL

  [HIT]  UPX — magic bytes "UPX!" found in stub header
```

---

## Usage

### Scan a single binary

```bash
packdetect scan malware.exe
```

Output includes:
- File info (size, MD5, SHA-256, arch, entry point)
- Verdict panel with confidence score and risk level
- Per-section entropy table with colour-coded bars
- Signature scan results (hit / not detected)
- Heuristic findings with individual scores
- Unpack hint if a supported packer is detected

### Plain ASCII output (no Rich)

```bash
packdetect scan malware.exe --plain
```

### JSON output (pipe-friendly)

```bash
packdetect scan malware.exe --json
packdetect scan malware.exe --json | jq .verdict
```

### Save JSON report alongside the file

```bash
packdetect scan malware.exe --save-json
# writes malware.packdetect.json
```

### Auto-unpack

```bash
packdetect unpack upx_packed.exe
# calls: upx -d upx_packed.exe -o upx_packed_unpacked.exe
```

### Batch scan a directory

```bash
packdetect batch ./samples/
packdetect batch ./samples/ --all          # include non-PE extensions
packdetect batch ./samples/ --json         # JSON array to stdout
packdetect batch ./samples/ --save-json    # saves packdetect_batch.json
```

---

## Running the test suite

The project ships with **26 unit tests** covering the full engine — entropy math, PE parsing,
signature detection, heuristic logic, verdict computation, and end-to-end analysis.
They use only **synthetic in-memory PE binaries** built with `struct` — no real malware required.

### Install pytest and run

```bash
pip install pytest
pytest tests/ -v
```

### Expected output

```
tests/test_engine.py::TestShannonEntropy::test_all_zeros                          PASSED
tests/test_engine.py::TestShannonEntropy::test_all_same_byte                      PASSED
tests/test_engine.py::TestShannonEntropy::test_two_equal_bytes                    PASSED
tests/test_engine.py::TestShannonEntropy::test_uniform_distribution               PASSED
tests/test_engine.py::TestShannonEntropy::test_random_like_data                   PASSED
tests/test_engine.py::TestShannonEntropy::test_empty                              PASSED
tests/test_engine.py::TestPEParser::test_parses_minimal_pe                        PASSED
tests/test_engine.py::TestPEParser::test_rejects_non_pe                           PASSED
tests/test_engine.py::TestPEParser::test_rejects_too_short                        PASSED
tests/test_engine.py::TestPEParser::test_upx_section_names                        PASSED
tests/test_engine.py::TestSignatureScanner::test_upx_magic_detected               PASSED
tests/test_engine.py::TestSignatureScanner::test_upx_section_name_detected        PASSED
tests/test_engine.py::TestSignatureScanner::test_mpress_section_name_detected     PASSED
tests/test_engine.py::TestSignatureScanner::test_clean_binary_no_matches          PASSED
tests/test_engine.py::TestSignatureScanner::test_confidence_is_positive           PASSED
tests/test_engine.py::TestHeuristics::test_clean_no_heuristics                    PASSED
tests/test_engine.py::TestHeuristics::test_high_entropy_flagged                   PASSED
tests/test_engine.py::TestHeuristics::test_virtual_only_section_flagged           PASSED
tests/test_engine.py::TestHeuristics::test_high_entropy_exec_section_flagged      PASSED
tests/test_engine.py::TestVerdictComputation::test_signature_hit_gives_packed     PASSED
tests/test_engine.py::TestVerdictComputation::test_no_sig_high_heuristic_gives_unknown PASSED
tests/test_engine.py::TestVerdictComputation::test_clean_binary_verdict           PASSED
tests/test_engine.py::TestVerdictComputation::test_suspicious_medium_score        PASSED
tests/test_engine.py::TestAnalyseIntegration::test_clean_binary                   PASSED
tests/test_engine.py::TestAnalyseIntegration::test_upx_magic_in_file             PASSED
tests/test_engine.py::TestAnalyseIntegration::test_result_fields_populated        PASSED

26 passed in 0.22s
```

### Run with coverage report

```bash
pip install pytest-cov
pytest tests/ -v --cov=packdetect --cov-report=term-missing
```

### What each test class covers

| Class | What it tests |
|-------|--------------|
| `TestShannonEntropy` | Entropy math edge cases — all zeros, uniform distribution, random data |
| `TestPEParser` | PE header parsing — valid PE32, ELF rejection, section name decoding |
| `TestSignatureScanner` | UPX magic bytes, MPRESS section names, clean file returns empty list |
| `TestHeuristics` | Virtual-only sections, high-entropy exec sections, clean binary baseline |
| `TestVerdictComputation` | Known sig → packed, heuristics only → unknown packer, clean baseline |
| `TestAnalyseIntegration` | Full `analyse()` pipeline on synthetic PE binaries end-to-end |

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean / success |
| 2 | Packed binary detected |
| 3 | Suspicious (inconclusive) |
| 4 | Unpack not supported |
| 5 | Unpack attempted but failed |

Use exit codes in scripts:

```bash
packdetect scan "$file" --plain
if [ $? -eq 2 ]; then
    echo "Packed! Attempting unpack..."
    packdetect unpack "$file"
fi
```

---

## JSON output schema

```json
{
  "file": {
    "path": "malware.exe",
    "size": 45056,
    "md5": "...",
    "sha256": "...",
    "arch": "x86",
    "is_pe": true,
    "entry_point": "0x00001000",
    "entry_point_section": "UPX1",
    "elapsed_seconds": 0.012
  },
  "entropy": {
    "overall": 7.621,
    "sections": [
      { "name": "UPX0", "entropy": 0.12, "raw_size": 0, "virtual_size": 65536, "flag": "NORMAL" },
      { "name": "UPX1", "entropy": 7.89, "raw_size": 40960, "virtual_size": 40960, "flag": "HIGH" }
    ]
  },
  "signatures": [
    { "name": "UPX", "version": "3.x", "offset": "0x00000050", "confidence": 95, "description": "..." }
  ],
  "heuristics": [
    { "name": "Virtual-only section", "description": "...", "score": 30 }
  ],
  "verdict": {
    "verdict": "packed",
    "packer": "UPX",
    "confidence": 97,
    "risk": "HIGH",
    "unpack_supported": true,
    "unpack_command": "upx -d malware.exe -o malware_unpacked.exe"
  }
}
```

---

## Project structure

```
packdetect/
├── packdetect/
│   ├── __init__.py          version string
│   ├── __main__.py          CLI — argparse, commands: scan / unpack / batch
│   ├── engine.py            analysis engine — PE parser, entropy, signatures, heuristics
│   └── output.py            display — Rich renderer, plain renderer, JSON serialiser
├── malware-lab/
│   └── 7d7655e9...exe       real UPX-packed malware sample for testing
├── tests/
│   ├── __init__.py
│   └── test_engine.py       26 unit tests (no real binaries needed)
├── .gitignore
├── LICENSE
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Extending the signature database

Open `packdetect/engine.py` and add an entry to `SIGNATURE_DB`:

```python
{
    "name": "MyPacker",
    "version": "1.0",
    "magic": [b"\xDE\xAD\xBE\xEF"],          # bytes to search anywhere in file
    "section_names": [".mypkr"],               # section name substrings
    "ep_stub": bytes([0x60, 0xE8, 0x00]),      # bytes at start of first exec section
    "description": "MyPacker v1.0 signature",
    "confidence": 85,
    "unpack_cmd": None,                        # or "mytool -d {input} -o {output}"
},
```

---

## Concepts covered (portfolio talking points)

| Concept | Where |
|---------|-------|
| PE format (DOS/COFF/Optional headers, sections) | `engine.py` → `PEParser` |
| Shannon entropy | `engine.py` → `shannon_entropy()` |
| Packer signatures / YARA-style matching | `engine.py` → `SIGNATURE_DB`, `scan_signatures()` |
| Unknown packer heuristics | `engine.py` → `run_heuristics()` |
| Subprocess orchestration | `engine.py` → `attempt_unpack()` |
| CLI design with argparse | `__main__.py` |
| Rich terminal UI with plain fallback | `output.py` |
| Structured JSON reporting | `output.py` → `to_json()` |
| Exit codes for scripting integration | `__main__.py` |
| Unit testing without external binaries | `tests/test_engine.py` |

---

## Disclaimer

This tool and the included sample are for **educational and legitimate security research purposes only**.
The malware sample in `malware-lab/` was obtained from [MalwareBazaar](https://bazaar.abuse.ch) — a public
repository maintained by abuse.ch for the security research community.
Do not execute the sample outside of an isolated environment. The authors accept no responsibility for misuse.