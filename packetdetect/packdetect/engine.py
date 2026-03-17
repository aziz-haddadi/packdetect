

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SectionResult:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    flags: int

    @property
    def is_executable(self) -> bool:
        return bool(self.flags & 0x20000000)

    @property
    def entropy_label(self) -> str:
        if self.entropy >= 7.0:
            return "HIGH"
        if self.entropy >= 6.0:
            return "SUSPICIOUS"
        return "NORMAL"


@dataclass
class SignatureMatch:
    name: str
    version: str
    offset: int
    confidence: int         
    description: str


@dataclass
class HeuristicFinding:
    name: str
    description: str
    score: int              


@dataclass
class AnalysisResult:
    # File info
    path: Path
    file_size: int
    md5: str
    sha256: str
    elapsed: float

    # PE basics
    is_pe: bool
    arch: str               
    entry_point: int
    entry_point_section: str

    # Entropy
    overall_entropy: float
    sections: list[SectionResult]

    # Detection
    signatures: list[SignatureMatch]
    heuristics: list[HeuristicFinding]

    # Verdict
    packer_name: str        
    confidence: int          
    verdict: str             
    risk: str                

    # Unpack
    unpack_command: Optional[str] = None
    unpack_supported: bool = False


class PEParser:
   
    def __init__(self, data: bytes):
        self.data = data
        self.valid = False
        self.machine = 0
        self.entry_point = 0
        self.image_base = 0
        self.sections: list[dict] = []
        self.num_imports = 0
        self._parse()

    def _u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self) -> None:
        if len(self.data) < 64:
            return
        if self.data[:2] != b"MZ":
            return
        pe_offset = self._u32(0x3C)
        if pe_offset + 24 > len(self.data):
            return
        
        if self.data[pe_offset: pe_offset + 4] != b"PE\x00\x00":
            return
        self.valid = True

        
        coff = pe_offset + 4
        self.machine = self._u16(coff)          
        num_sections = self._u16(coff + 2)
        opt_size = self._u16(coff + 16)

        
        opt = coff + 20
        magic = self._u16(opt)                  
        if magic == 0x10B:                      
            self.entry_point = self._u32(opt + 16)
            self.image_base = self._u32(opt + 28)
        elif magic == 0x20B:                   
            self.entry_point = self._u32(opt + 16)
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]

        # Import directory (data dir entry 1) — just count imports roughly
        if magic == 0x10B and opt_size >= 128:
            import_rva = self._u32(opt + 104)
        elif magic == 0x20B and opt_size >= 144:
            import_rva = self._u32(opt + 120)
        else:
            import_rva = 0
        self.num_imports = 1 if import_rva else 0  # rough: present/absent

        # Section headers
        sec_table = pe_offset + 4 + 20 + opt_size
        for i in range(min(num_sections, 96)):
            off = sec_table + i * 40
            if off + 40 > len(self.data):
                break
            raw_name = self.data[off: off + 8]
            name = raw_name.rstrip(b"\x00").decode("ascii", errors="replace")
            vsize  = self._u32(off + 8)
            vaddr  = self._u32(off + 12)
            rawsz  = self._u32(off + 16)
            rawptr = self._u32(off + 20)
            flags  = self._u32(off + 36)
            self.sections.append(
                dict(name=name, virtual_size=vsize, virtual_address=vaddr,
                     raw_size=rawsz, raw_ptr=rawptr, flags=flags)
            )

    @property
    def arch(self) -> str:
        return {0x14C: "x86", 0x8664: "x64"}.get(self.machine, "unknown")


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

# Each signature: (name, version, pattern_bytes_or_section_names, description)
# pattern is a list of (offset_hint, bytes_or_None) tuples;
# section_names is a list of known section name substrings.
SIGNATURE_DB: list[dict] = [
    {
        "name": "UPX",
        "version": "3.x",
        "magic": [b"UPX!", b"UPX0", b"UPX1"],
        "section_names": ["UPX0", "UPX1", "UPX2"],
        "ep_stub": None,
        "description": "UPX compression — magic bytes or section names found",
        "confidence": 95,
        "unpack_cmd": "upx -d {input} -o {output}",
    },
    {
        "name": "MPRESS",
        "version": "2.x",
        "magic": [b".MPRESS1", b".MPRESS2"],
        "section_names": [".MPRESS1", ".MPRESS2"],
        "ep_stub": None,
        "description": "MPRESS compression — section names .MPRESS1/.MPRESS2 detected",
        "confidence": 95,
        "unpack_cmd": "mpress -decompress {input}",
    },
    {
        "name": "ASPack",
        "version": "2.x",
        "magic": [b".adata", b"ASPack"],
        "section_names": [".adata"],
        "ep_stub": bytes([0x60, 0xE8]),          # pusha + call (EP stub pattern)
        "description": "ASPack — section name .adata and/or EP stub pattern",
        "confidence": 85,
        "unpack_cmd": None,
    },
    {
        "name": "PECompact",
        "version": "2.x",
        "magic": [b"PEC2"],
        "section_names": [],
        "ep_stub": bytes([0xEB, 0x06]),
        "description": "PECompact — PEC2 signature or short-jmp EP stub",
        "confidence": 80,
        "unpack_cmd": None,
    },
    {
        "name": "Themida/WinLicense",
        "version": "3.x",
        "magic": [b".themida", b"WinLicense"],
        "section_names": [".themida"],
        "ep_stub": bytes([0x9C, 0x60, 0xE8, 0x00, 0x00, 0x00, 0x00]),
        "description": "Themida/WinLicense VM protector — section name or VM EP stub",
        "confidence": 90,
        "unpack_cmd": None,
    },
    {
        "name": "VMProtect",
        "version": "2.x-3.x",
        "magic": [b".vmp0", b".vmp1"],
        "section_names": [".vmp0", ".vmp1"],
        "ep_stub": None,
        "description": "VMProtect — .vmp section names detected",
        "confidence": 90,
        "unpack_cmd": None,
    },
    {
        "name": "NSIS",
        "version": "any",
        "magic": [b"NullsoftInst"],
        "section_names": [],
        "ep_stub": None,
        "description": "NSIS installer wrapper detected",
        "confidence": 75,
        "unpack_cmd": None,
    },
    {
        "name": "FSG",
        "version": "2.0",
        "magic": [],
        "section_names": [],
        "ep_stub": bytes([0xBB, 0x00, 0x00, 0x40, 0x00, 0xBF]),
        "description": "FSG (Fast Small Good) packer — EP stub pattern",
        "confidence": 80,
        "unpack_cmd": None,
    },
    {
        "name": "Petite",
        "version": "2.x",
        "magic": [b".petite"],
        "section_names": [".petite"],
        "ep_stub": None,
        "description": "Petite packer — .petite section detected",
        "confidence": 88,
        "unpack_cmd": None,
    },
]


def scan_signatures(data: bytes, sections: list[dict]) -> list[SignatureMatch]:
    """Scan file bytes and section names against the signature DB."""
    matches: list[SignatureMatch] = []
    section_names = {s["name"].lower() for s in sections}

    for sig in SIGNATURE_DB:
        hit = False
        hit_offset = -1

        # 1. Magic byte scan
        for magic in sig.get("magic", []):
            pos = data.find(magic)
            if pos != -1:
                hit = True
                hit_offset = pos
                break

        # 2. Section name scan
        if not hit:
            for sname in sig.get("section_names", []):
                if sname.lower() in section_names:
                    hit = True
                    hit_offset = 0
                    break

        # 3. EP stub check (first 16 bytes of first section)
        ep_stub = sig.get("ep_stub")
        if not hit and ep_stub and len(data) > 0x400:
            # check from PE entry point (rough: first executable section)
            for s in sections:
                if s.get("flags", 0) & 0x20000000:
                    ptr = s["raw_ptr"]
                    chunk = data[ptr: ptr + len(ep_stub)]
                    if chunk == ep_stub:
                        hit = True
                        hit_offset = ptr
                    break

        if hit:
            matches.append(SignatureMatch(
                name=sig["name"],
                version=sig["version"],
                offset=hit_offset,
                confidence=sig["confidence"],
                description=sig["description"],
            ))

    return matches


# ---------------------------------------------------------------------------
# Heuristic detection (catches unknown packers)
# ---------------------------------------------------------------------------

def run_heuristics(
    data: bytes,
    pe: PEParser,
    sections: list[SectionResult],
    overall_entropy: float,
) -> list[HeuristicFinding]:
    """
    Structural heuristics that flag anomalies regardless of known signatures.
    Each finding carries a score; the sum feeds the confidence calculation.
    """
    findings: list[HeuristicFinding] = []

    # H1: High overall entropy
    if overall_entropy >= 7.5:
        findings.append(HeuristicFinding(
            "Very high overall entropy",
            f"Overall entropy {overall_entropy:.3f} ≥ 7.5 — strongly suggests encryption or compression",
            score=35,
        ))
    elif overall_entropy >= 7.0:
        findings.append(HeuristicFinding(
            "High overall entropy",
            f"Overall entropy {overall_entropy:.3f} ≥ 7.0 — likely compressed or encrypted payload",
            score=25,
        ))
    elif overall_entropy >= 6.5:
        findings.append(HeuristicFinding(
            "Elevated overall entropy",
            f"Overall entropy {overall_entropy:.3f} in suspicious range 6.5–7.0",
            score=12,
        ))

    # H2: Section with near-zero raw size but large virtual size
    for sec in sections:
        if sec.virtual_size > 4096 and sec.raw_size < 512:
            findings.append(HeuristicFinding(
                "Virtual-only section",
                f"Section '{sec.name}': raw_size={sec.raw_size}, virtual_size={sec.virtual_size} "
                f"— will expand in memory (classic packer stub placeholder)",
                score=30,
            ))
            break

    # H3: High-entropy executable section
    for sec in sections:
        if sec.is_executable and sec.entropy >= 7.0 and sec.raw_size > 1024:
            findings.append(HeuristicFinding(
                "High-entropy executable section",
                f"Section '{sec.name}' is executable with entropy {sec.entropy:.3f} — "
                "compressed/encrypted code section",
                score=30,
            ))
            break

    # H4: Very few imports (packed binaries rebuild their own IAT)
    if pe.valid:
        import_count = pe.num_imports
        # We count GetProcAddress/LoadLibrary as a proxy; 0 imports is a flag
        if import_count == 0:
            findings.append(HeuristicFinding(
                "No import table",
                "Import directory is absent or empty — packed binaries resolve "
                "imports dynamically at runtime",
                score=25,
            ))

    # H5: Entry point not in .text
    if pe.valid and sections:
        ep = pe.entry_point
        ep_section = _ep_section_name(ep, sections)
        if ep_section and ep_section.lower() not in (".text", "code", ".code"):
            findings.append(HeuristicFinding(
                "Entry point outside .text",
                f"EP (RVA 0x{ep:08X}) resolves to section '{ep_section}', "
                "not the standard code section",
                score=20,
            ))

    # H6: Suspicious ratio raw_size/virtual_size across all sections
    total_raw = sum(s.raw_size for s in sections)
    total_virt = sum(s.virtual_size for s in sections)
    if total_virt > 0 and total_raw > 0:
        ratio = total_raw / total_virt
        if ratio < 0.25:
            findings.append(HeuristicFinding(
                "Low raw/virtual size ratio",
                f"Total raw={total_raw}, virtual={total_virt} (ratio {ratio:.2f}) — "
                "large runtime expansion consistent with decompression",
                score=15,
            ))

    # H7: Non-standard or cleared section names
    standard = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".bss",
                ".edata", ".idata", ".pdata", ".tls", "code", "data"}
    weird_names = [s.name for s in sections
                   if s.name and s.name.lower() not in standard
                   and not s.name.startswith(".")]
    if len(weird_names) >= 2:
        findings.append(HeuristicFinding(
            "Non-standard section names",
            f"Sections with unusual names: {weird_names} — "
            "many packers rename or clear section names",
            score=10,
        ))

    return findings


def _ep_section_name(ep_rva: int, sections: list[SectionResult]) -> Optional[str]:
    for sec in sections:
        start = sec.virtual_address
        end = start + max(sec.virtual_size, sec.raw_size)
        if start <= ep_rva < end:
            return sec.name
    return None


# ---------------------------------------------------------------------------
# Verdict computation
# ---------------------------------------------------------------------------

def compute_verdict(
    signatures: list[SignatureMatch],
    heuristics: list[HeuristicFinding],
    overall_entropy: float,
) -> tuple[str, str, int, str]:
    """
    Returns (packer_name, verdict, confidence, risk).
    verdict: "clean" | "packed" | "unknown_packer" | "suspicious"
    """
    # Known signature hit — high confidence verdict
    if signatures:
        best = max(signatures, key=lambda s: s.confidence)
        heuristic_bonus = min(sum(h.score for h in heuristics), 10)
        conf = min(best.confidence + heuristic_bonus, 99)
        risk = "HIGH" if conf >= 80 else "MEDIUM"
        return best.name, "packed", conf, risk

    # No signature — rely on heuristics
    score = sum(h.score for h in heuristics)

    if score >= 60:
        return "Unknown", "unknown_packer", min(score, 94), "HIGH"
    if score >= 30 or overall_entropy >= 6.5:
        return "", "suspicious", min(score + 15, 79), "MEDIUM"
    return "", "clean", max(0, 20 - score), "LOW"


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

def analyse(path: Path) -> AnalysisResult:
    """Full analysis pipeline. Returns an AnalysisResult."""
    t0 = time.perf_counter()

    data = path.read_bytes()
    file_size = len(data)

    # Hashes
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # PE parse
    pe = PEParser(data)
    arch = pe.arch if pe.valid else "unknown"

    # Build SectionResult list with entropy
    section_results: list[SectionResult] = []
    for s in pe.sections:
        ptr = s["raw_ptr"]
        size = s["raw_size"]
        chunk = data[ptr: ptr + size] if size and ptr else b""
        ent = shannon_entropy(chunk) if chunk else 0.0
        section_results.append(SectionResult(
            name=s["name"],
            virtual_address=s["virtual_address"],
            virtual_size=s["virtual_size"],
            raw_size=s["raw_size"],
            entropy=ent,
            flags=s["flags"],
        ))

    # Overall entropy (whole file)
    overall_entropy = shannon_entropy(data)

    # EP section
    ep = pe.entry_point if pe.valid else 0
    ep_section = _ep_section_name(ep, section_results) or "?"

    # Signature scan
    signatures = scan_signatures(data, pe.sections) if pe.valid else []

    # Heuristics (also run on non-PE files if high entropy)
    heuristics = run_heuristics(data, pe, section_results, overall_entropy)

    # Verdict
    packer_name, verdict, confidence, risk = compute_verdict(
        signatures, heuristics, overall_entropy
    )

    # Unpack command
    unpack_cmd: Optional[str] = None
    unpack_supported = False
    if signatures:
        for sig in SIGNATURE_DB:
            if sig["name"] == signatures[0].name and sig.get("unpack_cmd"):
                unpack_supported = True
                output = path.with_stem(path.stem + "_unpacked")
                unpack_cmd = sig["unpack_cmd"].format(
                    input=str(path), output=str(output)
                )
                break

    elapsed = time.perf_counter() - t0

    return AnalysisResult(
        path=path,
        file_size=file_size,
        md5=md5,
        sha256=sha256,
        elapsed=round(elapsed, 3),
        is_pe=pe.valid,
        arch=arch,
        entry_point=ep,
        entry_point_section=ep_section,
        overall_entropy=overall_entropy,
        sections=section_results,
        signatures=signatures,
        heuristics=heuristics,
        packer_name=packer_name,
        confidence=confidence,
        verdict=verdict,
        risk=risk,
        unpack_command=unpack_cmd,
        unpack_supported=unpack_supported,
    )


# ---------------------------------------------------------------------------
# Unpacker
# ---------------------------------------------------------------------------

@dataclass
class UnpackResult:
    success: bool
    command: str
    stdout: str
    stderr: str
    output_path: Optional[Path]
    message: str


def attempt_unpack(result: AnalysisResult) -> UnpackResult:
    """Run the appropriate unpacker via subprocess."""
    if not result.unpack_supported or not result.unpack_command:
        return UnpackResult(
            success=False,
            command="",
            stdout="",
            stderr="",
            output_path=None,
            message="No supported unpacker available for this packer.",
        )

    cmd = result.unpack_command
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        output_path = result.path.with_stem(result.path.stem + "_unpacked")
        success = proc.returncode == 0 and output_path.exists()
        return UnpackResult(
            success=success,
            command=cmd,
            stdout=proc.stdout.strip(),
            stderr=proc.stderr.strip(),
            output_path=output_path if success else None,
            message="Unpacked successfully." if success else
                    f"Unpacker exited with code {proc.returncode}.",
        )
    except FileNotFoundError:
        tool = cmd.split()[0]
        return UnpackResult(
            success=False,
            command=cmd,
            stdout="",
            stderr="",
            output_path=None,
            message=f"Tool '{tool}' not found. Install it and add to PATH.",
        )
    except subprocess.TimeoutExpired:
        return UnpackResult(
            success=False,
            command=cmd,
            stdout="",
            stderr="",
            output_path=None,
            message="Unpacker timed out after 30 seconds.",
        )
