

import math
import struct
import pytest
from pathlib import Path

from packdetect.engine import (
    shannon_entropy,
    scan_signatures,
    run_heuristics,
    compute_verdict,
    PEParser,
    SectionResult,
    analyse,
)




class TestShannonEntropy:
    def test_all_zeros(self):
        assert shannon_entropy(bytes(256)) == 0.0

    def test_all_same_byte(self):
        assert shannon_entropy(b"\xFF" * 1000) == 0.0

    def test_two_equal_bytes(self):
        data = b"\x00\xFF" * 500
        e = shannon_entropy(data)
        assert abs(e - 1.0) < 0.01

    def test_uniform_distribution(self):
        # All 256 byte values once — maximum entropy
        data = bytes(range(256))
        e = shannon_entropy(data)
        assert abs(e - 8.0) < 0.01

    def test_random_like_data(self):
        # Pseudo-random bytes via xorshift — expect high entropy
        data = bytearray(4096)
        x = 0xDEADBEEF
        for i in range(4096):
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= (x >> 7)
            x ^= (x << 17) & 0xFFFFFFFF
            data[i] = x & 0xFF
        e = shannon_entropy(bytes(data))
        assert e > 7.5, f"Expected > 7.5, got {e}"

    def test_empty(self):
        assert shannon_entropy(b"") == 0.0


def _build_minimal_pe(
    section_name: bytes = b".text\x00\x00\x00",
    section_data: bytes = b"\x90" * 512,
    ep_section: bool = True,
) -> bytes:
    
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40) 

    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes)
    coff = struct.pack("<HHIIIHH",
        0x14C,  # machine x86
        1,      # num sections
        0,      # timestamp
        0,      # ptr to symbol table
        0,      # num symbols
        96,     # size of optional header
        0x0002, # characteristics: executable
    )

    ep_rva = 0x1000 if ep_section else 0x2000
    opt = struct.pack(
        "<HBBIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,  # magic PE32
        14, 0,  # linker ver
        512, 0, 0,     # code/data/bss sizes
        ep_rva,        # entry point RVA
        0x1000,        # base of code
        0x2000,        # base of data
        0x00400000,    # image base
        0x1000,        # section alignment
        0x200,         # file alignment
        6, 0, 0, 0,    # OS/image/subsystem versions
        0, 1,          # win32 version / image version
        0x00010000,    # size of image
        0x400,         # size of headers
        0,             # checksum
        2,             # subsystem (GUI)
        0,             # DLL characteristics
        0x100000, 0x1000, 0x100000, 0x1000,  # stack/heap reserves/commits
        0,             # loader flags
        16,            # num data directories
    )
    # Pad opt to 96 bytes 
    opt = opt.ljust(96, b"\x00")

    # Zero out data directory 
    data_dirs = b"\x00" * 128

    # Section header (40 bytes)
    raw_offset = 0x40 + len(pe_sig) + len(coff) + len(opt) + len(data_dirs) + 40
    raw_offset = (raw_offset + 0x1FF) & ~0x1FF  # align to 0x200
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        section_name[:8].ljust(8, b"\x00"),
        len(section_data),  # virtual size
        0x1000,             # virtual address
        len(section_data),  # raw size
        raw_offset,         # raw ptr
        0, 0,               # relocs/line numbers
        0, 0,               # counts
        0x60000020,         # flags: code + exec + read
    )

    headers = bytes(dos) + pe_sig + coff + opt + data_dirs + sec_hdr
    # Pad headers to raw_offset
    headers = headers.ljust(raw_offset, b"\x00")
    return headers + section_data


# ---------------------------------------------------------------------------
# PEParser
# ---------------------------------------------------------------------------

class TestPEParser:
    def test_parses_minimal_pe(self):
        data = _build_minimal_pe()
        pe = PEParser(data)
        assert pe.valid
        assert pe.arch == "x86"
        assert pe.entry_point == 0x1000
        assert len(pe.sections) == 1
        assert ".text" in pe.sections[0]["name"] or pe.sections[0]["name"] == ""

    def test_rejects_non_pe(self):
        pe = PEParser(b"ELF\x00" + b"\x00" * 200)
        assert not pe.valid

    def test_rejects_too_short(self):
        pe = PEParser(b"MZ")
        assert not pe.valid

    def test_upx_section_names(self):
        data = _build_minimal_pe(section_name=b"UPX1\x00\x00\x00\x00")
        pe = PEParser(data)
        assert pe.valid
        assert pe.sections[0]["name"] == "UPX1"




class TestSignatureScanner:
    def test_upx_magic_detected(self):
        data = b"\x00" * 256 + b"UPX!" + b"\x00" * 256
        matches = scan_signatures(data, [])
        names = [m.name for m in matches]
        assert "UPX" in names

    def test_upx_section_name_detected(self):
        data = b"MZ" + b"\x00" * 4096
        sections = [{"name": "UPX1", "flags": 0, "raw_ptr": 0, "raw_size": 0}]
        matches = scan_signatures(data, sections)
        assert any(m.name == "UPX" for m in matches)

    def test_mpress_section_name_detected(self):
        data = b"MZ" + b"\x00" * 4096
        sections = [{"name": ".MPRESS1", "flags": 0, "raw_ptr": 0, "raw_size": 0}]
        matches = scan_signatures(data, sections)
        assert any(m.name == "MPRESS" for m in matches)

    def test_clean_binary_no_matches(self):
        data = b"MZ" + b"\x00" * 4096
        sections = [{"name": ".text", "flags": 0, "raw_ptr": 0, "raw_size": 0}]
        matches = scan_signatures(data, sections)
        assert matches == []

    def test_confidence_is_positive(self):
        data = b"\x00" * 100 + b"UPX!" + b"\x00" * 100
        matches = scan_signatures(data, [])
        for m in matches:
            assert 0 < m.confidence <= 100


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

class TestHeuristics:
    def _make_pe_and_sections(self):
        data = _build_minimal_pe()
        pe = PEParser(data)
        sections = [
            SectionResult(".text", 0x1000, 512, 512, 5.1, 0x60000020)
        ]
        return data, pe, sections

    def test_clean_no_heuristics(self):
        data, pe, sections = self._make_pe_and_sections()
        findings = run_heuristics(data, pe, sections, overall_entropy=5.1)
        non_import = [h for h in findings if "import" not in h.name.lower()]
        assert all(h.score <= 15 for h in non_import), \
            f"Unexpected high-score findings: {non_import}"

    def test_high_entropy_flagged(self):
        data, pe, sections = self._make_pe_and_sections()
        findings = run_heuristics(data, pe, sections, overall_entropy=7.8)
        scores = [h.score for h in findings]
        assert max(scores) >= 25, "High entropy should produce a high-score finding"

    def test_virtual_only_section_flagged(self):
        data, pe, _ = self._make_pe_and_sections()
        sections = [
            SectionResult("UPX0", 0x1000, 65536, 0, 0.1, 0x60000020)  # raw=0
        ]
        findings = run_heuristics(data, pe, sections, overall_entropy=3.0)
        names = [h.name for h in findings]
        assert any("virtual" in n.lower() for n in names)

    def test_high_entropy_exec_section_flagged(self):
        data, pe, _ = self._make_pe_and_sections()
        sections = [
            SectionResult("UPX1", 0x1000, 32768, 32768, 7.9, 0x60000020)
        ]
        findings = run_heuristics(data, pe, sections, overall_entropy=7.9)
        names = [h.name for h in findings]
        assert any("entropy" in n.lower() for n in names)



class TestVerdictComputation:
    from packdetect.engine import SignatureMatch, HeuristicFinding

    def test_signature_hit_gives_packed(self):
        from packdetect.engine import SignatureMatch
        sigs = [SignatureMatch("UPX", "3.x", 0x50, 95, "test")]
        verdict, _, conf, risk = compute_verdict(sigs, [], 7.8)
        assert verdict == "packed"
        assert conf >= 90
        assert risk == "HIGH"

    def test_no_sig_high_heuristic_gives_unknown(self):
        from packdetect.engine import HeuristicFinding
        h = [
            HeuristicFinding("High entropy", "desc", 35),
            HeuristicFinding("Virtual section", "desc", 30),
        ]
        verdict, _, conf, risk = compute_verdict([], h, 7.5)
        assert verdict == "unknown_packer"
        assert risk == "HIGH"

    def test_clean_binary_verdict(self):
        _, verdict, conf, risk = compute_verdict([], [], 4.5)
        assert verdict == "clean"
        assert risk == "LOW"

    def test_suspicious_medium_score(self):
        from packdetect.engine import HeuristicFinding
        h = [HeuristicFinding("Elevated entropy", "desc", 20)]
        _, verdict, conf, risk = compute_verdict([], h, 6.5)
        assert verdict in ("suspicious", "unknown_packer")



class TestAnalyseIntegration:
    def test_clean_binary(self, tmp_path):
        data = _build_minimal_pe(section_data=bytes(range(256)) * 2)
        f = tmp_path / "clean.exe"
        f.write_bytes(data)
        result = analyse(f)
        assert result.is_pe
        assert result.arch == "x86"
        assert result.file_size == len(data)
        assert result.md5
        assert result.sha256
        assert len(result.sections) == 1

    def test_upx_magic_in_file(self, tmp_path):
        # Embed UPX! magic in the file to trigger signature detection
        section_data = b"UPX!" + b"\x00" * 508
        data = _build_minimal_pe(
            section_name=b"UPX1\x00\x00\x00\x00",
            section_data=section_data,
        )
        f = tmp_path / "upx.exe"
        f.write_bytes(data)
        result = analyse(f)
        assert any(s.name == "UPX" for s in result.signatures)
        assert result.verdict == "packed"
        assert result.packer_name == "UPX"

    def test_result_fields_populated(self, tmp_path):
        data = _build_minimal_pe()
        f = tmp_path / "test.exe"
        f.write_bytes(data)
        result = analyse(f)
        assert result.path == f
        assert result.elapsed >= 0
        assert 0.0 <= result.overall_entropy <= 8.0
        assert result.verdict in ("clean", "packed", "suspicious", "unknown_packer")
        assert result.risk in ("LOW", "MEDIUM", "HIGH")
        assert 0 <= result.confidence <= 100
