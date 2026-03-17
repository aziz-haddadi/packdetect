
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .engine import AnalysisResult, UnpackResult


RISK_COLOR = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "bold green"}
VERDICT_COLOR = {
    "packed":         "bold red",
    "unknown_packer": "bold magenta",
    "suspicious":     "bold yellow",
    "clean":          "bold green",
}
VERDICT_ICON = {
    "packed":         "⚠  PACKED",
    "unknown_packer": "⚠  UNKNOWN PACKER",
    "suspicious":     "⚡  SUSPICIOUS",
    "clean":          "✓  CLEAN",
}
ENTROPY_COLOR = {
    "HIGH":       "bold red",
    "SUSPICIOUS": "yellow",
    "NORMAL":     "green",
}


def _entropy_bar(entropy: float, width: int = 20) -> str:
    filled = round((entropy / 8.0) * width)
    return "[" + "█" * filled + "░" * (width - filled) + f"] {entropy:.4f}"


def _try_import_rich():
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        from rich.text import Text
        from rich.rule import Rule
        return Console, Table, Panel, box, Text, Rule
    except ImportError:
        return None


def print_rich(result: AnalysisResult) -> None:
    mods = _try_import_rich()
    if mods is None:
        print_plain(result)
        return

    Console, Table, Panel, box, Text, Rule = mods
    console = Console()

    # ---- Header ----
    console.print()
    console.print(Rule("[bold cyan]PackDetect Analysis Report[/]"))

    # ---- File info ----
    t = Table(box=box.SIMPLE_HEAD, show_header=False, padding=(0, 1))
    t.add_column(style="dim", width=18)
    t.add_column()
    t.add_row("File",    str(result.path))
    t.add_row("Size",    _fmt_size(result.file_size))
    t.add_row("MD5",     result.md5)
    t.add_row("SHA-256", result.sha256)
    t.add_row("Arch",    result.arch.upper())
    t.add_row("PE valid", "Yes" if result.is_pe else "[red]No (not a PE)[/]")
    if result.is_pe:
        t.add_row("Entry point", f"RVA 0x{result.entry_point:08X}  →  {result.entry_point_section}")
    t.add_row("Scan time", f"{result.elapsed:.3f}s")
    console.print(Panel(t, title="[bold]File Info[/]", border_style="dim", expand=False))

    # ---- Verdict ----
    vc = VERDICT_COLOR[result.verdict]
    icon = VERDICT_ICON[result.verdict]
    conf_bar = "█" * (result.confidence // 10) + "░" * (10 - result.confidence // 10)
    body = Text()
    body.append(f"  {icon}\n", style=vc)
    body.append(f"\n  Confidence : ", style="dim")
    body.append(f"{conf_bar}  {result.confidence}%\n", style=vc)
    body.append(f"  Risk level : ", style="dim")
    body.append(f"{result.risk}\n", style=RISK_COLOR[result.risk])
    if result.packer_name:
        body.append(f"  Packer     : ", style="dim")
        body.append(f"{result.packer_name}\n", style="bold cyan")
    console.print(Panel(body, title="[bold]Verdict[/]", border_style=vc.replace("bold ", "")))

    # ---- Entropy ----
    t2 = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1))
    t2.add_column("Section",   style="cyan",    width=14)
    t2.add_column("Entropy",   justify="right", width=10)
    t2.add_column("Bar",       width=28)
    t2.add_column("Raw sz",    justify="right", width=10)
    t2.add_column("Virt sz",   justify="right", width=10)
    t2.add_column("Flag",      width=12)

    for s in result.sections:
        col = ENTROPY_COLOR[s.entropy_label]
        bar_len = round((s.entropy / 8.0) * 24)
        bar = "█" * bar_len + "░" * (24 - bar_len)
        t2.add_row(
            s.name or "(unnamed)",
            f"[{col}]{s.entropy:.4f}[/]",
            f"[{col}]{bar}[/]",
            _fmt_size(s.raw_size),
            _fmt_size(s.virtual_size),
            f"[{col}]{s.entropy_label}[/]",
        )

    # Overall row
    oc = ENTROPY_COLOR["HIGH" if result.overall_entropy >= 7.0
                        else "SUSPICIOUS" if result.overall_entropy >= 6.0
                        else "NORMAL"]
    ob = "█" * round((result.overall_entropy / 8.0) * 24) + \
         "░" * (24 - round((result.overall_entropy / 8.0) * 24))
    t2.add_row(
        "[bold]OVERALL[/]",
        f"[{oc}][bold]{result.overall_entropy:.4f}[/][/]",
        f"[{oc}]{ob}[/]",
        _fmt_size(result.file_size), "", f"[{oc}]—[/]"
    )
    console.print(Panel(t2, title="[bold]Entropy Analysis[/]", border_style="blue"))

    # ---- Signatures ----
    t3 = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1))
    t3.add_column("Packer",     style="cyan", width=20)
    t3.add_column("Match",      width=8)
    t3.add_column("Offset",     width=14)
    t3.add_column("Confidence", width=12)
    t3.add_column("Description")

    matched_names = {s.name for s in result.signatures}
    for sig in result.signatures:
        t3.add_row(
            sig.name,
            "[bold red]HIT[/]",
            f"0x{sig.offset:08X}",
            f"[bold red]{sig.confidence}%[/]",
            sig.description,
        )

    # Show "no match" rows for the core packers that weren't found
    core = ["UPX", "MPRESS", "ASPack", "PECompact", "Themida/WinLicense", "VMProtect"]
    for name in core:
        if name not in matched_names:
            t3.add_row(name, "[dim]—[/]", "[dim]—[/]", "[dim]—[/]", "[dim]not detected[/]")

    console.print(Panel(t3, title="[bold]Signature Scan[/]", border_style="magenta"))

    # ---- Heuristics ----
    if result.heuristics:
        t4 = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1))
        t4.add_column("Finding",     style="yellow", width=32)
        t4.add_column("Score",       width=8)
        t4.add_column("Detail")
        for h in result.heuristics:
            t4.add_row(h.name, f"[yellow]+{h.score}[/]", h.description)
        console.print(Panel(t4, title="[bold]Heuristic Findings[/]", border_style="yellow"))
    else:
        console.print(Panel("[green]  No suspicious heuristics detected.[/]",
                            title="[bold]Heuristic Findings[/]", border_style="green"))

    # ---- Unpack hint ----
    if result.unpack_supported and result.unpack_command:
        console.print(Panel(
            f"[bold green]  Supported packer detected — auto-unpack available.\n\n"
            f"  [dim]Command:[/]  [cyan]{result.unpack_command}[/]\n\n"
            f"  Run:  [bold]packdetect unpack {result.path}[/]",
            title="[bold]Unpack[/]", border_style="green",
        ))
    elif result.verdict in ("packed", "unknown_packer"):
        console.print(Panel(
            "  [yellow]Packed binary detected but no automatic unpacker available.\n"
            "  Use x64dbg / OllyDbg to find the OEP, then dump with Scylla.[/]",
            title="[bold]Unpack[/]", border_style="yellow",
        ))

    console.print()


def print_unpack_rich(result: AnalysisResult, unpack: UnpackResult) -> None:
    mods = _try_import_rich()
    if mods is None:
        print_unpack_plain(result, unpack)
        return

    Console, Table, Panel, box, Text, Rule = mods
    console = Console()
    console.print()
    console.print(Rule("[bold cyan]PackDetect — Unpack[/]"))
    console.print(f"  Target  : [cyan]{result.path}[/]")
    console.print(f"  Packer  : [cyan]{result.packer_name}[/]")
    console.print(f"  Command : [dim]{unpack.command}[/]")
    console.print()

    if unpack.success:
        console.print(f"[bold green]  ✓ Unpacked successfully → {unpack.output_path}[/]")
        # Optionally re-analyse unpacked file
        console.print(f"  Run [cyan]packdetect scan {unpack.output_path}[/] to verify the result.")
    else:
        console.print(f"[bold red]  ✗ Unpack failed — {unpack.message}[/]")

    if unpack.stdout:
        console.print(f"\n[dim]  stdout:[/] {unpack.stdout}")
    if unpack.stderr:
        console.print(f"[dim]  stderr:[/] {unpack.stderr}")
    console.print()


# ---------------------------------------------------------------------------
# Plain renderer
# ---------------------------------------------------------------------------

def print_plain(result: AnalysisResult) -> None:
    sep = "=" * 60

    print(f"\n{sep}")
    print("PackDetect Analysis Report")
    print(sep)
    print(f"File       : {result.path}")
    print(f"Size       : {_fmt_size(result.file_size)}")
    print(f"MD5        : {result.md5}")
    print(f"SHA-256    : {result.sha256}")
    print(f"Arch       : {result.arch.upper()}")
    print(f"PE valid   : {'Yes' if result.is_pe else 'No'}")
    if result.is_pe:
        print(f"Entry point: RVA 0x{result.entry_point:08X} -> {result.entry_point_section}")
    print(f"Scan time  : {result.elapsed:.3f}s")

    print(f"\n{sep}")
    print("VERDICT")
    print(sep)
    icon = VERDICT_ICON[result.verdict]
    print(f"  {icon}")
    bar = "█" * (result.confidence // 10) + "░" * (10 - result.confidence // 10)
    print(f"  Confidence : {bar}  {result.confidence}%")
    print(f"  Risk       : {result.risk}")
    if result.packer_name:
        print(f"  Packer     : {result.packer_name}")

    print(f"\n{sep}")
    print("ENTROPY ANALYSIS")
    print(sep)
    print(f"  {'Section':<14} {'Entropy':>10}  {'Bar':<26} {'Flag'}")
    print(f"  {'-'*14} {'-'*10}  {'-'*26} {'-'*12}")
    for s in result.sections:
        bar = _entropy_bar(s.entropy, 24)
        print(f"  {s.name or '(unnamed)':<14} {s.entropy:>10.4f}  {bar:<26} {s.entropy_label}")
    bar = _entropy_bar(result.overall_entropy, 24)
    print(f"  {'OVERALL':<14} {result.overall_entropy:>10.4f}  {bar}")

    print(f"\n{sep}")
    print("SIGNATURE SCAN")
    print(sep)
    if result.signatures:
        for sig in result.signatures:
            print(f"  [HIT]  {sig.name} ({sig.confidence}% confidence)")
            print(f"         Offset 0x{sig.offset:08X} — {sig.description}")
    else:
        print("  No known packer signatures matched.")

    print(f"\n{sep}")
    print("HEURISTIC FINDINGS")
    print(sep)
    if result.heuristics:
        for h in result.heuristics:
            print(f"  [+{h.score:02d}]  {h.name}")
            print(f"         {h.description}")
    else:
        print("  No suspicious heuristics.")

    if result.unpack_supported and result.unpack_command:
        print(f"\n{sep}")
        print("UNPACK")
        print(sep)
        print(f"  Supported. Run:  packdetect unpack {result.path}")
        print(f"  Command        : {result.unpack_command}")

    print()


def print_unpack_plain(result: AnalysisResult, unpack: UnpackResult) -> None:
    sep = "=" * 60
    print(f"\n{sep}")
    print("PackDetect — Unpack")
    print(sep)
    print(f"Target  : {result.path}")
    print(f"Packer  : {result.packer_name}")
    print(f"Command : {unpack.command}")
    if unpack.success:
        print(f"\n[OK] Unpacked -> {unpack.output_path}")
    else:
        print(f"\n[FAIL] {unpack.message}")
    if unpack.stdout:
        print(f"stdout: {unpack.stdout}")
    if unpack.stderr:
        print(f"stderr: {unpack.stderr}")
    print()


def to_json(result: AnalysisResult, indent: int = 2) -> str:
    """Serialise AnalysisResult to a JSON string."""
    d = {
        "file": {
            "path":    str(result.path),
            "size":    result.file_size,
            "md5":     result.md5,
            "sha256":  result.sha256,
            "arch":    result.arch,
            "is_pe":   result.is_pe,
            "entry_point": f"0x{result.entry_point:08X}",
            "entry_point_section": result.entry_point_section,
            "elapsed_seconds": result.elapsed,
        },
        "entropy": {
            "overall": result.overall_entropy,
            "sections": [
                {
                    "name":           s.name,
                    "entropy":        s.entropy,
                    "raw_size":       s.raw_size,
                    "virtual_size":   s.virtual_size,
                    "virtual_address": s.virtual_address,
                    "is_executable":  s.is_executable,
                    "flag":           s.entropy_label,
                }
                for s in result.sections
            ],
        },
        "signatures": [
            {
                "name":        sig.name,
                "version":     sig.version,
                "offset":      f"0x{sig.offset:08X}",
                "confidence":  sig.confidence,
                "description": sig.description,
            }
            for sig in result.signatures
        ],
        "heuristics": [
            {
                "name":        h.name,
                "description": h.description,
                "score":       h.score,
            }
            for h in result.heuristics
        ],
        "verdict": {
            "verdict":       result.verdict,
            "packer":        result.packer_name,
            "confidence":    result.confidence,
            "risk":          result.risk,
            "unpack_supported": result.unpack_supported,
            "unpack_command":   result.unpack_command,
        },
    }
    return json.dumps(d, indent=indent)


def save_json(result: AnalysisResult, output: Optional[Path] = None) -> Path:
    if output is None:
        output = result.path.with_suffix(".packdetect.json")
    output.write_text(to_json(result), encoding="utf-8")
    return output




def print_batch_summary_rich(results: list[AnalysisResult]) -> None:
    mods = _try_import_rich()
    if mods is None:
        print_batch_summary_plain(results)
        return

    Console, Table, Panel, box, Text, Rule = mods
    console = Console()
    console.print()
    console.print(Rule("[bold cyan]Batch Scan Summary[/]"))

    t = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 1))
    t.add_column("File",       style="cyan")
    t.add_column("Verdict",    width=16)
    t.add_column("Packer",     width=16)
    t.add_column("Entropy",    width=10, justify="right")
    t.add_column("Confidence", width=12, justify="right")
    t.add_column("Risk",       width=8)

    for r in results:
        vc = VERDICT_COLOR[r.verdict]
        t.add_row(
            r.path.name,
            f"[{vc}]{r.verdict.upper()}[/]",
            r.packer_name or "—",
            f"{r.overall_entropy:.3f}",
            f"{r.confidence}%",
            f"[{RISK_COLOR[r.risk]}]{r.risk}[/]",
        )

    total = len(results)
    packed = sum(1 for r in results if r.verdict in ("packed", "unknown_packer"))
    suspicious = sum(1 for r in results if r.verdict == "suspicious")
    clean = sum(1 for r in results if r.verdict == "clean")

    console.print(t)
    console.print(f"\n  Scanned: {total}  |  "
                  f"[red]Packed: {packed}[/]  |  "
                  f"[yellow]Suspicious: {suspicious}[/]  |  "
                  f"[green]Clean: {clean}[/]\n")


def print_batch_summary_plain(results: list[AnalysisResult]) -> None:
    sep = "=" * 70
    print(f"\n{sep}")
    print("Batch Scan Summary")
    print(sep)
    print(f"  {'File':<30} {'Verdict':<16} {'Packer':<16} {'Entropy':>8} {'Conf':>6}")
    print(f"  {'-'*30} {'-'*16} {'-'*16} {'-'*8} {'-'*6}")
    for r in results:
        print(f"  {r.path.name:<30} {r.verdict.upper():<16} "
              f"{r.packer_name or '—':<16} {r.overall_entropy:>8.3f} {r.confidence:>5}%")
    total = len(results)
    packed = sum(1 for r in results if r.verdict in ("packed", "unknown_packer"))
    print(f"\n  Total: {total}  Packed/Unknown: {packed}  Clean: {total - packed}\n")


def _fmt_size(b: int) -> str:
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"
