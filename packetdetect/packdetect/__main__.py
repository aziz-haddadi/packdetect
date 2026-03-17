

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import analyse, attempt_unpack
from .output import (
    print_rich,
    print_plain,
    print_unpack_rich,
    print_unpack_plain,
    print_batch_summary_rich,
    print_batch_summary_plain,
    save_json,
    to_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BANNER = r"""
  ____            _     ____       _            _
 |  _ \ __ _  ___| | __| __ )  ___| |_ ___  ___| |_
 | |_) / _` |/ __| |/ /  _ \ / _ \ __/ _ \/ __| __|
 |  __/ (_| | (__|   <| |_) |  __/ ||  __/ (__| |_
 |_|   \__,_|\___|_|\_\____/ \___|\__\___|\___|\__|

  Packer Detection & Unpacking Tool  |  github.com/aziz-haddadi/packdetect
"""


def _exit(msg: str, code: int = 1) -> None:
    print(f"\n[ERROR] {msg}\n", file=sys.stderr)
    sys.exit(code)


def _resolve_file(path_str: str) -> Path:
    p = Path(path_str)
    if not p.exists():
        _exit(f"File not found: {p}")
    if not p.is_file():
        _exit(f"Not a file: {p}")
    return p



def cmd_scan(args: argparse.Namespace) -> None:
    target = _resolve_file(args.file)

    if not args.plain and not args.json:
        try:
            from rich.console import Console
            Console().print(f"[dim]{BANNER}[/]")
        except ImportError:
            print(BANNER)

    result = analyse(target)

    if args.json:
        print(to_json(result))
        return

    if args.plain:
        print_plain(result)
    else:
        print_rich(result)

    if args.save_json:
        out = save_json(result)
        msg = f"  JSON report saved → {out}"
        try:
            from rich.console import Console
            Console().print(f"[dim]{msg}[/]")
        except ImportError:
            print(msg)

    if result.verdict in ("packed", "unknown_packer"):
        sys.exit(2)
    if result.verdict == "suspicious":
        sys.exit(3)



def cmd_unpack(args: argparse.Namespace) -> None:
    target = _resolve_file(args.file)
    result = analyse(target)

    if not result.unpack_supported:
        _exit(
            f"No automatic unpacker available for this binary.\n"
            f"  Verdict   : {result.verdict}\n"
            f"  Packer    : {result.packer_name or 'unknown'}\n\n"
            f"  Tip: Use x64dbg to find the OEP, then dump with Scylla.",
            code=4,
        )

    unpack = attempt_unpack(result)

    if args.plain:
        print_unpack_plain(result, unpack)
    else:
        print_unpack_rich(result, unpack)

    if args.save_json:
        out = save_json(result)
        print(f"  JSON report saved → {out}")

    sys.exit(0 if unpack.success else 5)


def cmd_batch(args: argparse.Namespace) -> None:
    d = Path(args.directory)
    if not d.is_dir():
        _exit(f"Not a directory: {d}")

    extensions = {".exe", ".dll", ".sys", ".scr", ".ocx"}
    files = [
        f for f in d.rglob("*") if f.is_file()
        and (f.suffix.lower() in extensions or args.all)
    ]

    if not files:
        _exit(f"No PE files found in {d}  (use --all to scan every file)")

    results = []
    for i, f in enumerate(sorted(files), 1):
        if not args.plain and not args.json:
            try:
                from rich.console import Console
                Console().print(f"[dim]  [{i}/{len(files)}] Scanning {f.name}...[/]",
                                end="\r")
            except ImportError:
                print(f"  [{i}/{len(files)}] {f.name}", end="\r")

        results.append(analyse(f))

    if args.json:
        import json
        from .output import to_json as _to_json
        print(json.dumps([json.loads(_to_json(r)) for r in results], indent=2))
        return

    if args.plain:
        print_batch_summary_plain(results)
    else:
        print_batch_summary_rich(results)

    if args.save_json:
        import json
        from .output import to_json as _to_json
        out = d / "packdetect_batch.json"
        out.write_text(
            json.dumps([json.loads(_to_json(r)) for r in results], indent=2)
        )
        print(f"  Batch JSON saved → {out}")

    packed = sum(1 for r in results if r.verdict in ("packed", "unknown_packer"))
    sys.exit(2 if packed else 0)



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packdetect",
        description="Packer detection & unpacking tool for PE binaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  packdetect scan malware.exe
  packdetect scan malware.exe --json --save-json
  packdetect scan malware.exe --plain
  packdetect unpack upx_packed.exe
  packdetect batch ./samples/
  packdetect batch ./samples/ --all --json
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="command")

    # ---- scan ----
    p_scan = sub.add_parser("scan", help="Analyse a single PE binary")
    p_scan.add_argument("file", help="Path to the binary")
    p_scan.add_argument("--plain",     action="store_true",
                        help="Plain ASCII output (no Rich/colours)")
    p_scan.add_argument("--json",      action="store_true",
                        help="Output JSON to stdout (no decorations)")
    p_scan.add_argument("--save-json", action="store_true",
                        help="Save JSON report alongside the input file")

    # ---- unpack ----
    p_unp = sub.add_parser("unpack", help="Auto-unpack a supported packed binary")
    p_unp.add_argument("file", help="Path to the packed binary")
    p_unp.add_argument("--plain",     action="store_true")
    p_unp.add_argument("--save-json", action="store_true")

    # ---- batch ----
    p_bat = sub.add_parser("batch", help="Scan all PE files in a directory")
    p_bat.add_argument("directory", help="Directory to scan")
    p_bat.add_argument("--all",       action="store_true",
                        help="Include files without PE extensions")
    p_bat.add_argument("--plain",     action="store_true")
    p_bat.add_argument("--json",      action="store_true")
    p_bat.add_argument("--save-json", action="store_true")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "unpack":
        cmd_unpack(args)
    elif args.command == "batch":
        cmd_batch(args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
