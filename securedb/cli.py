from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .db import connect, seed, verify_chain
from .demo import run_demo
from .detect import detect


def render(con, log=None) -> str:
    alerts = detect(con)
    ok, bad, n = verify_chain(con)
    out = ["# SecureDB activity report", ""]
    if log:
        out += ["## What happened", *[f"- {l}" for l in log], ""]
    out += [f"## Audit chain: {'✅ intact' if ok else f'❌ BROKEN at entry #{bad}'} ({n} entries checked)", "", f"## Alerts ({len(alerts)})"]
    out += [f"- **[{a.severity.upper()}] {a.rule}** — {a.username} @ {a.at or 'n/a'}: {a.summary}" for a in alerts] or ["None."]
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="securedb", description="Database security demo: RBAC, row-level security, audit chain, misuse detection")
    p.add_argument("--db", default="securedb.sqlite")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create schema and seed sample data")
    d = sub.add_parser("demo", help="run a scripted week with misuse and print the report"); d.add_argument("--report", help="also write the report to this .md file"); d.add_argument("--clean", action="store_true", help="no misuse")
    sub.add_parser("verify", help="verify the audit hash chain")
    sub.add_parser("alerts", help="run detection rules")
    a = p.parse_args(argv)
    if a.cmd == "demo":
        Path(a.db).unlink(missing_ok=True)
        con, log = run_demo(a.db, misuse=not a.clean)
        text = render(con, log); print(text)
        if a.report: Path(a.report).write_text(text)
        return 0
    con = connect(a.db)
    if a.cmd == "init":
        seed(con); print(f"Initialized {a.db}")
    elif a.cmd == "verify":
        ok, bad, n = verify_chain(con); print(f"{'OK' if ok else f'BROKEN at entry #{bad}'} — {n} entries"); return 0 if ok else 1
    elif a.cmd == "alerts":
        for al in detect(con): print(f"[{al.severity}] {al.rule}: {al.username} {al.at} — {al.summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
