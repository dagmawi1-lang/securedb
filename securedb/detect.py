"""Detection of suspicious database activity from audit_log and security_events."""
from __future__ import annotations
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from .db import verify_chain


@dataclass
class Alert:
    rule: str
    severity: str
    username: str
    at: str
    summary: str


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s)


def detect(con, *, denial_threshold: int = 3, denial_window=timedelta(minutes=10), mass_read_rows: int = 50,
           mass_read_window=timedelta(minutes=10), business_hours=(7, 19), grade_change_threshold: float = 15.0) -> list[Alert]:
    alerts: list[Alert] = []
    # 1) Tamper evidence
    ok, bad_id, _ = verify_chain(con)
    if not ok:
        alerts.append(Alert("audit_tampering", "critical", "?", "", f"Audit hash chain broken at entry #{bad_id}: a past record was altered or removed."))
    # 2) Repeated permission denials = probing for access
    denials = defaultdict(list)
    for r in con.execute("SELECT * FROM security_events WHERE kind = 'denied' ORDER BY at"):
        denials[r["username"]].append(r)
    for user, rows in denials.items():
        i = 0
        for j in range(len(rows)):
            while _t(rows[j]["at"]) - _t(rows[i]["at"]) > denial_window:
                i += 1
            if j - i + 1 == denial_threshold:
                alerts.append(Alert("privilege_probing", "high", user, rows[j]["at"], f"{denial_threshold}+ denied requests within {int(denial_window.total_seconds() // 60)} min (e.g. {rows[j]['detail']})."))
    # 3) Injection attempts
    for r in con.execute("SELECT * FROM security_events WHERE kind = 'suspicious_input' ORDER BY at"):
        alerts.append(Alert("sql_injection_attempt", "high", r["username"], r["at"], f"Injection-like input on {r['resource']}: {r['detail']}"))
    # 4) Mass reads = possible data exfiltration
    reads = defaultdict(list)
    for r in con.execute("SELECT * FROM audit_log WHERE action = 'read' ORDER BY id"):
        rows = int(r["detail"].split("rows=")[1].split()[0]) if "rows=" in r["detail"] else 0
        reads[r["username"]].append((_t(r["at"]), rows))
    for user, evs in reads.items():
        i, total, flagged = 0, 0, False
        for j, (t, n) in enumerate(evs):
            total += n
            while t - evs[i][0] > mass_read_window:
                total -= evs[i][1]; i += 1
            if total >= mass_read_rows and not flagged:
                alerts.append(Alert("mass_read", "high", user, t.isoformat(timespec="seconds"), f"Read {total} records in {int(mass_read_window.total_seconds() // 60)} min ({j - i + 1} queries)."))
                flagged = True
            elif total < mass_read_rows:
                flagged = False
    # 5) After-hours data changes
    lo, hi = business_hours
    for r in con.execute("SELECT * FROM audit_log WHERE action IN ('insert','update','delete') AND username NOT IN ('seed') ORDER BY id"):
        h = _t(r["at"]).hour
        if not (lo <= h < hi):
            alerts.append(Alert("after_hours_change", "medium", r["username"], r["at"], f"{r['action']} on {r['resource']} #{r['row_id']} at {h:02d}:00."))
    # 6) Big grade changes and changes made outside the access layer
    for r in con.execute("SELECT * FROM audit_log WHERE resource = 'grades' AND action IN ('update','delete') ORDER BY id"):
        d = json.loads(r["detail"] or "{}")
        if r["username"] == "<direct-sql>":
            alerts.append(Alert("direct_sql_change", "critical", "<direct-sql>", r["at"], f"Grade #{r['row_id']} was changed with direct SQL, bypassing access control."))
        elif r["action"] == "update" and abs(d.get("new_score", 0) - d.get("old_score", 0)) >= grade_change_threshold:
            alerts.append(Alert("large_grade_change", "medium", r["username"], r["at"], f"Grade #{r['row_id']} ({d.get('assignment')}) changed {d.get('old_score')} → {d.get('new_score')}."))
    # 7) Privilege escalation
    for r in con.execute("SELECT * FROM audit_log WHERE resource = 'users' ORDER BY id"):
        d = json.loads(r["detail"] or "{}")
        if d.get("new_role") == "admin" and d.get("old_role") != "admin":
            alerts.append(Alert("privilege_escalation", "critical" if r["username"] == "<direct-sql>" else "high", r["username"], r["at"], f"{d.get('username')} promoted from {d.get('old_role')} to admin."))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts, key=lambda a: (order[a.severity], a.at))
