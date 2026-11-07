"""A scripted school week with normal use and injected misuse. Uses a fake clock so results are reproducible."""
from __future__ import annotations
from datetime import datetime, timedelta

from .access import PermissionDenied, SecureDB, unsafe_lookup
from .db import connect, seed


class Clock:
    def __init__(self, start: datetime):
        self.t = start

    def __call__(self) -> str:
        return self.t.isoformat(timespec="seconds")

    def set(self, day: int, hour: int, minute: int = 0):
        self.t = datetime(2026, 11, 2 + day, hour, minute)

    def tick(self, seconds: int = 20):
        self.t += timedelta(seconds=seconds)


def run_demo(path: str = ":memory:", misuse: bool = True):
    clock = Clock(datetime(2026, 11, 2, 8, 0))
    con = connect(path, clock=clock)
    seed(con)
    db = SecureDB(con, clock)
    log = []
    # ---- normal week ----
    for day in range(5):
        clock.set(day, 9)
        lee = db.session("ms_lee"); lee.read("grades"); lee.read("students")
        clock.tick(); lee.add_grade(1 + day % 3, 1, f"Homework {day + 1}", 80 + day)
        clock.set(day, 10); cho = db.session("mr_cho"); cho.read("grades"); cho.add_grade(4, 2, f"Practice {day + 1}", 70 + 2 * day)
        clock.set(day, 15); ava = db.session("ava"); ava.read("grades")
        clock.set(day, 13); db.session("counselor_ray").read("students", grade_level=10)
    clock.set(2, 14); db.session("ms_lee").update_grade(1, 94)  # small, legitimate correction
    log.append("Normal week: teachers graded their own classes, students viewed their own grades, counselor looked up students.")
    if not misuse:
        return con, log
    # ---- misuse ----
    clock.set(3, 12, 5)
    ben = db.session("ben")
    seen = ben.read("grades")
    log.append(f"ben (student) read grades: got only his own {len(seen)} rows (row-level security).")
    for gid in (2, 4, 5):
        clock.tick(30)
        try:
            ben.update_grade(gid, 100)
        except PermissionDenied:
            pass
    log.append("ben tried to change grades 3 times: all denied → privilege probing.")
    clock.tick(30)
    payload = "x' OR '1'='1"
    rows = ben.read("students", name=payload)
    log.append(f"ben tried SQL injection {payload!r} through the safe API: {len(rows)} rows returned, attempt logged.")
    log.append(f"The same payload against a deliberately unsafe query would return {len(unsafe_lookup(con, payload))} student records.")
    clock.set(3, 23, 40)
    db.session("mr_cho").update_grade(4, 98)
    log.append("mr_cho changed a Quiz 1 grade 71 → 98 at 23:40 → after-hours + large change.")
    clock.set(4, 11)
    ray = db.session("counselor_ray")
    for _ in range(12):
        clock.tick(15); ray.read("grades"); ray.read("students")
    log.append("counselor_ray ran 24 queries in 3 minutes → mass read.")
    clock.set(4, 16)
    con.execute("DELETE FROM session_context")  # someone using the sqlite3 shell directly
    con.execute("UPDATE grades SET score = 100 WHERE id = 2")
    con.execute("UPDATE users SET role = 'admin' WHERE username = 'ben'")
    log.append("Direct SQL (bypassing the app): changed grade #2 and promoted ben to admin. Triggers still audited it.")
    con.execute("DROP TRIGGER audit_no_update")
    con.execute("UPDATE audit_log SET detail = '{\"note\":\"nothing to see\"}' WHERE resource = 'users'")
    log.append("An attacker dropped the append-only trigger and rewrote an audit entry to hide the promotion.")
    return con, log
