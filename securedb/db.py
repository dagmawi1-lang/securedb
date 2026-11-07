"""Connection setup: schema, the audit_append() SQL function, seed data, and audit chain verification."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime
from importlib import resources

GENESIS = "0" * 64


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def entry_hash(prev: str, at: str, username: str, action: str, resource: str, row_id, detail: str) -> str:
    payload = json.dumps([prev, at, username, action, resource, row_id, detail], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def connect(path: str = "securedb.sqlite", clock=_now) -> sqlite3.Connection:
    con = sqlite3.connect(path, isolation_level=None)  # autocommit; we manage transactions explicitly
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")

    def audit_append(action, resource, row_id, detail):
        ctx = con.execute("SELECT username, at FROM session_context WHERE id = 1").fetchone()
        user, at = (ctx["username"], ctx["at"]) if ctx else ("<direct-sql>", clock())
        prev = con.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = prev["hash"] if prev else GENESIS
        h = entry_hash(prev, at, user, action, resource, row_id, detail or "")
        con.execute("INSERT INTO audit_log (at, username, action, resource, row_id, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                    (at, user, action, resource, row_id, detail or "", prev, h))
        return 1

    con.create_function("audit_append", 4, audit_append)
    con.executescript(resources.files("securedb").joinpath("schema.sql").read_text())
    return con


def log_audit(con, username: str, action: str, resource: str, row_id=None, detail: str = "", at: str | None = None) -> None:
    """Audit entries for reads and other actions that don't fire a trigger."""
    with_ctx(con, username, at)
    con.execute("SELECT audit_append(?,?,?,?)", (action, resource, row_id, detail))


def with_ctx(con, username: str, at: str | None = None) -> None:
    con.execute("INSERT INTO session_context (id, username, at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, at = excluded.at", (username, at or _now()))


def verify_chain(con) -> tuple[bool, int | None, int]:
    """Recomputes every hash. Returns (ok, first_bad_id, rows_checked)."""
    prev, n = GENESIS, 0
    for r in con.execute("SELECT * FROM audit_log ORDER BY id"):
        n += 1
        if r["prev_hash"] != prev or entry_hash(prev, r["at"], r["username"], r["action"], r["resource"], r["row_id"], r["detail"]) != r["hash"]:
            return False, r["id"], n
        prev = r["hash"]
    return True, None, n


def seed(con) -> None:
    if con.execute("SELECT COUNT(*) FROM roles").fetchone()[0]:
        return
    con.execute("BEGIN")
    con.executemany("INSERT INTO roles VALUES (?,?)", [("admin", "Database administrator"), ("teacher", "Teaches classes, manages their grades"), ("counselor", "Reads student records"), ("student", "Reads their own grades")])
    perms = [("admin", r, a, "all") for r in ("students", "grades", "users", "classes") for a in ("read", "insert", "update", "delete")]
    perms += [("teacher", "grades", "read", "class"), ("teacher", "grades", "insert", "class"), ("teacher", "grades", "update", "class"), ("teacher", "students", "read", "class"), ("teacher", "classes", "read", "all")]
    perms += [("counselor", "students", "read", "all"), ("counselor", "grades", "read", "all"), ("counselor", "students", "update", "all")]
    perms += [("student", "grades", "read", "own"), ("student", "students", "read", "own"), ("student", "classes", "read", "all")]
    con.executemany("INSERT INTO permissions VALUES (?,?,?,?)", perms)
    students = [(1, "Ava Brooks", 10, "ava@example.edu"), (2, "Ben Ortiz", 11, "ben@example.edu"), (3, "Chloe Diaz", 10, "chloe@example.edu"), (4, "Dev Patel", 12, "dev@example.edu"), (5, "Ella Kim", 11, "ella@example.edu")]
    con.executemany("INSERT INTO students VALUES (?,?,?,?)", students)
    con.executemany("INSERT INTO users (id, username, role, student_id) VALUES (?,?,?,?)",
                    [(1, "root_admin", "admin", None), (2, "ms_lee", "teacher", None), (3, "mr_cho", "teacher", None), (4, "counselor_ray", "counselor", None), (5, "ava", "student", 1), (6, "ben", "student", 2)])
    con.executemany("INSERT INTO classes VALUES (?,?,?)", [(1, "Biology", 2), (2, "Algebra II", 3)])
    con.executemany("INSERT INTO enrollments VALUES (?,?)", [(1, 1), (2, 1), (3, 1), (2, 2), (4, 2), (5, 2)])
    con.execute("COMMIT")
    with_ctx(con, "seed")
    con.execute("BEGIN")
    con.executemany("INSERT INTO grades (student_id, class_id, assignment, score) VALUES (?,?,?,?)",
                    [(1, 1, "Lab 1", 92), (2, 1, "Lab 1", 78), (3, 1, "Lab 1", 85), (2, 2, "Quiz 1", 71), (4, 2, "Quiz 1", 88), (5, 2, "Quiz 1", 95)])
    con.execute("COMMIT")
