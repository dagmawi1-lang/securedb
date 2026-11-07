"""The only supported way to touch data: every call is permission-checked, row-scoped, parameterized, and audited."""
from __future__ import annotations
import re
from datetime import datetime

from .db import log_audit, with_ctx

COLUMNS = {  # whitelists: user input never becomes an identifier in SQL
    "students": {"id", "name", "grade_level", "email"},
    "grades": {"id", "student_id", "class_id", "assignment", "score"},
    "classes": {"id", "title", "teacher_id"},
    "users": {"id", "username", "role", "active"},
}
SUSPICIOUS = re.compile(r"('|--|;|/\*|\*/|\bunion\b|\bselect\b|\bdrop\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|\bxp_)", re.I)


class PermissionDenied(Exception):
    pass


class SecureDB:
    def __init__(self, con, clock=None):
        self.con = con
        self.clock = clock or (lambda: datetime.now().isoformat(timespec="seconds"))

    def session(self, username: str) -> "Session":
        u = self.con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        at = self.clock()
        if not u or not u["active"]:
            self.con.execute("INSERT INTO security_events (at, username, kind, detail) VALUES (?,?,?,?)", (at, username, "login_failed", "unknown or inactive account"))
            raise PermissionDenied(f"{username}: unknown or inactive account")
        self.con.execute("INSERT INTO security_events (at, username, kind) VALUES (?,?,?)", (at, username, "login"))
        return Session(self, dict(u))


class Session:
    def __init__(self, db: SecureDB, user: dict):
        self.db, self.con, self.user = db, db.con, user

    # ---- policy ----
    def _scope(self, resource: str, action: str) -> str:
        r = self.con.execute("SELECT scope FROM permissions WHERE role = ? AND resource = ? AND action = ?", (self.user["role"], resource, action)).fetchone()
        if not r:
            self._event("denied", resource, f"{action} not permitted for role {self.user['role']}")
            raise PermissionDenied(f"{self.user['username']} ({self.user['role']}) may not {action} {resource}")
        return r["scope"]

    def _event(self, kind: str, resource: str | None, detail: str) -> None:
        self.con.execute("INSERT INTO security_events (at, username, kind, resource, detail) VALUES (?,?,?,?,?)", (self.db.clock(), self.user["username"], kind, resource, detail[:500]))

    def _check_input(self, resource: str, value) -> None:
        if isinstance(value, str) and SUSPICIOUS.search(value):
            # Parameterized queries make this harmless, but the attempt itself is worth recording.
            self._event("suspicious_input", resource, f"possible SQL injection payload: {value[:120]!r}")

    def _teacher_classes(self) -> list[int]:
        return [r[0] for r in self.con.execute("SELECT id FROM classes WHERE teacher_id = ?", (self.user["id"],))]

    def _row_filter(self, resource: str, scope: str) -> tuple[str, list]:
        """Row-level security as an extra WHERE clause."""
        if scope == "all":
            return "", []
        if scope == "own":
            sid = self.user["student_id"]
            col = "id" if resource == "students" else "student_id"
            return f" AND {col} = ?", [sid]
        if scope == "class":
            cls = self._teacher_classes() or [-1]
            marks = ",".join("?" * len(cls))
            if resource == "grades":
                return f" AND class_id IN ({marks})", cls
            if resource == "students":
                return f" AND id IN (SELECT student_id FROM enrollments WHERE class_id IN ({marks}))", cls
        raise PermissionDenied("unsupported scope")

    # ---- operations ----
    def read(self, resource: str, columns: list[str] | None = None, **filters) -> list[dict]:
        if resource not in COLUMNS:
            self._event("denied", resource, "unknown resource"); raise PermissionDenied(f"unknown resource {resource!r}")
        cols = columns or sorted(COLUMNS[resource])
        bad = [c for c in [*cols, *filters] if c not in COLUMNS[resource]]
        if bad:
            self._event("denied", resource, f"invalid column(s): {bad}"); raise PermissionDenied(f"invalid column(s) {bad}")
        scope = self._scope(resource, "read")
        for v in filters.values():
            self._check_input(resource, v)
        where, args = " WHERE 1=1", []
        for k, v in filters.items():
            where += f" AND {k} = ?"; args.append(v)
        rf, rargs = self._row_filter(resource, scope)
        rows = [dict(r) for r in self.con.execute(f"SELECT {', '.join(cols)} FROM {resource}{where}{rf} ORDER BY id", args + rargs)]
        log_audit(self.con, self.user["username"], "read", resource, None, f"rows={len(rows)} filters={sorted(filters)}", self.db.clock())
        return rows

    def _within_scope(self, resource: str, scope: str, row_id: int) -> bool:
        rf, rargs = self._row_filter(resource, scope)
        return self.con.execute(f"SELECT 1 FROM {resource} WHERE id = ?{rf}", [row_id, *rargs]).fetchone() is not None

    def add_grade(self, student_id: int, class_id: int, assignment: str, score: float) -> int:
        scope = self._scope("grades", "insert")
        self._check_input("grades", assignment)
        if scope == "class" and class_id not in self._teacher_classes():
            self._event("denied", "grades", f"insert into class {class_id} they don't teach"); raise PermissionDenied("not your class")
        with_ctx(self.con, self.user["username"], self.db.clock())
        cur = self.con.execute("INSERT INTO grades (student_id, class_id, assignment, score) VALUES (?,?,?,?)", (student_id, class_id, assignment[:100], float(score)))
        return cur.lastrowid

    def update_grade(self, grade_id: int, score: float) -> None:
        scope = self._scope("grades", "update")
        if not self._within_scope("grades", scope, grade_id):
            self._event("denied", "grades", f"update grade {grade_id} outside scope"); raise PermissionDenied("grade not found or not yours")
        with_ctx(self.con, self.user["username"], self.db.clock())
        self.con.execute("UPDATE grades SET score = ? WHERE id = ?", (float(score), grade_id))

    def update_student_email(self, student_id: int, email: str) -> None:
        scope = self._scope("students", "update")
        self._check_input("students", email)
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}", email or ""):
            raise ValueError("invalid email")
        if not self._within_scope("students", scope, student_id):
            raise PermissionDenied("student not found or not in scope")
        with_ctx(self.con, self.user["username"], self.db.clock())
        self.con.execute("UPDATE students SET email = ? WHERE id = ?", (email, student_id))

    def set_role(self, username: str, role: str) -> None:
        self._scope("users", "update")
        if username == self.user["username"]:
            self._event("denied", "users", "attempted to change own role"); raise PermissionDenied("you cannot change your own role")
        if not self.con.execute("SELECT 1 FROM roles WHERE name = ?", (role,)).fetchone():
            raise ValueError("unknown role")
        with_ctx(self.con, self.user["username"], self.db.clock())
        if self.con.execute("UPDATE users SET role = ? WHERE username = ?", (role, username)).rowcount == 0:
            raise ValueError("unknown user")


def unsafe_lookup(con, name: str) -> list[dict]:
    """DELIBERATELY VULNERABLE: builds SQL with string formatting. Used only in the demo and tests to show why
    parameterized queries matter. Never use this pattern."""
    return [dict(r) for r in con.execute(f"SELECT id, name, email FROM students WHERE name = '{name}'")]
