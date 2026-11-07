import sqlite3

import pytest

from securedb.access import PermissionDenied, SecureDB, unsafe_lookup
from securedb.db import connect, seed, verify_chain
from securedb.demo import Clock, run_demo
from securedb.detect import detect
from datetime import datetime


@pytest.fixture
def env():
    clock = Clock(datetime(2026, 11, 2, 9, 0))
    con = connect(":memory:", clock=clock); seed(con)
    return con, SecureDB(con, clock), clock


def test_rbac_and_row_level_security(env):
    con, db, _ = env
    assert len(db.session("ava").read("grades")) == 1, "student sees only own grades"
    assert {r["class_id"] for r in db.session("ms_lee").read("grades")} == {1}, "teacher sees only their class"
    assert {r["id"] for r in db.session("ms_lee").read("students")} == {1, 2, 3}, "teacher sees only enrolled students"
    assert len(db.session("counselor_ray").read("grades")) == 6
    with pytest.raises(PermissionDenied):
        db.session("ava").update_grade(1, 100)
    with pytest.raises(PermissionDenied):
        db.session("ms_lee").update_grade(4, 100)  # grade 4 is in mr_cho's class
    with pytest.raises(PermissionDenied):
        db.session("ms_lee").add_grade(2, 2, "x", 50)
    with pytest.raises(PermissionDenied):
        db.session("ms_lee").read("users")
    with pytest.raises(PermissionDenied):
        db.session("nobody")


def test_identifiers_are_whitelisted_and_values_parameterized(env):
    con, db, _ = env
    s = db.session("counselor_ray")
    with pytest.raises(PermissionDenied):
        s.read("students", columns=["name", "password"])
    with pytest.raises(PermissionDenied):
        s.read("students; DROP TABLE students")
    with pytest.raises(PermissionDenied):
        s.read("students", **{"1=1 OR id": 1})
    assert s.read("students", name="x' OR '1'='1") == []
    assert con.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 5
    assert len(unsafe_lookup(con, "x' OR '1'='1")) == 5, "the vulnerable pattern leaks every row"
    assert con.execute("SELECT kind FROM security_events WHERE kind='suspicious_input'").fetchone()


def test_audit_log_is_append_only_and_hash_chained(env):
    con, db, _ = env
    db.session("ms_lee").update_grade(1, 95)
    ok, _, n = verify_chain(con)
    assert ok and n >= 7
    last = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    assert last["username"] == "ms_lee" and '"new_score":95' in last["detail"].replace(" ", "")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("UPDATE audit_log SET username='x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        con.execute("DELETE FROM audit_log")
    con.execute("DROP TRIGGER audit_no_delete")
    con.execute("DELETE FROM audit_log WHERE id = 3")
    ok, bad, _ = verify_chain(con)
    assert not ok and bad == 4


def test_direct_sql_is_still_audited(env):
    con, *_ = env
    con.execute("DELETE FROM session_context")
    con.execute("UPDATE grades SET score = 1 WHERE id = 1")
    con.execute("UPDATE users SET role='admin' WHERE username='ben'")
    rules = {a.rule for a in detect(con)}
    assert {"direct_sql_change", "privilege_escalation"} <= rules


def test_self_promotion_blocked(env):
    _, db, _ = env
    with pytest.raises(PermissionDenied):
        db.session("root_admin").set_role("root_admin", "student")
    db.session("root_admin").set_role("counselor_ray", "admin")
    assert any(a.rule == "privilege_escalation" and a.severity == "high" for a in detect(db.con))


def test_input_validation(env):
    _, db, _ = env
    with pytest.raises(ValueError):
        db.session("counselor_ray").update_student_email(1, "not-an-email")
    with pytest.raises(sqlite3.IntegrityError):
        db.session("ms_lee").add_grade(1, 1, "Bad", 150)  # CHECK constraint
    with pytest.raises(sqlite3.IntegrityError):
        db.session("ms_lee").add_grade(4, 1, "Not enrolled", 50)  # composite foreign key to enrollments


def test_clean_week_has_no_alerts():
    con, _ = run_demo(misuse=False)
    assert detect(con) == []
    assert verify_chain(con)[0]


def test_demo_detects_every_misuse():
    con, _ = run_demo(misuse=True)
    rules = {a.rule for a in detect(con)}
    assert {"audit_tampering", "direct_sql_change", "privilege_probing", "sql_injection_attempt", "mass_read", "after_hours_change", "large_grade_change"} <= rules


def test_cli(tmp_path, capsys):
    from securedb.cli import main
    assert main(["--db", str(tmp_path / "d.sqlite"), "demo", "--report", str(tmp_path / "r.md")]) == 0
    assert "BROKEN" in (tmp_path / "r.md").read_text()
    assert main(["--db", str(tmp_path / "d.sqlite"), "verify"]) == 1
    assert main(["--db", str(tmp_path / "e.sqlite"), "init"]) == 0 and main(["--db", str(tmp_path / "e.sqlite"), "verify"]) == 0
