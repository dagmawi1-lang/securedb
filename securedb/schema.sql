-- SecureDB schema: a small school records system with security controls built into the database.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY, description TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (
  role TEXT NOT NULL REFERENCES roles(name), resource TEXT NOT NULL, action TEXT NOT NULL CHECK (action IN ('read','insert','update','delete')),
  scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all','own','class')),  -- row-level scope
  PRIMARY KEY (role, resource, action));
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, role TEXT NOT NULL REFERENCES roles(name),
  active INTEGER NOT NULL DEFAULT 1, student_id INTEGER REFERENCES students(id));

CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, name TEXT NOT NULL, grade_level INTEGER NOT NULL CHECK (grade_level BETWEEN 9 AND 12), email TEXT);
CREATE TABLE IF NOT EXISTS classes (id INTEGER PRIMARY KEY, title TEXT NOT NULL, teacher_id INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS enrollments (student_id INTEGER NOT NULL REFERENCES students(id), class_id INTEGER NOT NULL REFERENCES classes(id), PRIMARY KEY (student_id, class_id));
CREATE TABLE IF NOT EXISTS grades (
  id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES students(id), class_id INTEGER NOT NULL REFERENCES classes(id),
  assignment TEXT NOT NULL, score REAL NOT NULL CHECK (score BETWEEN 0 AND 100), FOREIGN KEY (student_id, class_id) REFERENCES enrollments(student_id, class_id));

-- Who is acting right now. The access layer sets this per operation so triggers can attribute changes.
CREATE TABLE IF NOT EXISTS session_context (id INTEGER PRIMARY KEY CHECK (id = 1), username TEXT NOT NULL, at TEXT NOT NULL);

-- Append-only, hash-chained audit log. Each row's hash covers the previous row's hash, so editing or deleting
-- any past row (even with direct SQL) breaks the chain and is detectable.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, username TEXT NOT NULL, action TEXT NOT NULL, resource TEXT NOT NULL,
  row_id INTEGER, detail TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- Security events: denied requests, suspicious input, logins.
CREATE TABLE IF NOT EXISTS security_events (id INTEGER PRIMARY KEY, at TEXT NOT NULL, username TEXT NOT NULL, kind TEXT NOT NULL, resource TEXT, detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS sec_user_at ON security_events (username, at);
CREATE INDEX IF NOT EXISTS audit_user_at ON audit_log (username, at);

-- Data-change triggers write the audit trail automatically, even for changes that bypass the Python layer.
-- audit_append() is a Python function registered on every connection (see db.py). It computes the hash chain.
CREATE TRIGGER IF NOT EXISTS grades_ins AFTER INSERT ON grades BEGIN
  SELECT audit_append('insert', 'grades', NEW.id, json_object('student_id', NEW.student_id, 'class_id', NEW.class_id, 'assignment', NEW.assignment, 'score', NEW.score)); END;
CREATE TRIGGER IF NOT EXISTS grades_upd AFTER UPDATE ON grades BEGIN
  SELECT audit_append('update', 'grades', NEW.id, json_object('assignment', NEW.assignment, 'old_score', OLD.score, 'new_score', NEW.score)); END;
CREATE TRIGGER IF NOT EXISTS grades_del AFTER DELETE ON grades BEGIN
  SELECT audit_append('delete', 'grades', OLD.id, json_object('assignment', OLD.assignment, 'score', OLD.score)); END;
CREATE TRIGGER IF NOT EXISTS students_upd AFTER UPDATE ON students BEGIN
  SELECT audit_append('update', 'students', NEW.id, json_object('old_email', OLD.email, 'new_email', NEW.email, 'old_name', OLD.name, 'new_name', NEW.name)); END;
CREATE TRIGGER IF NOT EXISTS users_role_upd AFTER UPDATE OF role, active ON users BEGIN
  SELECT audit_append('update', 'users', NEW.id, json_object('username', NEW.username, 'old_role', OLD.role, 'new_role', NEW.role, 'active', NEW.active)); END;
