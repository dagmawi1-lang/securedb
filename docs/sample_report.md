# SecureDB activity report

## What happened
- Normal week: teachers graded their own classes, students viewed their own grades, counselor looked up students.
- ben (student) read grades: got only his own 4 rows (row-level security).
- ben tried to change grades 3 times: all denied → privilege probing.
- ben tried SQL injection "x' OR '1'='1" through the safe API: 0 rows returned, attempt logged.
- The same payload against a deliberately unsafe query would return 5 student records.
- mr_cho changed a Quiz 1 grade 71 → 98 at 23:40 → after-hours + large change.
- counselor_ray ran 24 queries in 3 minutes → mass read.
- Direct SQL (bypassing the app): changed grade #2 and promoted ben to admin. Triggers still audited it.
- An attacker dropped the append-only trigger and rewrote an audit entry to hide the promotion.

## Audit chain: ❌ BROKEN at entry #71 (71 entries checked)

## Alerts (7)
- **[CRITICAL] audit_tampering** — ? @ n/a: Audit hash chain broken at entry #71: a past record was altered or removed.
- **[CRITICAL] direct_sql_change** — <direct-sql> @ 2026-11-06T16:00:00: Grade #2 was changed with direct SQL, bypassing access control.
- **[HIGH] privilege_probing** — ben @ 2026-11-05T12:06:30: 3+ denied requests within 10 min (e.g. update not permitted for role student).
- **[HIGH] sql_injection_attempt** — ben @ 2026-11-05T12:07:00: Injection-like input on students: possible SQL injection payload: "x' OR '1'='1"
- **[HIGH] mass_read** — counselor_ray @ 2026-11-06T11:00:45: Read 60 records in 10 min (6 queries).
- **[MEDIUM] after_hours_change** — mr_cho @ 2026-11-05T23:40:00: update on grades #4 at 23:00.
- **[MEDIUM] large_grade_change** — mr_cho @ 2026-11-05T23:40:00: Grade #4 (Quiz 1) changed 71.0 → 98.0.