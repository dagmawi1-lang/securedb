# SecureDB roadmap

## Done (v1.0.0)
- [x] Database creation and management (schema, constraints, seed data, CLI)
- [x] Role-based permissions plus row-level security scopes
- [x] Audit logging (database triggers, append-only, SHA-256 hash chain)
- [x] Security event tracking (logins, denials, suspicious input)
- [x] Detection of suspicious database activity (8 rules)
- [x] 9 tests, including a clean-week zero-alert check

## Next
- [ ] PostgreSQL version using real Row-Level Security policies (`CREATE POLICY`) and `pgaudit`
- [ ] Periodically anchor the latest audit hash somewhere external (e.g. printed in a daily report) so a full rewrite is also detectable
- [ ] Encrypt sensitive columns (emails) at rest
- [ ] Small web UI to browse alerts
