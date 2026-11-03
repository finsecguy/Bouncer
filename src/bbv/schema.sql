-- bbv schema. PRAGMAs that must persist per-connection (foreign_keys, etc.)
-- are set in db.connect(), NOT here: PRAGMA foreign_keys is per-connection and
-- would not survive this script's connection closing.

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program      TEXT NOT NULL,
    target_url   TEXT NOT NULL,
    vuln_class   TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT 'new',
    confidence   REAL NOT NULL DEFAULT 0.3,
    request      TEXT NOT NULL,          -- JSON: method/url/headers/params/body
    notes        TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,          -- diff | canary_reflection | browser_exec | idor_match | sqli_differential | error | scope_block
    data         TEXT NOT NULL,          -- JSON
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS transitions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    from_state        TEXT NOT NULL,
    to_state          TEXT NOT NULL,
    confidence_before REAL NOT NULL,
    confidence_after  REAL NOT NULL,
    reason            TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_state     ON findings(state);
CREATE INDEX IF NOT EXISTS idx_evidence_finding   ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_transitions_finding ON transitions(finding_id);
