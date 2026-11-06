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
    matched_signature_id INTEGER REFERENCES false_positive_signatures(id),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Recon assets. Every row was scope-checked before being written: in_scope
-- records the verdict (out-of-scope assets are kept, flagged, and never probed).
CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    program      TEXT NOT NULL,
    kind         TEXT NOT NULL,          -- subdomain | host | endpoint | js | tech
    value        TEXT NOT NULL,          -- the subdomain / url / endpoint / fingerprint
    in_scope     INTEGER NOT NULL,       -- 1 or 0, scope verdict at persist time
    source       TEXT NOT NULL,          -- subfinder | httpx | katana | seed | manual
    metadata     TEXT,                   -- JSON: status_code, tech[], title, content_type...
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(program, kind, value)
);

-- Milestone 3: false-positive signature catalog (ADVISORY / triage only).
-- A signature is a deterministic fingerprint of WHY a finding was rejected,
-- derived from the same structured evidence the validators already emit. It
-- never gates or alters validation; it only makes repetition visible.
CREATE TABLE IF NOT EXISTS false_positive_signatures (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_class       TEXT NOT NULL,
    feature_key      TEXT NOT NULL,     -- canonical fingerprint string
    scope            TEXT NOT NULL,     -- 'global' | 'program'
    program          TEXT,              -- set when scope='program', else NULL
    endpoint         TEXT,              -- normalized host+path for program-scoped, else NULL
    example_evidence TEXT NOT NULL,     -- JSON: one representative evidence sample
    last_reason      TEXT,              -- last rejection reason text (human context)
    times_seen       INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Dedupe identity. COALESCE handles NULL program/endpoint so global rows (both
-- NULL) collapse to one row rather than SQLite treating each NULL as distinct.
CREATE UNIQUE INDEX IF NOT EXISTS idx_fps_identity ON false_positive_signatures(
    vuln_class, feature_key, scope, COALESCE(program,''), COALESCE(endpoint,'')
);

-- Per-program recurrence for EVERY signature (including globally-scoped ones),
-- so "this exact pattern, on this exact program, N times" is always answerable.
CREATE TABLE IF NOT EXISTS signature_program_counts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id  INTEGER NOT NULL REFERENCES false_positive_signatures(id) ON DELETE CASCADE,
    program       TEXT NOT NULL,
    times_seen    INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_seen     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    UNIQUE(signature_id, program)
);

CREATE INDEX IF NOT EXISTS idx_findings_state     ON findings(state);
CREATE INDEX IF NOT EXISTS idx_evidence_finding   ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_transitions_finding ON transitions(finding_id);
CREATE INDEX IF NOT EXISTS idx_transitions_sig    ON transitions(matched_signature_id);
CREATE INDEX IF NOT EXISTS idx_assets_program     ON assets(program, kind);
CREATE INDEX IF NOT EXISTS idx_assets_scope       ON assets(program, in_scope);
CREATE INDEX IF NOT EXISTS idx_fps_lookup         ON false_positive_signatures(vuln_class, scope, program);
