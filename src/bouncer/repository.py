"""All SQL lives here. Every state change is one atomic transaction that writes
the finding update AND its transition row together, so a crash never leaves a
confidence change without an audit trail."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import models as m
from . import signatures as sig
from . import state_machine as sm


class Repository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # --- findings ---
    def create_finding(self, f: m.Finding) -> int:
        cur = self.conn.execute(
            """INSERT INTO findings (program, target_url, vuln_class, state, confidence, request, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (f.program, f.target_url, f.vuln_class, f.state, f.confidence,
             json.dumps(f.request), f.notes),
        )
        return int(cur.lastrowid)

    def get_finding(self, finding_id: int) -> m.Finding | None:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    def list_findings(self, state: str | None = None) -> list[m.Finding]:
        if state:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE state = ? ORDER BY id", (state,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY id"
            ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> m.Finding:
        return m.Finding(
            id=row["id"],
            program=row["program"],
            target_url=row["target_url"],
            vuln_class=row["vuln_class"],
            state=row["state"],
            confidence=row["confidence"],
            request=json.loads(row["request"]),
            notes=row["notes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # --- assets ---
    def upsert_asset(self, a: m.Asset) -> int:
        """Insert or update an asset. Idempotent on (program, kind, value) so
        re-running recon does not duplicate rows."""
        cur = self.conn.execute(
            """INSERT INTO assets (program, kind, value, in_scope, source, metadata)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(program, kind, value) DO UPDATE SET
                   in_scope = excluded.in_scope,
                   source   = excluded.source,
                   metadata = excluded.metadata
               RETURNING id""",
            (a.program, a.kind, a.value, 1 if a.in_scope else 0, a.source,
             json.dumps(a.metadata)),
        )
        return int(cur.fetchone()["id"])

    def list_assets(
        self, program: str, kind: str | None = None, in_scope: bool | None = None
    ) -> list[m.Asset]:
        q = "SELECT * FROM assets WHERE program = ?"
        params: list[Any] = [program]
        if kind is not None:
            q += " AND kind = ?"
            params.append(kind)
        if in_scope is not None:
            q += " AND in_scope = ?"
            params.append(1 if in_scope else 0)
        q += " ORDER BY id"
        rows = self.conn.execute(q, params).fetchall()
        return [
            m.Asset(
                id=r["id"], program=r["program"], kind=r["kind"], value=r["value"],
                in_scope=bool(r["in_scope"]), source=r["source"],
                metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # --- evidence ---
    def add_evidence(self, ev: m.Evidence) -> int:
        cur = self.conn.execute(
            "INSERT INTO evidence (finding_id, kind, data) VALUES (?, ?, ?)",
            (ev.finding_id, ev.kind, json.dumps(ev.data)),
        )
        return int(cur.lastrowid)

    def list_evidence(self, finding_id: int) -> list[m.Evidence]:
        rows = self.conn.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY id", (finding_id,)
        ).fetchall()
        return [
            m.Evidence(id=r["id"], finding_id=r["finding_id"], kind=r["kind"],
                       data=json.loads(r["data"]), created_at=r["created_at"])
            for r in rows
        ]

    # --- transitions ---
    def list_transitions(self, finding_id: int) -> list[m.Transition]:
        rows = self.conn.execute(
            "SELECT * FROM transitions WHERE finding_id = ? ORDER BY id", (finding_id,)
        ).fetchall()
        return [
            m.Transition(
                id=r["id"], finding_id=r["finding_id"], from_state=r["from_state"],
                to_state=r["to_state"], confidence_before=r["confidence_before"],
                confidence_after=r["confidence_after"], reason=r["reason"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # --- the one guarded mutation ---
    def transition(
        self,
        finding_id: int,
        to_state: str,
        new_confidence: float,
        reason: str,
        evidence: list[m.Evidence] | None = None,
    ) -> m.Transition:
        """Atomically: validate the transition, update the finding, log the
        transition, and persist any evidence. Raises IllegalTransition before
        writing anything if the move is not allowed."""
        new_confidence = max(0.0, min(1.0, new_confidence))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT state, confidence, vuln_class, program, target_url "
                "FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"finding {finding_id} does not exist")
            from_state = row["state"]
            conf_before = row["confidence"]

            sm.assert_transition(from_state, to_state)

            # ADVISORY signature catalog: on a validating->rejected move, derive
            # a deterministic fingerprint from this rejection's evidence and
            # upsert it IN THIS SAME TRANSACTION. If it fails, the whole
            # rejection rolls back — no silent partial write. This never affects
            # the rejection decision itself (already made by the validator).
            matched_sig_id: int | None = None
            if from_state == m.VALIDATING and to_state == m.REJECTED:
                matched_sig_id = self._record_signature(
                    row["vuln_class"], row["program"], row["target_url"],
                    evidence or [], reason,
                )

            self.conn.execute(
                """UPDATE findings
                   SET state = ?, confidence = ?,
                       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                   WHERE id = ?""",
                (to_state, new_confidence, finding_id),
            )
            cur = self.conn.execute(
                """INSERT INTO transitions
                   (finding_id, from_state, to_state, confidence_before,
                    confidence_after, reason, matched_signature_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (finding_id, from_state, to_state, conf_before, new_confidence,
                 reason, matched_sig_id),
            )
            trans_id = int(cur.lastrowid)

            for ev in (evidence or []):
                self.conn.execute(
                    "INSERT INTO evidence (finding_id, kind, data) VALUES (?, ?, ?)",
                    (finding_id, ev.kind, json.dumps(ev.data)),
                )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        return m.Transition(
            id=trans_id, finding_id=finding_id, from_state=from_state,
            to_state=to_state, confidence_before=conf_before,
            confidence_after=new_confidence, reason=reason,
        )

    # --- signature catalog (advisory) ---
    def _record_signature(
        self, vuln_class: str, program: str, target_url: str,
        evidence: list[m.Evidence], reason: str,
    ) -> int | None:
        """Upsert the signature for a rejection. Runs INSIDE the caller's open
        transaction (no commit here) so it shares the rejection's atomicity."""
        s = sig.extract(vuln_class, evidence)
        if s is None:
            return None  # no deterministic fingerprint -> record nothing

        program_val = program if s.scope == sig.SCOPE_PROGRAM else None
        endpoint = (sig.normalize_endpoint(target_url)
                    if s.scope == sig.SCOPE_PROGRAM else None)

        existing = self.conn.execute(
            """SELECT id FROM false_positive_signatures
               WHERE vuln_class = ? AND feature_key = ? AND scope = ?
                 AND COALESCE(program,'') = COALESCE(?, '')
                 AND COALESCE(endpoint,'') = COALESCE(?, '')""",
            (s.vuln_class, s.feature_key, s.scope, program_val, endpoint),
        ).fetchone()

        if existing:
            sig_id = int(existing["id"])
            self.conn.execute(
                """UPDATE false_positive_signatures
                   SET times_seen = times_seen + 1,
                       last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                       last_reason = ?
                   WHERE id = ?""",
                (reason, sig_id),
            )
        else:
            cur = self.conn.execute(
                """INSERT INTO false_positive_signatures
                   (vuln_class, feature_key, scope, program, endpoint,
                    example_evidence, last_reason, times_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (s.vuln_class, s.feature_key, s.scope, program_val, endpoint,
                 json.dumps(s.example_evidence), reason),
            )
            sig_id = int(cur.lastrowid)

        # Per-program recurrence (tracked for every signature, global included).
        pc = self.conn.execute(
            "SELECT id FROM signature_program_counts WHERE signature_id = ? AND program = ?",
            (sig_id, program),
        ).fetchone()
        if pc:
            self.conn.execute(
                """UPDATE signature_program_counts
                   SET times_seen = times_seen + 1,
                       last_seen = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                   WHERE id = ?""",
                (pc["id"],),
            )
        else:
            self.conn.execute(
                """INSERT INTO signature_program_counts (signature_id, program, times_seen)
                   VALUES (?, ?, 1)""",
                (sig_id, program),
            )
        return sig_id

    def list_signatures(
        self, program: str | None = None, vuln_class: str | None = None
    ) -> list[dict]:
        """Signatures sorted by times_seen desc. When program is given, include
        that program's per-program count and restrict to signatures seen there."""
        if program:
            q = """SELECT s.*, pc.times_seen AS program_times_seen
                   FROM false_positive_signatures s
                   JOIN signature_program_counts pc ON pc.signature_id = s.id
                   WHERE pc.program = ?"""
            params: list[Any] = [program]
            if vuln_class:
                q += " AND s.vuln_class = ?"
                params.append(vuln_class)
            q += " ORDER BY s.times_seen DESC, s.id"
        else:
            q = "SELECT s.*, NULL AS program_times_seen FROM false_positive_signatures s"
            params = []
            if vuln_class:
                q += " WHERE s.vuln_class = ?"
                params.append(vuln_class)
            q += " ORDER BY s.times_seen DESC, s.id"
        return [dict(r) for r in self.conn.execute(q, params).fetchall()]

    def get_signature(self, signature_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM false_positive_signatures WHERE id = ?", (signature_id,)
        ).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["example_evidence"] = json.loads(out["example_evidence"]) if out["example_evidence"] else {}
        out["program_breakdown"] = [
            dict(r) for r in self.conn.execute(
                "SELECT program, times_seen, first_seen, last_seen "
                "FROM signature_program_counts WHERE signature_id = ? "
                "ORDER BY times_seen DESC", (signature_id,)
            ).fetchall()
        ]
        out["linked_finding_ids"] = [
            r["finding_id"] for r in self.conn.execute(
                "SELECT DISTINCT finding_id FROM transitions "
                "WHERE matched_signature_id = ? ORDER BY finding_id", (signature_id,)
            ).fetchall()
        ]
        return out

    def precheck_signatures(
        self, program: str, vuln_class: str, endpoint: str
    ) -> list[dict]:
        """Program-scoped signatures previously recorded for THIS endpoint. This
        is the only genuinely pre-validation-derivable match (endpoint + class);
        global/response-derived patterns are intentionally not matched here."""
        rows = self.conn.execute(
            """SELECT * FROM false_positive_signatures
               WHERE scope = 'program' AND program = ? AND vuln_class = ? AND endpoint = ?
               ORDER BY times_seen DESC""",
            (program, vuln_class, endpoint),
        ).fetchall()
        return [dict(r) for r in rows]

    def backfill_signatures(self) -> int:
        """Re-derive signatures from already-stored evidence for past rejections
        that have no signature linked yet. Read-only over evidence (no validator
        re-run), deterministic. Returns the number of transitions annotated."""
        pending = self.conn.execute(
            """SELECT t.id AS tid, t.finding_id, t.reason, f.vuln_class, f.program, f.target_url
               FROM transitions t JOIN findings f ON f.id = t.finding_id
               WHERE t.from_state = 'validating' AND t.to_state = 'rejected'
                 AND t.matched_signature_id IS NULL
               ORDER BY t.id""",
        ).fetchall()
        annotated = 0
        for r in pending:
            evidence = self.list_evidence(r["finding_id"])
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                sig_id = self._record_signature(
                    r["vuln_class"], r["program"], r["target_url"], evidence, r["reason"],
                )
                if sig_id is not None:
                    self.conn.execute(
                        "UPDATE transitions SET matched_signature_id = ? WHERE id = ?",
                        (sig_id, r["tid"]),
                    )
                    annotated += 1
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return annotated
