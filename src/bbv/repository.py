"""All SQL lives here. Every state change is one atomic transaction that writes
the finding update AND its transition row together, so a crash never leaves a
confidence change without an audit trail."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import models as m
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
                "SELECT state, confidence FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"finding {finding_id} does not exist")
            from_state = row["state"]
            conf_before = row["confidence"]

            sm.assert_transition(from_state, to_state)

            self.conn.execute(
                """UPDATE findings
                   SET state = ?, confidence = ?,
                       updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                   WHERE id = ?""",
                (to_state, new_confidence, finding_id),
            )
            cur = self.conn.execute(
                """INSERT INTO transitions
                   (finding_id, from_state, to_state, confidence_before, confidence_after, reason)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (finding_id, from_state, to_state, conf_before, new_confidence, reason),
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
