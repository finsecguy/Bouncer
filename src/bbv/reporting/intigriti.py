"""Intigriti markdown report formatter."""
from __future__ import annotations

import json

from .base import Reporter, ReportFacts


class IntigritiReporter(Reporter):
    platform = "intigriti"

    def render(self, facts: ReportFacts) -> str:
        f = facts.finding
        a = facts.assessment
        lines: list[str] = []
        add = lines.append

        add(f"# {facts.title}")
        add("")
        add(f"- **Program:** {f.program}")
        add(f"- **Finding ID:** {f.id}")
        add(f"- **Vulnerability type:** {f.vuln_class}  ({a.cwe_id}: {a.cwe_name})")
        add(f"- **Severity:** {a.severity}  (CVSS 3.1 {a.cvss_score})")
        add(f"- **CVSS vector:** `{a.cvss_vector}`")
        add(f"- **Target:** {f.target_url}")
        add("")

        add("## Summary")
        add("")
        add(facts.summary)
        add("")

        add("## Steps to Reproduce")
        add("")
        for i, step in enumerate(facts.steps, 1):
            add(f"{i}. {step}")
        add("")

        add("## Impact")
        add("")
        add(facts.impact)
        add("")

        add("## Severity Rationale (CVSS 3.1)")
        add("")
        add(f"Vector: `{a.cvss_vector}` → **{a.cvss_score} ({a.severity})**. "
            "Each metric is derived from the evidence below, not estimated:")
        add("")
        for metric, why in a.metric_reasoning.items():
            add(f"- **{metric}** ({a.metrics.get(metric, '—')}): {why}"
                if metric in a.metrics else f"- **{metric}**: {why}")
        add("")

        add("## Evidence Appendix")
        add("")
        add("Every evidence row recorded during deterministic validation is "
            "reproduced verbatim below; nothing is summarised away.")
        add("")
        for ev in facts.evidence:
            add(f"### Evidence #{ev.id} — `{ev.kind}`  ({ev.created_at})")
            add("")
            add("```json")
            add(json.dumps(ev.data, indent=2))
            add("```")
            add("")

        add("## Validation Trail")
        add("")
        add("| time | from | to | confidence | reason |")
        add("|------|------|----|-----------|--------|")
        for t in facts.transitions:
            reason = t.reason.replace("|", "\\|")
            add(f"| {t.created_at} | {t.from_state} | {t.to_state} | "
                f"{t.confidence_before:.2f} → {t.confidence_after:.2f} | {reason} |")
        add("")

        add("---")
        add("")
        add("_This report was assembled deterministically from stored validation "
            "evidence. It has NOT been submitted anywhere — submission to the "
            "platform is a manual action performed by the researcher._")
        add("")
        return "\n".join(lines)
