# Bouncer design principles

## The human-in-the-loop boundary (non-negotiable)

No feature, flag, or mode of Bouncer may ever cause the tool to:

- **auto-approve** a finding,
- **auto-dismiss** a finding,
- **auto-generate a report** for a finding that a human has not already approved, or
- **auto-submit** anything to a bug bounty platform. (There is no submission
  code anywhere in this repo, by design, and none may be added that submits
  without a separate, deliberate human action.)

Detection and validation may be automated as much as is useful. Approval,
dismissal, and submission may not be, ever.

## Why

The validators (`reflected_xss`, `idor`, `sqli_boolean`) are deterministic and
produce real request/response evidence. Automating detection and validation is
safe because every result is provable from stored evidence and reproducible: the
machine is only reporting what it measured.

Approval, dismissal, and submission are different in kind. They are human
judgment calls, about whether a finding is worth a human's name on a report,
whether it is in genuine scope and good faith, and whether it should be sent to a
third party. No amount of convenience justifies a machine making that call. The
pipeline therefore always stops at `in_review`, and a human must separately and
explicitly invoke `bouncer review` (to approve or dismiss) and `bouncer report` (to
generate a write-up they will read before submitting themselves).

## Scope of this principle

This applies to **all** current and future automation, with no exceptions:

- It applies to `bouncer run` and to its opt-in `--auto-chain` mode, which may chain
  recon, candidate generation, and ingestion unattended but **stops at ingest**.
  `--auto-chain` never approves, dismisses, reports, or submits.
- It applies to any future scheduled, unattended, or "fully automatic" mode that
  anyone might add later. Such a mode may extend automation only up to and
  including ingest (running a validator and recording its evidence-based
  `in_review` or `rejected` result). It may not cross into approval, dismissal,
  report generation, or submission.

If a future change and this principle ever point in different directions, this
principle wins.

## Enforcement

This boundary is enforced by an automated test, not by documentation alone. See
`tests/test_design_boundary.py`:

- `test_auto_chain_can_never_reach_approval_or_report` runs a full `--auto-chain`
  pass with the approval/dismissal/report sinks wrapped to fail if called, and
  asserts none of them fire and that no finding leaves `in_review`/`rejected`.
- `test_run_path_does_not_wire_in_reporting_or_approval` statically asserts that
  no code reachable from `cmd_run` within the CLI layer imports the reporting or
  severity modules or references report-generation entry points.

If either test fails, the human-in-the-loop boundary has been crossed. That is a
build failure on purpose, not a flaky test: fix the code, do not weaken the test.
