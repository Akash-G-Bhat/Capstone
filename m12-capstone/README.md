# Capstone starter - AI-Powered Network & Security Operations Assistant

Built-in building blocks (read-only, offline):
  assistant.py check         scan a file for secrets, personal data and prompt injection
  assistant.py troubleshoot  sanitise evidence and fill a runbook prompt (prompts/runbook-*.md)
  assistant.py rca           build a blameless RCA prompt from a timeline (prompts/rca.md)
  assistant.py action        approval gate with tiers T0-T3 and an audit trail (audit/)

The assistant writes ready-made prompts into out/. Open them in VS Code and
send them to GitHub Copilot Chat with #file - Copilot is the AI for this course.

Plug in your earlier work (copy the script into this folder and call it from assistant.py):
  Troubleshooting runbooks   Module 3 runbook prompts        -> prompts/runbook-<symptom>.md
  Log investigation          Module 6 correlate.py
  Incident timelines         Module 11 timeline_builder.py
  Security alert analysis    Module 5 triage_helper.py
  Firewall rule review       Module 7 firewall/fw_check.py
  Vulnerability summary      Module 8 vuln/vuln_merge.py
  Compliance checklist       Module 8 compliance/compliance_check.py
  Approval workflow ideas    Module 9 agent_proto.py (tiers, kill switch, audit)

Rules: fictional lab data only; every action that is not read-only goes through
`assistant.py action` and is recorded in audit/.

## Components

### `check`
Scans a file for secrets, personal data and instruction-like text. It prints finding categories only, never matched values. This sample has two findings; do not send the raw file to AI.
`python3 assistant.py check samples/router-output.txt`

### `troubleshoot`
Sanitises evidence, fills a symptom-specific runbook prompt and saves it in `out/`.
`python3 assistant.py troubleshoot --symptom bgp --evidence samples/router-output.txt`

### `rca`
Sanitises an incident timeline and creates a blameless RCA prompt in `out/`.
`python3 assistant.py rca --timeline samples/timeline.txt --incident INC-DEMO-1015`

### `alerts`
Runs the read-only Module 5 triage helper, checks its captured output, then saves an analysis prompt in `out/` only if it passes.
`python3 assistant.py alerts`

### `action`
Records an approval decision. T1 is a low-risk approval, T2 is proposal-only, and T3 is refused; this starter does not execute the named operation.
`python3 assistant.py action --name "open demo ticket" --tier T1 --approver Demo-Approver`
`python3 assistant.py action --name "change demo ACL" --tier T2 --approver Demo-Approver`
`python3 assistant.py action --name "delete demo logs" --tier T3`

## 8-minute demo

- **0–1:** Explain that SOC analysts get faster alert context. Measure a manual triage and assisted run before quoting time saved.
- **1–5:** Run `check samples/router-output.txt`; confirm it reports two categories without exposing values. Run `troubleshoot`, then open its saved prompt from `out/` in Copilot Chat with `#file`. Verify Copilot names the 1400/1500-byte DF-bit tests and check its claims against the source evidence.
- **5–6:** Show T1 approval, T2 proposal-only approval and T3 refusal; open `audit/assistant-audit.jsonl`.
- **6–7:** Show these component commands and the reusable templates in `prompts/`.
- **7–8:** Explain limits: fictional/offline inputs, heuristic checks, no live SIEM or automatic remediation. Next: test with more benign and adversarial fixtures, then add a controlled ticket handoff.

Captured command output for the demo is stored in `demo/` (`check.txt`, `troubleshoot.txt`, `rca.txt`, `alerts.txt`, `action-t1.txt`, `action-t2.txt`, `action-t3.txt`).
