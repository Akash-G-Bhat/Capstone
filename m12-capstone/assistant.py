#!/usr/bin/env python3
"""assistant.py - capstone starter for the AI-Powered Network & Security Operations Assistant.

Provides the three mandatory-core building blocks; teams wire in their own prompts,
earlier lab scripts and two optional modules.

  troubleshoot  sanitise evidence, fill a runbook prompt, save it (and optionally send it)
  rca           build a blameless RCA prompt from an incident timeline
  action        human approval gate for any operation, with tiers and an audit trail
  check         scan a file for secrets or personal data before it goes into a prompt

The assistant never sends data anywhere by default: prompts are written to out/ for
pasting into the approved AI tool. To call your approved LLM directly, implement
llm_call() - every prompt still passes through sanitise() and check() first.

Examples:
  python3 assistant.py check samples/router-output.txt
  python3 assistant.py troubleshoot --symptom bgp --evidence samples/router-output.txt
  python3 assistant.py rca --timeline samples/timeline.txt --incident INC-OUTAGE-1015
  python3 assistant.py action --name "open ticket for INC-OUTAGE-1015" --tier T1
  python3 assistant.py action --name "block_ip 198.51.100.77" --tier T2
"""
import argparse
import getpass
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).parent
OUT = BASE / "out"
AUDIT = BASE / "audit" / "assistant-audit.jsonl"

# Module 10 sanitising rules, extended. Order matters: secrets first.
RULES = [
    (r"((?:secret|password|key) \d+ )\S+", r"\1<REDACTED>"),
    (r"(snmp-server community )\S+", r"\1<REDACTED>"),
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<EMAIL>"),
    (r"\+91-?[0-9x]{10}", "<PHONE>"),
    (r"(Configured from console by )\S+", r"\1<USER>"),          # blameless RCA: no names
    (r"([\w-]+) \([a-z][\w.]*\):", r"\1 (<PERSON>):"),          # chat lines "Role (name):"
]
CHECKS = {
    "secret or hash": r"(secret|password|key) \d+ (?!<REDACTED>)\S+",
    "SNMP community": r"snmp-server community (?!<REDACTED>)\S+",
    "email address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "private key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "instruction-like text": r"ignore (all )?(previous|prior) instructions",
}
TIERS = {"T0": "read-only, runs", "T1": "low-risk write, needs approval",
         "T2": "change, proposal only - a human executes", "T3": "never allowed"}


def audit(event, **kw):
    AUDIT.parent.mkdir(exist_ok=True)
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "event": event, **kw}
    with AUDIT.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def sanitise(text):
    for pat, rep in RULES:
        text = re.sub(pat, rep, text)
    return text


def check(text):
    """Return finding categories without including any matched sensitive text."""
    return [name for name, pat in CHECKS.items() if re.search(pat, text, re.I)]


def fill(template_name, **values):
    tpl = (BASE / "prompts" / template_name).read_text()
    for k, v in values.items():
        tpl = tpl.replace("{{" + k + "}}", v)
    missing = re.findall(r"\{\{(\w+)\}\}", tpl)
    if missing:
        raise SystemExit(f"Template still has placeholders: {missing}")
    return tpl


def save_prompt(name, prompt):
    OUT.mkdir(exist_ok=True)
    path = OUT / f"{name}-{datetime.now():%Y%m%d-%H%M%S}.txt"
    path.write_text(prompt)
    return path


def llm_call(prompt):
    # In this course the AI is GitHub Copilot Chat: open the prompt file saved in out/
    # and send it to Copilot with #file. Nothing here calls an AI service.
    raise NotImplementedError("Open the prompt in out/ and send it to GitHub Copilot Chat with #file.")


def cmd_check(a):
    findings = check(Path(a.file).read_text())
    for name in findings:
        print(f"FOUND  {name}")
    print("CLEAN" if not findings else f"{len(findings)} finding(s): fix before using this file in a prompt")
    audit("check", file=a.file, findings=len(findings))


def cmd_troubleshoot(a):
    evidence = sanitise(Path(a.evidence).read_text())
    issues = check(evidence)
    if issues:
        raise SystemExit(f"Stopped: sanitised evidence still contains {issues}")
    prompt = fill(f"runbook-{a.symptom}.md", evidence=evidence)
    path = save_prompt(f"troubleshoot-{a.symptom}", prompt)
    audit("troubleshoot", symptom=a.symptom, evidence=a.evidence, prompt=str(path.relative_to(BASE)))
    print(f"Prompt ready (sanitised): {path.relative_to(BASE)}")
    if a.send:
        print(llm_call(prompt))


def cmd_rca(a):
    timeline = sanitise(Path(a.timeline).read_text())
    issues = check(timeline)
    if issues:
        raise SystemExit(f"Stopped: timeline still contains {issues}")
    prompt = fill("rca.md", incident=a.incident, timeline=timeline)
    path = save_prompt(f"rca-{a.incident}", prompt)
    audit("rca", incident=a.incident, prompt=str(path.relative_to(BASE)))
    print(f"RCA prompt ready: {path.relative_to(BASE)}")


def cmd_alerts(_a):
    helper_dir = BASE.parent / "m05-secops"
    try:
        result = subprocess.run(
            [sys.executable, "triage_helper.py"],
            cwd=helper_dir,
            capture_output=True,
            text=True,
        )
    except OSError:
        audit("alerts", returncode=None, findings=0, saved=False)
        raise SystemExit("Alert triage could not run; no prompt was saved.")

    output = result.stdout
    findings = check(output)
    if result.returncode != 0 or findings:
        audit("alerts", returncode=result.returncode, findings=len(findings), saved=False)
        raise SystemExit("Alert triage failed or did not pass safety checks; no prompt was saved.")

    prompt = fill("alerts.md", alerts=output)
    path = save_prompt("alerts", prompt)
    audit("alerts", returncode=result.returncode, findings=0,
          prompt=str(path.relative_to(BASE)), saved=True)
    print(f"Alert analysis prompt ready: {path.relative_to(BASE)}")


def cmd_action(a):
    tier = a.tier
    print(f"Action: {a.name}\nTier:   {tier} ({TIERS[tier]})")
    if tier == "T3":
        audit("action", name=a.name, tier=tier, decision="refused")
        raise SystemExit("Refused: T3 actions are never allowed.")
    if tier == "T0":
        audit("action", name=a.name, tier=tier, decision="allowed")
        print("Allowed: read-only.")
        return
    approver = input("Approver name (blank = reject): ").strip() if a.approver is None else a.approver
    typed = input('Type APPROVE to approve: ').strip() if a.approver is None else "APPROVE"
    decision = "approved" if approver and typed == "APPROVE" else "rejected"
    audit("action", name=a.name, tier=tier, decision=decision, approver=approver or "-",
          operator=getpass.getuser())
    if decision == "rejected":
        print("Rejected: nothing done.")
    elif tier == "T1":
        print(f"Approved by {approver}: the assistant may perform this low-risk action.")
    else:
        print(f"Approved by {approver} as a PROPOSAL. A human engineer executes it under change control.")


def main():
    ap = argparse.ArgumentParser(description="Capstone starter assistant")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("check"); s.add_argument("file"); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("troubleshoot"); s.add_argument("--symptom", required=True, choices=["latency", "bgp"])
    s.add_argument("--evidence", required=True); s.add_argument("--send", action="store_true"); s.set_defaults(fn=cmd_troubleshoot)
    s = sub.add_parser("rca"); s.add_argument("--timeline", required=True); s.add_argument("--incident", required=True)
    s.set_defaults(fn=cmd_rca)
    s = sub.add_parser("alerts"); s.set_defaults(fn=cmd_alerts)
    s = sub.add_parser("action"); s.add_argument("--name", required=True); s.add_argument("--tier", required=True, choices=list(TIERS))
    s.add_argument("--approver", help="non-interactive approver name (for demos and tests)"); s.set_defaults(fn=cmd_action)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
