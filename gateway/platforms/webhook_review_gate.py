"""Pull-request review gate for the Hermes webhook.

Creates the implementer block and one reviewer card, and arms a one-shot
10-minute alert. Never merges and never submits a GitHub APPROVE review.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any, Callable, Optional

ALLOWED_ACTIONS = ("opened", "synchronize")
REVIEWER_SKILLS = ("github-code-review", "requesting-code-review")
HERMES_BIN = "/home/hermes/.hermes/venvs/hermes-023f959a28de/bin/hermes"
ALERT_SCRIPT = "/home/hermes/.hermes/profiles/neo/scripts/pr_review_alert.py"
DEFAULT_REVIEW_ASSIGNEE = "default"

Runner = Callable[[list[str]], tuple[int, str, str]]


def webhook_action_allowed(route_config: Any, payload: Any) -> bool:
    """Return False when a route actions allow-list excludes this payload.

    Missing or empty ``actions`` means no action filter (events still apply).
    """
    if not isinstance(route_config, dict):
        return True
    allowed = route_config.get("actions")
    if allowed is None or allowed == [] or allowed == "":
        return True
    if isinstance(allowed, str):
        allowed_list = [allowed]
    elif isinstance(allowed, (list, tuple, set)):
        allowed_list = list(allowed)
    else:
        return False
    if not isinstance(payload, dict):
        return False
    action = payload.get("action")
    if not isinstance(action, str):
        return False
    return action in allowed_list


def review_instructions() -> str:
    return (
        "After the spec stage, record it with python3 /home/hermes/.hermes/scripts/review_telemetry.py "
        "record-stage --repo OWNER/REPO --number N --stage spec --seconds S --tokens T --cost USD "
        "--findings JSON. JSON is a list of objects with key, severity blocking or nit, and summary. "
        "After the quality stage, run the same command with --stage quality. "
        "Record what CI caught with record-ci --repo OWNER/REPO --number N --findings JSON. "
        "When you complete the card, put the output of "
        "python3 /home/hermes/.hermes/scripts/review_telemetry.py footer --repo OWNER/REPO --number N "
        "in the completion report. "
        "Spec stage first, using Grok high reasoning. "
        "Quality stage starts only after spec passes, and uses the other "
        "family (Fable or Sol), not Grok. "
        "Blocking findings: logic errors, security, spend order, permissions. "
        "Missing tests block only when the diff changes behavior. "
        "T0 (docs or metadata only, no instruction, guard, or code behavior): "
        "one reviewer from the other family. Not Grok-high, and not a second family. "
        "A 10-minute alert means the review is still running. "
        "Do not kill the reviewer, do not unblock, and do not merge on that alert. "
        "Merge only when the review verdict is pass or approve AND GitHub CI is "
        "green (full unit suite and the safety registry). "
        "Do not merge. Do not post a GitHub APPROVE review. A comment is not a merge. "
        "Do not move any card to the review status column."
    )


def _default_run(argv: list[str]) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception:
        return 1, "", "command failed"
    return proc.returncode, proc.stdout or "", ""


def _task_id(stdout: str) -> Optional[str]:
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and data.get("id"):
        return str(data["id"])
    return None


def _pr_fields(payload: dict) -> tuple[str, str, str, str, str]:
    repo = ""
    repository = payload.get("repository")
    if isinstance(repository, dict):
        repo = str(repository.get("full_name") or "")
    number = payload.get("number")
    number_s = str(number) if number is not None else ""
    pr = payload.get("pull_request")
    sha = ""
    url = ""
    if isinstance(pr, dict):
        url = str(pr.get("html_url") or "")
        head = pr.get("head")
        if isinstance(head, dict) and head.get("sha"):
            sha = str(head.get("sha"))
    action = payload.get("action")
    action_s = action if isinstance(action, str) else ""
    return action_s, repo, number_s, sha, url


def _unit_name(repo: str, number: str, sha: str) -> str:
    digest = hashlib.sha256(f"{repo}:{number}:{sha}".encode()).hexdigest()[:12]
    return f"hermes-pr-review-alert-{digest}"


def post_still_running_alert(card_id: str, repo: str, number: str, *, run: Optional[Runner] = None) -> int:
    """Comment once that the review is still running. Does not unblock or merge."""
    run = run or _default_run
    text = (
        f"review-alert: pull_request review is still running after 10 minutes "
        f"for {repo}#{number}. Not killing the reviewer, not unblocking, not merging."
    )
    code, _out, _err = run(
        [HERMES_BIN, "kanban", "comment", "--author", "webhook-review-gate", card_id, text]
    )
    return code


def apply_review_gate(payload: dict, *, run: Optional[Runner] = None) -> dict:
    """Find or create the implementer card, block it, spawn one reviewer.

    Returns a summary. Does not merge and does not call GitHub.
    """
    run = run or _default_run
    action, repo, number, sha, url = _pr_fields(payload if isinstance(payload, dict) else {})
    note_bits = []
    summary: dict[str, Any] = {
        "ok": False,
        "action": action,
        "repo": repo,
        "number": number,
        "sha": sha,
        "implementer_id": None,
        "reviewer_id": None,
        "alert_scheduled": False,
        "merged": False,
    }
    if action not in ALLOWED_ACTIONS or not repo or not number:
        summary["note"] = "review gate skipped: not an opened or synchronize pull request"
        return summary

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "review_telemetry",
            "/home/hermes/.hermes/scripts/review_telemetry.py",
        )
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.record_open(repo, number, sha)
    except Exception:
        pass

    reason = f"review-required: pull_request {action} {repo}#{number}"
    instructions = review_instructions()
    reviewer_assignee = os.environ.get("HERMES_PR_REVIEW_ASSIGNEE", DEFAULT_REVIEW_ASSIGNEE).strip()
    impl_body = (
        f"Implementer for {url or repo + '#' + number}. "
        f"Sticky block reason prefix review-required:. "
        f"Do not move this card to the review column. {instructions}"
    )
    code, out, _err = run(
        [
            HERMES_BIN,
            "kanban",
            "create",
            "--json",
            "--idempotency-key",
            f"review-impl:{repo}:{number}",
            "--created-by",
            "webhook-review-gate",
            "--body",
            impl_body,
            f"PR {repo}#{number} implementer",
        ]
    )
    impl_id = _task_id(out) if code == 0 else None
    summary["implementer_id"] = impl_id
    if not impl_id:
        summary["note"] = "review gate could not create the implementer card; no merge attempted"
        return summary

    bcode, _bout, _berr = run([HERMES_BIN, "kanban", "block", impl_id, reason])
    note_bits.append(
        f"implementer {impl_id} block rc={bcode} reason_prefix=review-required:"
    )

    short = sha[:7] if sha else "nosha"
    rev_body = (
        f"Reviewer for {url or repo + '#' + number} head {sha or 'unknown'}. "
        f"Parent implementer {impl_id}. "
        f"Skills: github-code-review, requesting-code-review. "
        f"{instructions}"
    )
    rcode, rout, _rerr = run(
        [
            HERMES_BIN,
            "kanban",
            "create",
            "--json",
            "--idempotency-key",
            f"review-rev:{repo}:{number}:{sha or 'nosha'}",
            "--skill",
            REVIEWER_SKILLS[0],
            "--skill",
            REVIEWER_SKILLS[1],
            *( ["--assignee", reviewer_assignee] if reviewer_assignee else [] ),
            "--created-by",
            "webhook-review-gate",
            "--body",
            rev_body,
            f"PR {repo}#{number} reviewer {short}",
        ]
    )
    rev_id = _task_id(rout) if rcode == 0 else None
    summary["reviewer_id"] = rev_id
    if not rev_id:
        summary["note"] = "implementer blocked; reviewer card was not created; no merge attempted"
        return summary
    note_bits.append(
        f"reviewer {rev_id} related_implementer={impl_id} assignee={reviewer_assignee or '(unassigned)'} skills={','.join(REVIEWER_SKILLS)}"
    )

    unit = _unit_name(repo, number, sha or "nosha")
    scode, sout, _serr = run(
        ["systemctl", "--user", "show", unit, "-p", "LoadState", "--value"]
    )
    load_state = (sout or "").strip()
    if scode == 0 and load_state and load_state != "not-found":
        note_bits.append(f"alert unit {unit} already present")
    else:
        runtime = os.environ.get("XDG_RUNTIME_DIR", "")
        tcode, _tout, _terr = run(
            [
                "systemd-run",
                "--user",
                "--on-active=10min",
                f"--unit={unit}",
                "--description=Hermes PR review still-running alert",
                "/usr/bin/python3",
                ALERT_SCRIPT,
                rev_id,
                repo,
                number,
            ]
        )
        summary["alert_scheduled"] = tcode == 0
        note_bits.append(f"alert unit {unit} scheduled={tcode == 0} runtime_dir_set={bool(runtime)}")

    summary["ok"] = True
    summary["note"] = "; ".join(note_bits) + "; merge=not-performed"
    return summary
