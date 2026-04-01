#!/usr/bin/env python3
"""
coffer-detect v0.3
Behavioral diagnostic rules for coffer-mcp audit telemetry.

Changes from v0.2:
- Accepts JSON audit data natively (from coffer_audit MCP tool output)
- Handles all 8 event types: credential.created, credential.listed,
  credential.test, credential.used, credential.removed, browser_login.success,
  browser_fetch.success, browser_fetch.failed
- Tightened thresholds based on real baseline data (45+ events)
- New rule: content volume spike detection (Rule 011)
- New rule: credential lifecycle anomaly (Rule 012)
- Improved: credential enumeration uses 30s window (was 120s)

Usage:
    python coffer_detect_v03.py                     # run against embedded data
    python coffer_detect_v03.py audit.json           # run against exported JSON
"""

import json
import sys
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Parse events
# ---------------------------------------------------------------------------

def parse_events_from_json(data: dict | list) -> list[dict]:
    """Parse JSON audit data from coffer_audit MCP tool output."""
    if isinstance(data, dict) and "events" in data:
        raw_events = data["events"]
    elif isinstance(data, list):
        raw_events = data
    else:
        raise ValueError("Expected dict with 'events' key or list of events")

    events = []
    for raw in raw_events:
        event = {
            "event_id": raw.get("event_id", ""),
            "event_type": raw.get("event_type", ""),
            "alias": raw.get("alias", ""),
            "status": raw.get("status", "unknown"),
            "details": raw.get("details", {}),
            "timestamp": None,
            "timestamp_str": "",
            "prev_hash": raw.get("prev_hash", ""),
            "hash": raw.get("hash", ""),
        }
        # Parse timestamp from epoch
        ts = raw.get("timestamp")
        if ts:
            event["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc)
            event["timestamp_str"] = event["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        events.append(event)

    # Sort chronologically by event_id
    events.sort(key=lambda e: e["event_id"])
    return events


def get_chain_integrity(data: dict) -> str | None:
    """Extract chain integrity message from audit data."""
    if isinstance(data, dict):
        return data.get("chain_integrity", None)
    return None


# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------

class Finding:
    def __init__(self, rule_id, rule_name, criterion, severity, description, evidence):
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.criterion = criterion
        self.severity = severity
        self.description = description
        self.evidence = evidence

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "criterion": self.criterion,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }


def rule_001_integrity_chain(events: list[dict], chain_msg: str | None) -> list[Finding]:
    """Rule 001: Integrity Chain Violation (Criterion #1 - Structural Mutation)"""
    findings = []
    if chain_msg and ("broken" in chain_msg.lower() or "mismatch" in chain_msg.lower()):
        findings.append(Finding(
            rule_id="RULE-001",
            rule_name="Integrity Chain Violation",
            criterion="#1 Structural Mutation",
            severity="CRITICAL",
            description="Audit log hash chain is broken — tamper detected or integrity lost.",
            evidence=chain_msg
        ))
    return findings


def rule_002_double_auth(events: list[dict]) -> list[Finding]:
    """Rule 002: Double Authentication (Criterion #2 - Command Vocabulary)
    Two login events for the same credential within 1 second."""
    findings = []
    login_events = [e for e in events if "login" in e["event_type"] and e["timestamp"]]
    for i in range(len(login_events) - 1):
        a, b = login_events[i], login_events[i + 1]
        if a["alias"] == b["alias"]:
            delta = abs((b["timestamp"] - a["timestamp"]).total_seconds())
            if delta < 1.0:
                findings.append(Finding(
                    rule_id="RULE-002",
                    rule_name="Double Authentication",
                    criterion="#2 Command Vocabulary",
                    severity="MEDIUM",
                    description=f"Two logins for '{a['alias']}' within {delta:.2f}s.",
                    evidence=f"{a['event_id']} and {b['event_id']} at {a['timestamp_str']}"
                ))
    return findings


def rule_003_consecutive_failures(events: list[dict], threshold: int = 3) -> list[Finding]:
    """Rule 003: Consecutive Failure Streak (Criterion #2 + #5)"""
    findings = []
    streak_alias = None
    streak_count = 0
    streak_start = None
    streak_type = None

    for e in events:
        if e["status"] == "failure":
            if e["alias"] == streak_alias:
                streak_count += 1
            else:
                if streak_count >= threshold:
                    findings.append(Finding(
                        rule_id="RULE-003",
                        rule_name="Consecutive Failure Streak",
                        criterion="#2 Command Vocabulary + #5 Traversal Anomaly",
                        severity="MEDIUM-HIGH",
                        description=f"{streak_count} consecutive failures for '{streak_alias}' ({streak_type}).",
                        evidence=f"Starting at {streak_start}"
                    ))
                streak_alias = e["alias"]
                streak_count = 1
                streak_start = e["event_id"]
                streak_type = e["event_type"]
        else:
            if streak_count >= threshold:
                findings.append(Finding(
                    rule_id="RULE-003",
                    rule_name="Consecutive Failure Streak",
                    criterion="#2 Command Vocabulary + #5 Traversal Anomaly",
                    severity="MEDIUM-HIGH",
                    description=f"{streak_count} consecutive failures for '{streak_alias}' ({streak_type}).",
                    evidence=f"Starting at {streak_start}"
                ))
            streak_count = 0
            streak_alias = None

    if streak_count >= threshold:
        findings.append(Finding(
            rule_id="RULE-003",
            rule_name="Consecutive Failure Streak",
            criterion="#2 Command Vocabulary + #5 Traversal Anomaly",
            severity="MEDIUM-HIGH",
            description=f"{streak_count} consecutive failures for '{streak_alias}'.",
            evidence=f"Starting at {streak_start}, continues to end of log"
        ))
    return findings


def rule_004_credential_enumeration(events: list[dict], window_seconds: int = 30) -> list[Finding]:
    """Rule 004: Credential Enumeration (Criterion #5 - Traversal Anomaly)
    Multiple distinct credentials accessed within a short window.
    Tightened from 120s to 30s based on real data — agent bursts are ~16s."""
    findings = []
    access_types = {"credential.test", "credential.used", "browser_login.success",
                    "browser_fetch.success", "browser_fetch.failed"}

    access_events = [e for e in events if e["event_type"] in access_types and e["timestamp"]]

    for i, event in enumerate(access_events):
        window_aliases = set()
        window_events = []
        for j in range(i, len(access_events)):
            delta = (access_events[j]["timestamp"] - event["timestamp"]).total_seconds()
            if delta > window_seconds:
                break
            if access_events[j]["alias"] != "*":
                window_aliases.add(access_events[j]["alias"])
            window_events.append(access_events[j]["event_id"])

        if len(window_aliases) >= 3:
            findings.append(Finding(
                rule_id="RULE-004",
                rule_name="Credential Enumeration",
                criterion="#5 Traversal Anomaly",
                severity="MEDIUM",
                description=f"{len(window_aliases)} distinct credentials accessed within {window_seconds}s window.",
                evidence=f"Aliases: {', '.join(sorted(window_aliases))}. Events: {window_events[0]}–{window_events[-1]}"
            ))
            break

    return findings


def rule_005_session_amnesia(events: list[dict]) -> list[Finding]:
    """Rule 005: Session Amnesia (Criterion #2 - Command Vocabulary)
    Repeated login-then-single-fetch cycles instead of reusing sessions."""
    findings = []
    cycles = []
    current_cycle_login = None
    current_cycle_fetches = 0

    for e in events:
        if "login" in e["event_type"] and e["status"] == "success":
            if current_cycle_login and current_cycle_fetches <= 1:
                cycles.append(current_cycle_login)
            current_cycle_login = e
            current_cycle_fetches = 0
        elif "fetch" in e["event_type"]:
            current_cycle_fetches += 1

    if current_cycle_login and current_cycle_fetches <= 1:
        cycles.append(current_cycle_login)

    consecutive_single_cycles = 0
    for i in range(len(cycles) - 1):
        if cycles[i]["alias"] == cycles[i + 1]["alias"]:
            consecutive_single_cycles += 1

    if consecutive_single_cycles >= 2:
        findings.append(Finding(
            rule_id="RULE-005",
            rule_name="Session Amnesia",
            criterion="#2 Command Vocabulary",
            severity="LOW-MEDIUM",
            description=f"{consecutive_single_cycles + 1} consecutive single-fetch login cycles for '{cycles[0]['alias']}'.",
            evidence="Agent repeatedly logs in, fetches once, then logs in again instead of reusing session."
        ))
    return findings


def rule_006_burst_creation(events: list[dict], window_seconds: int = 600, threshold: int = 3) -> list[Finding]:
    """Rule 006: Burst Credential Creation (Criterion #3 - Privilege Pattern)
    Tightened window from 900s to 600s based on real data (580s burst observed)."""
    findings = []
    create_events = [e for e in events if e["event_type"] == "credential.created" and e["timestamp"]]

    if len(create_events) < threshold:
        return findings

    for i, event in enumerate(create_events):
        window_creates = []
        for j in range(i, len(create_events)):
            delta = (create_events[j]["timestamp"] - event["timestamp"]).total_seconds()
            if delta > window_seconds:
                break
            window_creates.append(create_events[j])

        if len(window_creates) >= threshold:
            aliases = [e["alias"] for e in window_creates]
            span = (window_creates[-1]["timestamp"] - window_creates[0]["timestamp"]).total_seconds()
            findings.append(Finding(
                rule_id="RULE-006",
                rule_name="Burst Credential Creation",
                criterion="#3 Privilege Pattern",
                severity="MEDIUM",
                description=f"{len(window_creates)} credentials created within {span:.0f}s.",
                evidence=f"Aliases: {', '.join(aliases)}. {window_creates[0]['event_id']}–{window_creates[-1]['event_id']}"
            ))
            break

    return findings


def rule_007_test_after_create(events: list[dict], gap_seconds: int = 5) -> list[Finding]:
    """Rule 007: Rapid Test After Create (Criterion #5 - Traversal Anomaly)
    Credential tested within seconds of creation — automated probing."""
    findings = []
    create_times = {}
    for e in events:
        if e["event_type"] == "credential.created" and e["timestamp"]:
            create_times[e["alias"]] = e

    for e in events:
        if e["event_type"] == "credential.test" and e["timestamp"]:
            if e["alias"] in create_times:
                create_event = create_times[e["alias"]]
                delta = (e["timestamp"] - create_event["timestamp"]).total_seconds()
                if 0 < delta <= gap_seconds:
                    findings.append(Finding(
                        rule_id="RULE-007",
                        rule_name="Rapid Test After Create",
                        criterion="#5 Traversal Anomaly",
                        severity="LOW",
                        description=f"Credential '{e['alias']}' tested {delta:.0f}s after creation.",
                        evidence=f"Created: {create_event['event_id']}, Tested: {e['event_id']}"
                    ))
    return findings


def rule_008_repeated_listing(events: list[dict], window_seconds: int = 300, threshold: int = 3) -> list[Finding]:
    """Rule 008: Repeated Credential Listing (Criterion #5 - Traversal Anomaly)"""
    findings = []
    list_events = [e for e in events if e["event_type"] == "credential.listed" and e["timestamp"]]

    if len(list_events) < threshold:
        return findings

    for i, event in enumerate(list_events):
        window_lists = []
        for j in range(i, len(list_events)):
            delta = (list_events[j]["timestamp"] - event["timestamp"]).total_seconds()
            if delta > window_seconds:
                break
            window_lists.append(list_events[j])

        if len(window_lists) >= threshold:
            span = (window_lists[-1]["timestamp"] - window_lists[0]["timestamp"]).total_seconds()
            findings.append(Finding(
                rule_id="RULE-008",
                rule_name="Repeated Credential Listing",
                criterion="#5 Traversal Anomaly",
                severity="LOW-MEDIUM",
                description=f"{len(window_lists)} listing operations within {span:.0f}s.",
                evidence=f"{window_lists[0]['event_id']}–{window_lists[-1]['event_id']}"
            ))
            break

    return findings


def rule_009_silent_failure(events: list[dict], expected_tests: list[str] = None) -> list[Finding]:
    """Rule 009: Silent Test Failure (Criterion #1 - Structural Mutation)"""
    findings = []
    if not expected_tests:
        return findings

    tested_aliases = {e["alias"] for e in events if e["event_type"] == "credential.test"}

    for alias in expected_tests:
        if alias not in tested_aliases:
            findings.append(Finding(
                rule_id="RULE-009",
                rule_name="Silent Test Failure",
                criterion="#1 Structural Mutation",
                severity="HIGH",
                description=f"Credential '{alias}' was tested but produced no audit event.",
                evidence="Test was observed externally but not found in audit log. Telemetry gap."
            ))
    return findings


def rule_010_session_gap(events: list[dict]) -> list[Finding]:
    """Rule 010: Session Gap Analysis (Baseline - Informational)"""
    findings = []
    timestamped = [e for e in events if e["timestamp"]]
    if len(timestamped) < 2:
        return findings

    max_gap = 0
    gap_start = None
    gap_end = None

    for i in range(len(timestamped) - 1):
        delta = (timestamped[i + 1]["timestamp"] - timestamped[i]["timestamp"]).total_seconds()
        if delta > max_gap:
            max_gap = delta
            gap_start = timestamped[i]
            gap_end = timestamped[i + 1]

    gap_hours = max_gap / 3600
    if gap_hours > 1:
        findings.append(Finding(
            rule_id="RULE-010",
            rule_name="Session Gap Analysis",
            criterion="Baseline",
            severity="INFO",
            description=f"Largest activity gap: {gap_hours:.1f} hours ({gap_hours/24:.1f} days).",
            evidence=f"Between {gap_start['event_id']} ({gap_start['timestamp_str']}) and {gap_end['event_id']} ({gap_end['timestamp_str']})"
        ))
    return findings


def rule_011_content_volume_spike(events: list[dict], multiplier: float = 100.0) -> list[Finding]:
    """Rule 011: Content Volume Spike (Criterion #3 - Privilege Pattern)
    A fetch returns content dramatically larger than the baseline for that credential.
    NEW in v0.3."""
    findings = []
    fetch_events = [e for e in events if "fetch" in e["event_type"] and e["status"] == "success"]

    # Group by alias
    alias_sizes = defaultdict(list)
    for e in fetch_events:
        size = e.get("details", {}).get("content_length", 0)
        if size > 0:
            alias_sizes[e["alias"]].append((e, size))

    for alias, entries in alias_sizes.items():
        if len(entries) < 2:
            continue
        sizes = [s for _, s in entries]
        median = sorted(sizes)[len(sizes) // 2]
        if median == 0:
            continue

        for event, size in entries:
            ratio = size / median
            if ratio >= multiplier:
                findings.append(Finding(
                    rule_id="RULE-011",
                    rule_name="Content Volume Spike",
                    criterion="#3 Privilege Pattern",
                    severity="MEDIUM",
                    description=f"Fetch for '{alias}' returned {size:,} bytes — {ratio:.0f}x the median ({median:,} bytes).",
                    evidence=f"{event['event_id']} at {event['timestamp_str']}, URL: {event.get('details', {}).get('url', 'unknown')}"
                ))
    return findings


def rule_012_credential_lifecycle(events: list[dict]) -> list[Finding]:
    """Rule 012: Credential Lifecycle Anomaly (Criterion #1 + #3)
    Credential removed and re-created (possible rotation bypass or cover-up).
    NEW in v0.3."""
    findings = []
    removed = {}
    for e in events:
        if e["event_type"] == "credential.removed" and e["timestamp"]:
            removed[e["alias"]] = e

    for e in events:
        if e["event_type"] == "credential.created" and e["timestamp"]:
            if e["alias"] in removed:
                remove_event = removed[e["alias"]]
                # Only flag if re-created AFTER removal
                if e["timestamp"] > remove_event["timestamp"]:
                    delta = (e["timestamp"] - remove_event["timestamp"]).total_seconds()
                    findings.append(Finding(
                        rule_id="RULE-012",
                        rule_name="Credential Lifecycle Anomaly",
                        criterion="#1 Structural Mutation + #3 Privilege Pattern",
                        severity="MEDIUM",
                        description=f"Credential '{e['alias']}' was removed and re-created {delta:.0f}s later.",
                        evidence=f"Removed: {remove_event['event_id']}, Re-created: {e['event_id']}. "
                                 f"Legitimate rotation should use 'coffer rotate', not remove+add."
                    ))
    return findings


def rule_013_auth_status_mismatch(events: list[dict]) -> list[Finding]:
    """Rule 013: Auth Status Mismatch (Criterion #2 - Command Vocabulary)
    Two patterns:
    (a) credential.used with status="success" but HTTP 401/403 — legacy gap before auth_rejected was added
    (b) credential.used with status="auth_rejected" — credential injected, target rejected it
    Updated in v0.4 to handle the auth_rejected status introduced in coffer-mcp."""
    findings = []
    for e in events:
        if e["event_type"] == "credential.used":
            http_status = e.get("details", {}).get("status_code")
            if http_status in (401, 403) and e["status"] == "success":
                findings.append(Finding(
                    rule_id="RULE-013",
                    rule_name="Auth Status Mismatch",
                    criterion="#2 Command Vocabulary",
                    severity="MEDIUM-HIGH",
                    description=f"Credential '{e['alias']}' logged success but server returned {http_status}.",
                    evidence=f"{e['event_id']} — URL: {e.get('details', {}).get('url', 'unknown')}. "
                             f"Credential may be invalid, expired, or revoked at the target."
                ))
            elif e["status"] == "auth_rejected":
                findings.append(Finding(
                    rule_id="RULE-013",
                    rule_name="Auth Rejected by Target",
                    criterion="#2 Command Vocabulary",
                    severity="MEDIUM-HIGH",
                    description=f"Credential '{e['alias']}' was injected but target returned {http_status}.",
                    evidence=f"{e['event_id']} — URL: {e.get('details', {}).get('url', 'unknown')}. "
                             f"Credential was delivered but not accepted by the target server."
                ))
    return findings


def rule_014_access_denied(events: list[dict]) -> list[Finding]:
    """Rule 014: Credential Access Denied / Allowlist Violation (Criterion #5)
    Agent attempted to use a credential against a URL outside its allowlist.
    NEW in v0.4 — discovered during red-team evaluation."""
    findings = []
    denied_events = [e for e in events if e["event_type"] == "credential.access_denied"]
    for e in denied_events:
        url = e.get("details", {}).get("url", "unknown")
        reason = e.get("details", {}).get("reason", "unknown")
        findings.append(Finding(
            rule_id="RULE-014",
            rule_name="Credential Access Denied",
            criterion="#5 Traversal Anomaly",
            severity="HIGH",
            description=f"Credential '{e['alias']}' was used against URL '{url}' — blocked by allowlist ({reason}).",
            evidence=f"{e['event_id']} at {e.get('timestamp_str', 'unknown')}. "
                     f"Agent attempted to use a credential outside its authorized scope."
        ))
    denied_by_alias = defaultdict(list)
    for e in denied_events:
        denied_by_alias[e["alias"]].append(e)
    for alias, events_list in denied_by_alias.items():
        if len(events_list) >= 2:
            findings.append(Finding(
                rule_id="RULE-014",
                rule_name="Repeated Access Denied",
                criterion="#5 Traversal Anomaly",
                severity="CRITICAL",
                description=f"Credential '{alias}' triggered {len(events_list)} allowlist violations — active probing pattern.",
                evidence=f"Events: {', '.join(e['event_id'] for e in events_list)}"
            ))
    return findings


def rule_015_burst_fetch(events: list[dict], window_seconds: int = 120, threshold: int = 4) -> list[Finding]:
    """Rule 015: Burst Fetch / Data Exfiltration Pattern (Criterion #3)
    Rapid sequential content fetches from the same session — smash and grab.
    NEW in v0.4 — discovered during red-team evaluation."""
    findings = []
    fetch_events = [e for e in events
                    if e["event_type"] in ("browser_fetch.success", "browser_fetch.failed")
                    and e["timestamp"]]
    alias_fetches = defaultdict(list)
    for e in fetch_events:
        alias_fetches[e["alias"]].append(e)
    for alias, fetches in alias_fetches.items():
        fetches.sort(key=lambda e: e["timestamp"])
        for i, event in enumerate(fetches):
            window = []
            total_bytes = 0
            for j in range(i, len(fetches)):
                delta = (fetches[j]["timestamp"] - event["timestamp"]).total_seconds()
                if delta > window_seconds:
                    break
                window.append(fetches[j])
                total_bytes += fetches[j].get("details", {}).get("content_length", 0)
            if len(window) >= threshold:
                urls = set(e.get("details", {}).get("url", "") for e in window)
                findings.append(Finding(
                    rule_id="RULE-015",
                    rule_name="Burst Fetch",
                    criterion="#3 Privilege Pattern",
                    severity="MEDIUM-HIGH",
                    description=f"{len(window)} fetches for '{alias}' within {window_seconds}s, "
                                f"totaling {total_bytes:,} bytes across {len(urls)} unique URLs.",
                    evidence=f"{window[0]['event_id']}–{window[-1]['event_id']}. "
                             f"Rapid sequential content retrieval — potential data exfiltration."
                ))
                break
    return findings


def rule_016_multi_credential_use(events: list[dict], window_seconds: int = 60) -> list[Finding]:
    """Rule 016: Multi-Credential Use in Short Window (Criterion #3 + #5)
    Agent uses (not just tests) multiple different credentials in rapid succession.
    NEW in v0.4 — discovered during red-team evaluation."""
    findings = []
    use_events = [e for e in events
                  if e["event_type"] in ("credential.used", "credential.access_denied")
                  and e["timestamp"]]
    for i, event in enumerate(use_events):
        window_aliases = set()
        window_events = []
        for j in range(i, len(use_events)):
            delta = (use_events[j]["timestamp"] - event["timestamp"]).total_seconds()
            if delta > window_seconds:
                break
            window_aliases.add(use_events[j]["alias"])
            window_events.append(use_events[j])
        if len(window_aliases) >= 2:
            findings.append(Finding(
                rule_id="RULE-016",
                rule_name="Multi-Credential Use",
                criterion="#3 Privilege Pattern + #5 Traversal Anomaly",
                severity="HIGH",
                description=f"{len(window_aliases)} distinct credentials used within {window_seconds}s.",
                evidence=f"Aliases: {', '.join(sorted(window_aliases))}. "
                         f"Events: {window_events[0]['event_id']}–{window_events[-1]['event_id']}. "
                         f"Agent is actively using multiple credentials in rapid succession."
            ))
            break
    return findings


def rule_017_missing_reason(events: list[dict]) -> list[Finding]:
    """Rule 017: Missing Reason on Credential Access (Layer 2 - Context Binding)
    credential.used or credential.test events where the agent did not provide
    a reason for accessing the credential. Absence of justification is the signal.
    NEW in v0.4 — first Layer 2 detection rule."""
    findings = []
    reason_events = [e for e in events
                     if e["event_type"] in ("credential.used", "credential.test")]
    # Error-style reason values are short snake_case codes from the system,
    # not Layer 2 task context from the agent. Filter them out.
    error_reason_patterns = {
        "invalid_oauth2_format", "credential_not_found", "url_not_allowed",
        "method_not_allowed", "credential_expired", "no_allowed_urls",
        "wrong_type", "token_url_not_allowed", "invalid_http_method",
    }
    missing = []
    present = []
    for e in reason_events:
        reason = e.get("details", {}).get("reason", "")
        if not reason or not reason.strip() or reason in error_reason_patterns:
            missing.append(e)
        else:
            present.append(e)

    if missing and present:
        # Mixed — some events have reasons, some don't. The missing ones are suspicious.
        for e in missing:
            findings.append(Finding(
                rule_id="RULE-017",
                rule_name="Missing Reason (Mixed)",
                criterion="Layer 2 Context Binding",
                severity="MEDIUM",
                description=f"Credential '{e['alias']}' accessed without a stated reason, "
                            f"but other credential accesses in this session include reasons.",
                evidence=f"{e['event_id']} — {e['event_type']}. "
                         f"{len(present)} events have reasons, {len(missing)} do not. "
                         f"Inconsistent reason usage suggests the missing ones may lack upstream justification."
            ))
    elif missing and not present:
        # All events lack reasons — might be pre-Layer-2 data or agent doesn't support it yet.
        # Lower severity, informational.
        if len(missing) >= 3:
            findings.append(Finding(
                rule_id="RULE-017",
                rule_name="Missing Reason (All)",
                criterion="Layer 2 Context Binding",
                severity="LOW",
                description=f"None of the {len(missing)} credential access events include a stated reason.",
                evidence=f"Events: {missing[0]['event_id']}–{missing[-1]['event_id']}. "
                         f"This may indicate pre-Layer-2 telemetry or an agent that does not "
                         f"support the reason parameter."
            ))
    return findings


# ---------------------------------------------------------------------------
# Run all rules
# ---------------------------------------------------------------------------

def run_detection(events: list[dict], chain_msg: str | None,
                  expected_tests: list[str] = None) -> list[Finding]:
    """Run all detection rules against the event set."""
    findings = []
    findings.extend(rule_001_integrity_chain(events, chain_msg))
    findings.extend(rule_002_double_auth(events))
    findings.extend(rule_003_consecutive_failures(events))
    findings.extend(rule_004_credential_enumeration(events))
    findings.extend(rule_005_session_amnesia(events))
    findings.extend(rule_006_burst_creation(events))
    findings.extend(rule_007_test_after_create(events))
    findings.extend(rule_008_repeated_listing(events))
    findings.extend(rule_009_silent_failure(events, expected_tests))
    findings.extend(rule_010_session_gap(events))
    findings.extend(rule_011_content_volume_spike(events))
    findings.extend(rule_012_credential_lifecycle(events))
    findings.extend(rule_013_auth_status_mismatch(events))
    findings.extend(rule_014_access_denied(events))
    findings.extend(rule_015_burst_fetch(events))
    findings.extend(rule_016_multi_credential_use(events))
    findings.extend(rule_017_missing_reason(events))
    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(findings: list[Finding], events: list[dict]) -> str:
    total_events = len(events)
    unique_aliases = len(set(e["alias"] for e in events if e["alias"] != "*"))
    event_types = sorted(set(e["event_type"] for e in events))
    failures = len([e for e in events if e["status"] == "failure"])

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM-HIGH": 2, "MEDIUM": 3,
                      "LOW-MEDIUM": 4, "LOW": 5, "INFO": 6}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    lines = []
    lines.append("# Coffer Detection Report v0.3")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Events analyzed:** {total_events}")
    lines.append(f"**Unique credentials:** {unique_aliases}")
    lines.append(f"**Event types:** {', '.join(event_types)}")
    lines.append(f"**Failures:** {failures}")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")

    # Time span
    timestamped = [e for e in events if e["timestamp"]]
    if len(timestamped) >= 2:
        first = timestamped[0]["timestamp_str"]
        last = timestamped[-1]["timestamp_str"]
        span_hours = (timestamped[-1]["timestamp"] - timestamped[0]["timestamp"]).total_seconds() / 3600
        lines.append(f"**Time span:** {first} to {last} ({span_hours:.1f} hours / {span_hours/24:.1f} days)")
        lines.append("")

    # Severity summary
    severity_counts = defaultdict(int)
    for f in findings:
        severity_counts[f.severity] += 1

    lines.append("## Severity Summary")
    lines.append("")
    for sev in ["CRITICAL", "HIGH", "MEDIUM-HIGH", "MEDIUM", "LOW-MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            lines.append(f"- **{sev}:** {severity_counts[sev]}")
    lines.append("")

    # Credential coverage
    lines.append("## Credential Coverage")
    lines.append("")
    alias_events = defaultdict(list)
    for e in events:
        display_alias = e["alias"] if e["alias"] != "*" else "(all)"
        alias_events[display_alias].append(e)

    for alias in sorted(alias_events.keys()):
        evts = alias_events[alias]
        types = sorted(set(e["event_type"] for e in evts))
        lines.append(f"- **{alias}**: {len(evts)} events — {', '.join(types)}")
    lines.append("")

    # Findings detail
    lines.append("## Findings")
    lines.append("")
    for f in findings:
        lines.append(f"### {f.rule_id}: {f.rule_name}")
        lines.append(f"- **Severity:** {f.severity}")
        lines.append(f"- **Criterion:** {f.criterion}")
        lines.append(f"- **Description:** {f.description}")
        lines.append(f"- **Evidence:** {f.evidence}")
        lines.append("")

    # Rules that did NOT fire
    all_rule_ids = {f"RULE-{i:03d}" for i in range(1, 18)}
    fired_rules = {f.rule_id for f in findings}
    silent_rules = sorted(all_rule_ids - fired_rules)

    if silent_rules:
        lines.append("## Rules That Did Not Fire")
        lines.append("")
        for rule_id in silent_rules:
            lines.append(f"- {rule_id}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main — embedded data from full 46-event audit log
# ---------------------------------------------------------------------------

EMBEDDED_DATA = {
  "chain_integrity": "Chain broken at entry 1: hash mismatch (tampered)",
  "events": [
    {"event_id": "evt_000001", "event_type": "credential.created", "alias": "onetrust-blog", "status": "success", "details": {"auth_type": "web_login"}, "timestamp": 1773865654.1565032},
    {"event_id": "evt_000002", "event_type": "credential.listed", "alias": "*", "status": "success", "details": {"count": 1}, "timestamp": 1773866634.2255926},
    {"event_id": "evt_000003", "event_type": "credential.listed", "alias": "*", "status": "success", "details": {"count": 1}, "timestamp": 1773866744.78049},
    {"event_id": "evt_000004", "event_type": "credential.listed", "alias": "*", "status": "success", "details": {"count": 1}, "timestamp": 1773866772.5682113},
    {"event_id": "evt_000005", "event_type": "credential.listed", "alias": "*", "status": "success", "details": {"count": 1}, "timestamp": 1773867891.9449205},
    {"event_id": "evt_000006", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {"login_url": "https://my.onetrust.com/login", "page_title": "MyOneTrust Home"}, "timestamp": 1773867926.564872},
    {"event_id": "evt_000007", "event_type": "browser_fetch.failed", "alias": "onetrust-blog", "status": "failure", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "error": "Timeout 30000ms exceeded"}, "timestamp": 1773868093.9999335},
    {"event_id": "evt_000008", "event_type": "browser_fetch.failed", "alias": "onetrust-blog", "status": "failure", "details": {"url": "https://my.onetrust.com/s/knowledge", "error": "Timeout 30000ms exceeded"}, "timestamp": 1773868129.256514},
    {"event_id": "evt_000009", "event_type": "browser_fetch.failed", "alias": "onetrust-blog", "status": "failure", "details": {"url": "https://my.onetrust.com/s/", "error": "Timeout 30000ms exceeded"}, "timestamp": 1773868165.685182},
    {"event_id": "evt_000010", "event_type": "browser_fetch.failed", "alias": "onetrust-blog", "status": "failure", "details": {"url": "https://my.onetrust.com", "error": "Timeout 30000ms exceeded"}, "timestamp": 1773868202.2621136},
    {"event_id": "evt_000011", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {"login_url": "https://my.onetrust.com/login", "page_title": "MyOneTrust Home"}, "timestamp": 1773871569.3110948},
    {"event_id": "evt_000012", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {"login_url": "https://my.onetrust.com/login", "page_title": "MyOneTrust Home"}, "timestamp": 1773871569.3968654},
    {"event_id": "evt_000013", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "title": "MyOneTrust | Cookie Consent Articles", "content_length": 476}, "timestamp": 1773871608.7104201},
    {"event_id": "evt_000014", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "title": "MyOneTrust | Cookie Consent Articles", "content_length": 1369146}, "timestamp": 1773871633.3555317},
    {"event_id": "evt_000015", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {}, "timestamp": 1773871825.5282824},
    {"event_id": "evt_000016", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "content_length": 476}, "timestamp": 1773871842.7986736},
    {"event_id": "evt_000017", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {}, "timestamp": 1773872031.9224255},
    {"event_id": "evt_000018", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "content_length": 476}, "timestamp": 1773872045.5733438},
    {"event_id": "evt_000019", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {}, "timestamp": 1773872189.8333936},
    {"event_id": "evt_000020", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "content_length": 7338}, "timestamp": 1773872203.5586762},
    {"event_id": "evt_000021", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {}, "timestamp": 1773872819.333205},
    {"event_id": "evt_000022", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/blog", "content_length": 1379607}, "timestamp": 1773872834.4237351},
    {"event_id": "evt_000023", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/article/Cookie-Consent-Overview", "title": "Error", "content_length": 2860}, "timestamp": 1773872898.510661},
    {"event_id": "evt_000024", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {}, "timestamp": 1773875198.2293203},
    {"event_id": "evt_000025", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/knowledge", "content_length": 2321}, "timestamp": 1773875454.834722},
    {"event_id": "evt_000026", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topiccatalog", "content_length": 2321}, "timestamp": 1773875454.9394236},
    {"event_id": "evt_000027", "event_type": "credential.created", "alias": "stripe-test", "status": "success", "details": {"auth_type": "bearer_token"}, "timestamp": 1775048512.525338},
    {"event_id": "evt_000028", "event_type": "credential.created", "alias": "confluence-wiki", "status": "success", "details": {"auth_type": "web_login"}, "timestamp": 1775048606.4949045},
    {"event_id": "evt_000029", "event_type": "credential.created", "alias": "aws-dev", "status": "success", "details": {"auth_type": "basic_auth"}, "timestamp": 1775048667.5740778},
    {"event_id": "evt_000030", "event_type": "credential.created", "alias": "github-pat", "status": "success", "details": {"auth_type": "api_key_header"}, "timestamp": 1775048997.117588},
    {"event_id": "evt_000031", "event_type": "credential.created", "alias": "snowflake-analytics", "status": "success", "details": {"auth_type": "oauth2_client_credentials"}, "timestamp": 1775049092.4906816},
    {"event_id": "evt_000032", "event_type": "credential.test", "alias": "stripe-test", "status": "failure", "details": {"error": "Request URL is missing an 'http://' or 'https://' protocol.", "latency_ms": 301}, "timestamp": 1775050159.3548443},
    {"event_id": "evt_000033", "event_type": "credential.test", "alias": "aws-dev", "status": "success", "details": {"status_code": 302, "latency_ms": 402}, "timestamp": 1775050169.0197635},
    {"event_id": "evt_000034", "event_type": "credential.test", "alias": "github-pat", "status": "success", "details": {"status_code": 200, "latency_ms": 438}, "timestamp": 1775050175.3116617},
    {"event_id": "evt_000035", "event_type": "credential.test", "alias": "snowflake-analytics", "status": "failure", "details": {"reason": "invalid_oauth2_format"}, "timestamp": 1775051460.3542635},
    {"event_id": "evt_000036", "event_type": "credential.test", "alias": "github-pat", "status": "success", "details": {"status_code": 200, "latency_ms": 512}, "timestamp": 1775051654.8808687},
    {"event_id": "evt_000037", "event_type": "credential.test", "alias": "aws-dev", "status": "success", "details": {"status_code": 302, "latency_ms": 210}, "timestamp": 1775051659.378378},
    {"event_id": "evt_000038", "event_type": "credential.test", "alias": "stripe-test", "status": "failure", "details": {"error": "Request URL is missing an 'http://' or 'https://' protocol.", "latency_ms": 9}, "timestamp": 1775051665.844631},
    {"event_id": "evt_000039", "event_type": "credential.used", "alias": "github-pat", "status": "success", "details": {"url": "https://api.github.com/user", "method": "GET", "status_code": 401}, "timestamp": 1775051860.8719466},
    {"event_id": "evt_000040", "event_type": "credential.removed", "alias": "stripe-test", "status": "success", "details": {}, "timestamp": 1775052180.92625},
    {"event_id": "evt_000041", "event_type": "credential.created", "alias": "stripe-test", "status": "success", "details": {"auth_type": "bearer_token"}, "timestamp": 1775052213.6787384},
    {"event_id": "evt_000042", "event_type": "credential.test", "alias": "stripe-test", "status": "failure", "details": {"status_code": 404, "latency_ms": 205}, "timestamp": 1775052227.4781706},
    {"event_id": "evt_000043", "event_type": "browser_login.success", "alias": "onetrust-blog", "status": "success", "details": {"login_url": "https://my.onetrust.com/s/login/"}, "timestamp": 1775052337.384807},
    {"event_id": "evt_000044", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/topic/0TO1Q000000ItRyWAK/trust-intelligence", "content_length": 6849}, "timestamp": 1775052357.0759995},
    {"event_id": "evt_000045", "event_type": "browser_fetch.success", "alias": "onetrust-blog", "status": "success", "details": {"url": "https://my.onetrust.com/s/article/UUID-baa0cebd-79ba-4194-8ad3-5c7d4e9aa7b0", "title": "Error", "content_length": 2371}, "timestamp": 1775052386.6234217},
    {"event_id": "evt_000046", "event_type": "credential.test", "alias": "stripe-test", "status": "failure", "details": {"status_code": 404, "latency_ms": 259}, "timestamp": 1775052931.5755165},
    {"event_id": "evt_000047", "event_type": "credential.test", "alias": "github-pat", "status": "success", "details": {"status_code": 200, "latency_ms": 197}, "timestamp": 1775052940.5125887},
    {"event_id": "evt_000048", "event_type": "credential.test", "alias": "stripe-test", "status": "failure", "details": {"status_code": 404, "latency_ms": 1422}, "timestamp": 1775053040.6504867},
  ]
}


def main():
    if len(sys.argv) > 1 and sys.argv[1] != "--embedded":
        input_path = Path(sys.argv[1])
        data = json.loads(input_path.read_text())
    else:
        data = EMBEDDED_DATA

    events = parse_events_from_json(data)
    chain_msg = get_chain_integrity(data)

    findings = run_detection(events, chain_msg)
    report = generate_report(findings, events)
    print(report)


if __name__ == "__main__":
    main()
