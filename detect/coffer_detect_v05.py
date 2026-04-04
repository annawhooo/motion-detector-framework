#!/usr/bin/env python3
"""coffer-detect v0.5 — Motion Detector Framework detection rules.

Implements 17 detection rules against coffer-mcp audit telemetry.
Handles schema transition: reason / stated_reason / agent_reason fields.
"""

import json
import sys
from collections import defaultdict
from datetime import datetime


def load_events(data):
    """Load events from audit data, sorted chronologically."""
    events = data.get("events", [])
    # Sort by timestamp ascending (oldest first)
    events.sort(key=lambda e: e["timestamp"])
    return events


def get_agent_reason(event):
    """Extract agent's stated reason, handling schema transition.

    Schema versions:
    - Pre-v0.5: 'reason' in credential.used/test, 'stated_reason' in access_denied
    - v0.5+: 'agent_reason' everywhere
    - System reasons: 'reason' in access_denied (e.g., 'url_not_allowed'),
                      'reason' in credential.test failure (e.g., 'credential_expired')
    """
    details = event.get("details", {})

    # v0.5+ schema
    if "agent_reason" in details:
        return details["agent_reason"]

    # Pre-v0.5 access_denied: agent reason is in 'stated_reason'
    if event.get("event_type") == "credential.access_denied":
        return details.get("stated_reason", "")

    # Pre-v0.5 credential.test failure: 'reason' is the system reason, not agent
    if event.get("event_type") == "credential.test" and event.get("status") == "failure":
        # Check if this is a system reason like 'credential_expired' or 'invalid_oauth2_format'
        reason = details.get("reason", "")
        if reason in ("credential_expired", "invalid_oauth2_format"):
            return ""  # System reason, not agent reason
        return reason

    # Pre-v0.5 credential.used/test: 'reason' is the agent's reason
    return details.get("reason", "")


def ts_to_str(ts):
    """Convert timestamp to readable string."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def rule_001_integrity_chain(data, events):
    """Rule 001: Integrity Chain Violation. Criterion #1."""
    findings = []
    if not data.get("chain_valid", True):
        findings.append({
            "rule": "RULE-001",
            "severity": "CRITICAL",
            "criterion": "#1 Structural Mutation",
            "description": f"Audit log integrity chain is broken: {data.get('chain_integrity', 'unknown')}",
            "events": []
        })

    # Also check for duplicate event IDs
    id_counts = defaultdict(list)
    for e in events:
        id_counts[e["event_id"]].append(e)

    for eid, dupes in id_counts.items():
        if len(dupes) > 1:
            findings.append({
                "rule": "RULE-001",
                "severity": "HIGH",
                "criterion": "#1 Structural Mutation",
                "description": f"Duplicate event ID {eid}: appears {len(dupes)} times with different content",
                "events": [d["event_id"] for d in dupes]
            })

    return findings


def rule_002_double_auth(events):
    """Rule 002: Double Authentication. Criterion #2."""
    findings = []
    login_events = [e for e in events if e["event_type"] == "browser_login.success"]

    for i in range(len(login_events) - 1):
        curr = login_events[i]
        nxt = login_events[i + 1]
        if curr["alias"] == nxt["alias"]:
            gap = nxt["timestamp"] - curr["timestamp"]
            if gap < 1.0:
                findings.append({
                    "rule": "RULE-002",
                    "severity": "MEDIUM",
                    "criterion": "#2 Command Vocabulary",
                    "description": f"Double login for '{curr['alias']}' within {gap:.2f}s",
                    "events": [curr["event_id"], nxt["event_id"]]
                })
    return findings


def rule_003_consecutive_failures(events):
    """Rule 003: Consecutive Failure Streak. Criterion #2 + #5.

    v0.5 refinement: Time-windowed streaks. Consecutive failures within 300s
    are "burst" (probing, MEDIUM-HIGH). Failures spread over longer periods
    are "chronic" (misconfiguration, LOW-MEDIUM).
    """
    BURST_WINDOW = 300  # seconds
    findings = []
    alias_events = defaultdict(list)
    for e in events:
        if e.get("alias") and e["alias"] != "*":
            alias_events[e["alias"]].append(e)

    for alias, evts in alias_events.items():
        streak = 0
        streak_start_ts = None
        streak_events = []
        for e in evts:
            if e["status"] in ("failure", "auth_rejected"):
                if streak == 0:
                    streak_start_ts = e["timestamp"]
                streak += 1
                streak_events.append(e)
            else:
                if streak >= 3:
                    span = streak_events[-1]["timestamp"] - streak_start_ts
                    is_burst = span <= BURST_WINDOW
                    severity = "MEDIUM-HIGH" if is_burst else "LOW-MEDIUM"
                    label = "burst" if is_burst else "chronic"
                    findings.append({
                        "rule": "RULE-003",
                        "severity": severity,
                        "criterion": "#2 + #5",
                        "description": f"{streak} consecutive failures for '{alias}' ({label}: {span:.0f}s span)",
                        "events": [e["event_id"] for e in streak_events]
                    })
                streak = 0
                streak_events = []
        if streak >= 3:
            span = streak_events[-1]["timestamp"] - streak_start_ts
            is_burst = span <= BURST_WINDOW
            severity = "MEDIUM-HIGH" if is_burst else "LOW-MEDIUM"
            label = "burst" if is_burst else "chronic"
            findings.append({
                "rule": "RULE-003",
                "severity": severity,
                "criterion": "#2 + #5",
                "description": f"{streak} consecutive failures for '{alias}' ({label}: {span:.0f}s span)",
                "events": [e["event_id"] for e in streak_events]
            })
    return findings


def rule_004_credential_enumeration(events):
    """Rule 004: Credential Enumeration. Criterion #5."""
    findings = []
    # Look for 3+ distinct credentials accessed within 30s window
    access_events = [e for e in events if e["event_type"] in (
        "credential.used", "credential.test", "credential.access_denied"
    )]

    for i, e in enumerate(access_events):
        window_aliases = set()
        window_events = []
        for j in range(i, len(access_events)):
            if access_events[j]["timestamp"] - e["timestamp"] <= 30:
                window_aliases.add(access_events[j]["alias"])
                window_events.append(access_events[j]["event_id"])
            else:
                break
        if len(window_aliases) >= 3:
            findings.append({
                "rule": "RULE-004",
                "severity": "MEDIUM",
                "criterion": "#5 Traversal Anomaly",
                "description": f"{len(window_aliases)} distinct credentials accessed in {access_events[min(i+len(window_events)-1, len(access_events)-1)]['timestamp'] - e['timestamp']:.1f}s: {', '.join(sorted(window_aliases))}",
                "events": window_events
            })
            break  # Avoid duplicate findings for overlapping windows

    return findings


def rule_005_session_amnesia(events):
    """Rule 005: Session Amnesia. Criterion #2.

    v0.5 fix: Rewritten to detect login-then-single-fetch cycles per alias.
    A cycle is: login event followed by exactly one fetch, then another login
    (instead of reusing the session for multiple fetches). Counts total cycles
    per alias rather than requiring perfect consecutive ordering.
    """
    findings = []
    # Filter to web events only, group by alias
    web_events = [e for e in events if e["event_type"] in (
        "browser_login.success", "browser_fetch.success", "browser_fetch.failed"
    )]

    if len(web_events) < 2:
        return findings

    # Walk through and identify login→single-fetch→login patterns
    alias_cycles = defaultdict(list)
    i = 0
    while i < len(web_events) - 1:
        curr = web_events[i]
        nxt = web_events[i + 1]

        if curr["event_type"] == "browser_login.success":
            if nxt["event_type"] in ("browser_fetch.success", "browser_fetch.failed"):
                # Count how many fetches follow this login
                fetch_count = 0
                j = i + 1
                while j < len(web_events) and web_events[j]["event_type"] in (
                    "browser_fetch.success", "browser_fetch.failed"
                ):
                    fetch_count += 1
                    j += 1

                if fetch_count == 1:
                    # Single fetch after login = session amnesia cycle
                    alias = curr["alias"]
                    alias_cycles[alias].append((curr, nxt))
                    i = j  # Skip past the fetch
                    continue
        i += 1

    for alias, cycles in alias_cycles.items():
        if len(cycles) >= 3:
            cycle_events = []
            for login, fetch in cycles:
                cycle_events.extend([login["event_id"], fetch["event_id"]])
            findings.append({
                "rule": "RULE-005",
                "severity": "LOW-MEDIUM",
                "criterion": "#2 Command Vocabulary",
                "description": f"{len(cycles)} login-then-single-fetch cycles for '{alias}' (session not reused)",
                "events": cycle_events
            })

    return findings


def rule_006_burst_creation(events):
    """Rule 006: Burst Credential Creation. Criterion #3."""
    findings = []
    create_events = [e for e in events if e["event_type"] == "credential.created"]

    for i, e in enumerate(create_events):
        window = [e]
        for j in range(i + 1, len(create_events)):
            if create_events[j]["timestamp"] - e["timestamp"] <= 600:
                window.append(create_events[j])
            else:
                break
        if len(window) >= 3:
            span = window[-1]["timestamp"] - window[0]["timestamp"]
            aliases = [w["alias"] for w in window]
            findings.append({
                "rule": "RULE-006",
                "severity": "MEDIUM",
                "criterion": "#3 Privilege Pattern",
                "description": f"{len(window)} credentials created in {span:.0f}s: {', '.join(aliases)}",
                "events": [w["event_id"] for w in window]
            })
            break  # Avoid overlapping

    return findings


def rule_007_rapid_test_after_create(events):
    """Rule 007: Rapid Test After Create. Criterion #5."""
    findings = []
    for e in events:
        if e["event_type"] == "credential.created":
            alias = e["alias"]
            create_ts = e["timestamp"]
            # Look for test within 5s
            for e2 in events:
                if (e2["event_type"] == "credential.test" and
                    e2["alias"] == alias and
                    0 < e2["timestamp"] - create_ts <= 5):
                    findings.append({
                        "rule": "RULE-007",
                        "severity": "LOW",
                        "criterion": "#5 Traversal Anomaly",
                        "description": f"'{alias}' tested {e2['timestamp'] - create_ts:.1f}s after creation",
                        "events": [e["event_id"], e2["event_id"]]
                    })
    return findings


def rule_008_repeated_listing(events):
    """Rule 008: Repeated Credential Listing. Criterion #5."""
    findings = []
    list_events = [e for e in events if e["event_type"] == "credential.listed"]

    for i, e in enumerate(list_events):
        window = [e]
        for j in range(i + 1, len(list_events)):
            if list_events[j]["timestamp"] - e["timestamp"] <= 300:
                window.append(list_events[j])
            else:
                break
        if len(window) >= 3:
            span = window[-1]["timestamp"] - window[0]["timestamp"]
            findings.append({
                "rule": "RULE-008",
                "severity": "LOW-MEDIUM",
                "criterion": "#5 Traversal Anomaly",
                "description": f"{len(window)} credential listings in {span:.0f}s",
                "events": [w["event_id"] for w in window]
            })
            break

    return findings


def rule_010_session_gap(events):
    """Rule 010: Session Gap Analysis. Criterion: Baseline. INFO level."""
    findings = []
    if len(events) < 2:
        return findings

    max_gap = 0
    gap_after = None
    for i in range(len(events) - 1):
        gap = events[i + 1]["timestamp"] - events[i]["timestamp"]
        if gap > max_gap:
            max_gap = gap
            gap_after = events[i]

    if max_gap > 0:
        days = max_gap / 86400
        findings.append({
            "rule": "RULE-010",
            "severity": "INFO",
            "criterion": "Baseline",
            "description": f"Largest session gap: {days:.1f} days (after {gap_after['event_id']} at {ts_to_str(gap_after['timestamp'])})",
            "events": [gap_after["event_id"]]
        })

    return findings


def rule_011_content_volume_spike(events):
    """Rule 011: Content Volume Spike. Criterion #3."""
    findings = []
    # Group fetches by alias, compute median, flag 100x+
    alias_fetches = defaultdict(list)
    for e in events:
        if e["event_type"] in ("browser_fetch.success",) and "content_length" in e.get("details", {}):
            alias_fetches[e["alias"]].append(e)

    for alias, fetches in alias_fetches.items():
        sizes = sorted([f["details"]["content_length"] for f in fetches])
        if len(sizes) < 2:
            continue
        median = sizes[len(sizes) // 2]
        if median == 0:
            continue
        for f in fetches:
            ratio = f["details"]["content_length"] / median
            if ratio >= 100:
                findings.append({
                    "rule": "RULE-011",
                    "severity": "MEDIUM",
                    "criterion": "#3 Privilege Pattern",
                    "description": f"Content volume spike for '{alias}': {f['details']['content_length']:,} bytes ({ratio:.0f}x median of {median:,})",
                    "events": [f["event_id"]]
                })

    return findings


def rule_012_credential_lifecycle(events):
    """Rule 012: Credential Lifecycle Anomaly. Criterion #1 + #3."""
    findings = []
    # Look for remove followed by create of same alias
    for i, e in enumerate(events):
        if e["event_type"] == "credential.removed":
            alias = e["alias"]
            for j in range(i + 1, len(events)):
                if (events[j]["event_type"] == "credential.created" and
                    events[j]["alias"] == alias):
                    gap = events[j]["timestamp"] - e["timestamp"]
                    findings.append({
                        "rule": "RULE-012",
                        "severity": "MEDIUM",
                        "criterion": "#1 + #3",
                        "description": f"'{alias}' removed and re-created {gap:.0f}s later (possible rotation bypass)",
                        "events": [e["event_id"], events[j]["event_id"]]
                    })
                    break
    return findings


def is_test_credential(alias):
    """Check if a credential alias indicates a test/dummy credential."""
    return alias.startswith("test-") or alias.endswith("-test") or "-dummy" in alias


def is_post_fix_event(event):
    """Check if an event was generated after the v0.5 schema fix.

    Post-fix events have a 'source' field. Pre-fix events don't.
    """
    return "source" in event


def rule_013_auth_status_mismatch(events):
    """Rule 013: Auth Status Mismatch. Criterion #2.

    v0.5 refinement: Downgrades severity for known-dummy credentials.
    Dummy creds are expected to get auth_rejected from real endpoints.
    Real creds getting auth_rejected is a genuine signal.
    """
    findings = []
    for e in events:
        alias = e.get("alias", "")
        is_dummy = is_test_credential(alias)

        # Legacy pattern: status "success" but HTTP 401/403
        if (e["event_type"] == "credential.used" and
            e["status"] == "success" and
            e.get("details", {}).get("status_code") in (401, 403)):
            severity = "LOW" if is_dummy else "MEDIUM-HIGH"
            findings.append({
                "rule": "RULE-013",
                "severity": severity,
                "criterion": "#2 Command Vocabulary",
                "description": f"Auth mismatch for '{alias}': vault reports success but HTTP {e['details']['status_code']}" + (" [dummy cred]" if is_dummy else ""),
                "events": [e["event_id"]]
            })
        # New pattern: auth_rejected status
        elif (e["event_type"] in ("credential.used", "credential.test") and
              e["status"] == "auth_rejected"):
            severity = "LOW" if is_dummy else "MEDIUM-HIGH"
            findings.append({
                "rule": "RULE-013",
                "severity": severity,
                "criterion": "#2 Command Vocabulary",
                "description": f"Auth rejected for '{alias}': credential injected but target returned {e.get('details', {}).get('status_code', 'N/A')}" + (" [dummy cred]" if is_dummy else ""),
                "events": [e["event_id"]]
            })
    return findings


def rule_014_credential_access_denied(events):
    """Rule 014: Credential Access Denied. Criterion #5."""
    findings = []
    denied_counts = defaultdict(int)

    for e in events:
        if e["event_type"] == "credential.access_denied":
            alias = e["alias"]
            url = e.get("details", {}).get("url", "unknown")
            denied_counts[alias] += 1
            severity = "CRITICAL" if denied_counts[alias] >= 3 else "HIGH"
            findings.append({
                "rule": "RULE-014",
                "severity": severity,
                "criterion": "#5 Traversal Anomaly",
                "description": f"Access denied for '{alias}' against {url} (blocked by allowlist). Violation #{denied_counts[alias]} for this credential.",
                "events": [e["event_id"]]
            })
    return findings


def rule_015_burst_fetch(events):
    """Rule 015: Burst Fetch. Criterion #3."""
    findings = []
    fetch_events = [e for e in events if e["event_type"] in (
        "browser_fetch.success", "credential.used"
    ) and e.get("details", {}).get("url")]

    # Group by alias
    alias_fetches = defaultdict(list)
    for e in fetch_events:
        alias_fetches[e["alias"]].append(e)

    for alias, fetches in alias_fetches.items():
        for i, e in enumerate(fetches):
            window = [e]
            for j in range(i + 1, len(fetches)):
                if fetches[j]["timestamp"] - e["timestamp"] <= 120:
                    window.append(fetches[j])
                else:
                    break
            if len(window) >= 4:
                span = window[-1]["timestamp"] - window[0]["timestamp"]
                urls = set(w.get("details", {}).get("url", "") for w in window)
                findings.append({
                    "rule": "RULE-015",
                    "severity": "MEDIUM-HIGH",
                    "criterion": "#3 Privilege Pattern",
                    "description": f"Burst fetch for '{alias}': {len(window)} fetches in {span:.0f}s across {len(urls)} unique URLs",
                    "events": [w["event_id"] for w in window]
                })
                break

    return findings


def rule_016_multi_credential_use(events):
    """Rule 016: Multi-Credential Use. Criterion #3 + #5."""
    findings = []
    use_events = [e for e in events if e["event_type"] in (
        "credential.used",
    ) and e.get("alias")]

    for i, e in enumerate(use_events):
        window_aliases = set()
        window_events = []
        for j in range(i, len(use_events)):
            if use_events[j]["timestamp"] - e["timestamp"] <= 60:
                window_aliases.add(use_events[j]["alias"])
                window_events.append(use_events[j])
            else:
                break
        if len(window_aliases) >= 2:
            span = window_events[-1]["timestamp"] - window_events[0]["timestamp"]
            findings.append({
                "rule": "RULE-016",
                "severity": "HIGH",
                "criterion": "#3 + #5",
                "description": f"Multi-credential use: {len(window_aliases)} credentials used in {span:.0f}s: {', '.join(sorted(window_aliases))}",
                "events": [w["event_id"] for w in window_events]
            })
            break

    return findings


def rule_017_missing_reason(events):
    """Rule 017: Missing Reason. Layer 2 Context Binding.

    v0.5 refinement: Recency-weighted. Post-fix events (with 'source' field)
    that are missing reasons are more suspicious than pre-fix events (which
    predate the reason feature). Reports both categories separately.
    """
    findings = []
    reason_events = [e for e in events if e["event_type"] in (
        "credential.used", "credential.test", "credential.access_denied",
        "browser_fetch.success", "browser_fetch.failed"
    )]

    has_reason = []
    missing_pre_fix = []   # Missing reason, pre-fix (no 'source' field)
    missing_post_fix = []  # Missing reason, post-fix (has 'source' field)

    for e in reason_events:
        agent_reason = get_agent_reason(e)
        if agent_reason:
            has_reason.append(e)
        elif is_post_fix_event(e):
            missing_post_fix.append(e)
        else:
            missing_pre_fix.append(e)

    # Post-fix events missing reasons are the most suspicious
    if missing_post_fix:
        findings.append({
            "rule": "RULE-017",
            "severity": "MEDIUM-HIGH",
            "criterion": "Layer 2 Context Binding",
            "description": f"Missing Reason (Post-fix): {len(missing_post_fix)} credential access events from MCP (post-v0.5) lack agent_reason. The reason field was available but not provided.",
            "events": [e["event_id"] for e in missing_post_fix[:10]]
        })

    # Pre-fix events missing reasons — expected but tracked
    if missing_pre_fix and has_reason:
        findings.append({
            "rule": "RULE-017",
            "severity": "LOW",
            "criterion": "Layer 2 Context Binding",
            "description": f"Missing Reason (Pre-fix): {len(missing_pre_fix)} credential access events predate the reason field. Informational — not suspicious, but these events lack Layer 2 context.",
            "events": [e["event_id"] for e in missing_pre_fix[:10]]
        })
    elif missing_pre_fix and not has_reason:
        findings.append({
            "rule": "RULE-017",
            "severity": "INFO",
            "criterion": "Layer 2 Context Binding",
            "description": f"Missing Reason (All Pre-fix): All {len(missing_pre_fix)} credential access events predate the reason field. Pre-Layer-2 telemetry.",
            "events": [e["event_id"] for e in missing_pre_fix[:10]]
        })

    return findings


def run_all_rules(data):
    """Run all 17 rules and return findings."""
    events = load_events(data)

    all_findings = []
    all_findings.extend(rule_001_integrity_chain(data, events))
    all_findings.extend(rule_002_double_auth(events))
    all_findings.extend(rule_003_consecutive_failures(events))
    all_findings.extend(rule_004_credential_enumeration(events))
    all_findings.extend(rule_005_session_amnesia(events))
    all_findings.extend(rule_006_burst_creation(events))
    all_findings.extend(rule_007_rapid_test_after_create(events))
    all_findings.extend(rule_008_repeated_listing(events))
    # Rule 009 (Silent Test Failure) requires external observation — skipped
    all_findings.extend(rule_010_session_gap(events))
    all_findings.extend(rule_011_content_volume_spike(events))
    all_findings.extend(rule_012_credential_lifecycle(events))
    all_findings.extend(rule_013_auth_status_mismatch(events))
    all_findings.extend(rule_014_credential_access_denied(events))
    all_findings.extend(rule_015_burst_fetch(events))
    all_findings.extend(rule_016_multi_credential_use(events))
    all_findings.extend(rule_017_missing_reason(events))

    return events, all_findings


def print_report(events, findings):
    """Print formatted findings report."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM-HIGH": 2, "MEDIUM": 3,
                      "LOW-MEDIUM": 4, "LOW": 5, "INFO": 6}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    print("=" * 70)
    print("COFFER-DETECT v0.5 — FINDINGS REPORT")
    print(f"Events analyzed: {len(events)}")
    print(f"Findings: {len(findings)}")
    print("=" * 70)

    severity_counts = defaultdict(int)
    rule_counts = defaultdict(int)

    for i, f in enumerate(findings, 1):
        severity_counts[f["severity"]] += 1
        rule_counts[f["rule"]] += 1
        print(f"\n[{i}] {f['rule']} | {f['severity']} | {f['criterion']}")
        print(f"    {f['description']}")
        if f.get("events"):
            print(f"    Events: {', '.join(str(e) for e in f['events'][:5])}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("-" * 70)
    print(f"Total findings: {len(findings)}")
    print(f"\nBy severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM-HIGH", "MEDIUM", "LOW-MEDIUM", "LOW", "INFO"]:
        if severity_counts[sev]:
            print(f"  {sev}: {severity_counts[sev]}")
    print(f"\nBy rule:")
    for rule in sorted(rule_counts.keys()):
        print(f"  {rule}: {rule_counts[rule]}")
    print(f"\nRules that fired: {len(rule_counts)} of 17")
    print(f"Rules silent: {17 - len(rule_counts)} of 17")
    print("  (Rule 009 skipped — requires external observation)")
    print("=" * 70)


if __name__ == "__main__":
    data = json.load(open(sys.argv[1]))
    events, findings = run_all_rules(data)
    print_report(events, findings)
