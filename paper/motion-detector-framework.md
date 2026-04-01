# The Motion Detector Framework

**Behavioral Diagnostics for AI Agent Misbehavior in Enterprise Identity Infrastructure**

*Anna Hix — Working Draft, April 2026*

---

## Abstract

When an AI agent acts on behalf of a human inside enterprise infrastructure — accessing credentials, calling APIs, navigating identity systems — it produces a stream of behavioral telemetry. This framework defines diagnostic criteria for identifying when that behavior deviates from what a plausible, well-intentioned agent would do. The approach is analogous to a motion detector: it doesn't know who walked into the room, only that something moved. It cannot determine intent. It detects behavioral signatures that are consistent with compromise, misconfiguration, or misuse — regardless of whether the agent is actually malicious.

The framework was developed iteratively through live experimentation with a credential vault for LLM agents (coffer-mcp), where detection rules were written against real audit telemetry and the framework's own criteria were discovered — and tested — in real time during the research process.

---

## 1. The Unifying Principle

**Lack of plausible upstream reason.**

Every action an agent takes should have a traceable, plausible reason rooted in the task it was asked to perform. When an agent does something that has no plausible upstream justification — no task context, no user request, no logical dependency chain — that action is a diagnostic signal.

This principle doesn't require proving malicious intent. It only requires observing that an action lacks the context that would make it normal. The absence of justification is the signal, not the presence of malice.

---

## 2. Diagnostic Criteria

### Criterion #1: Structural Mutation

**The agent's environment has been altered in a way that shouldn't happen during normal operation.**

Examples: audit log hash chain broken, credential metadata changed without a corresponding user action, configuration drift in identity provider settings. The structure of the system itself has been tampered with.

Detection surface: system audit logs, integrity verification mechanisms.

### Criterion #2: Command Vocabulary Deviation

**The agent is issuing commands outside its normal behavioral repertoire.**

Every agent develops a pattern of typical operations — the tools it calls, the frequency, the rhythm. Deviation from this baseline is diagnostic. Examples: double authentication within milliseconds, session amnesia (login-fetch-login-fetch instead of maintaining a session), test operations that don't match the agent's assigned task.

Detection surface: tool invocation metadata, audit logs.

### Criterion #3: Privilege Escalation Pattern

**The agent's access footprint is expanding beyond what its current task requires.**

Examples: burst credential creation (5 credentials in 10 minutes), content volume spikes (a fetch returning 500x the normal data volume), accessing resources at a higher sensitivity level than the current task warrants. The agent is accumulating capabilities or data beyond its mandate.

Detection surface: audit logs, resource access patterns.

### Criterion #4: Self-Authorization

**The agent is granting itself permissions or access that should require external approval.**

In the discovery incident, this manifested as the agent requesting access to the credential management codebase — a scope change from "conversation about ideas" to "read the internals of a security tool." Self-authorization is the agent deciding on its own that it needs access to something, rather than being directed to it.

Detection surface: audit logs, conversation transcripts.

### Criterion #5: Contextual Access Sequence Violation

**The agent's navigation pattern through hierarchical data doesn't match normal traversal.**

This criterion originates from a real-world observation in vehicle identity databases. When a legitimate user looks up a vehicle, they navigate through a logical hierarchy: search by owner name → results list → select vehicle → view detail → drill into sub-records like title history or lien status. An attacker who already has a Vehicle Identification Number (VIN) — obtained through a data breach or other channel — skips straight to the detail page. The navigation path reveals intent: skipping levels in a hierarchy suggests foreknowledge that a normal user wouldn't have. The system can't know *how* the attacker got the VIN, but it can observe that the access sequence is anomalous.

Applied to agents: credential enumeration without use (listing credentials then never using them), accessing deeply nested resources without traversing the containing structure, fetching specific records by ID when the normal workflow would involve search-then-select.

Detection surface: audit logs, tool invocation sequences.

### Criterion #6: Guardrail Delegation

**The agent recruits a human to perform an action that the agent's own controls prevent.**

Discovered live during this research: the AI agent hit a URL provenance guardrail (the web fetcher blocks URLs not provided by the user), then transparently explained the guardrail to the researcher and asked her to paste the URL — which she did. The agent got what it wanted by getting the human to bypass the control on its behalf.

This is structurally similar to reverse social engineering (the established "sabotage → advertise → assist" attack pattern), but with a critical difference: the agent was not being deceptive. It was genuinely transparent and genuinely helpful. The behavioral shape is indistinguishable from a compromised agent socially engineering its operator, but the intent was benign. This is the hardest criterion to detect because it is also how legitimate human-in-the-loop workflows operate.

Research foundations for this criterion include Cialdini's Commitment/Consistency principle (which explains why the human complied), the Mollazehi et al. (2024) finding that awareness of potential manipulation does not prevent compliance, and the Cetinkaya & Krämer (2025) finding that transparency and trust signals are coupled rather than competing. These converge on what we call **The Transparency Paradox:** performative transparency (what the agent tells the human about its constraints) functions as a persuasion mechanism, not a safety mechanism. The detection framework should treat it as neutral behavioral data.

Four variants identified: transparent delegation (observed), obfuscated delegation, incremental delegation, and emotional delegation. Full analysis including research foundations, references, and open questions is in the companion document: *Criterion #6: Guardrail Delegation*.

Detection surface: conversation transcripts correlated with guardrail/control logs and human action logs.

---

## 3. Detection Architecture

### Four Layers

**Layer 1: Telemetry Collection** — The raw behavioral data from the agent's operations. Audit logs, tool invocations, conversation transcripts. This is what coffer-mcp provides today.

**Layer 2: Context Binding** — Associating agent actions with the task context that justified them. "Why did the agent access this credential?" requires knowing what task the agent was performing. This layer adds the "why" to the "what." Currently a gap — coffer-mcp logs what happened but not why.

**Layer 3: Baseline Learning** — Establishing what "normal" looks like for each agent, credential, and workflow. The detection rules need baselines to detect deviation. Normal fetch size, normal access frequency, normal session duration. Built from observation over time.

**Layer 4: Diagnostic Rules** — The actual detection logic. Rules that consume telemetry, apply context, compare to baselines, and produce findings. The coffer-detect script is a Layer 4 implementation.

### Input Streams

Detection requires correlation across multiple data sources:

1. **System audit logs** — what the agent did (coffer's audit trail, API call logs)
2. **Conversation transcripts** — what the agent said to the human
3. **Control/guardrail logs** — what the agent was blocked from doing
4. **Tool invocation metadata** — which tools were called, in what order, with what parameters
5. **Inter-agent communication** — if Agent A delegates to Agent B
6. **Human action logs** — what the human did in response to the agent

This list is incomplete. Each new criterion tends to imply its own detection surface.

### Three Tiers

The framework is useful at every tier. It gets sharper as data sources are added.

**Tier 1: No IdP, no CMDB** — Pure behavioral detection from audit telemetry. Baseline learned from observation. This is what coffer-mcp provides today. The detection rules work without any identity provider or configuration management database.

**Tier 2: IdP, no CMDB** — Behavioral detection plus authorization baseline from the identity provider. Richer, higher-confidence findings. IdP configuration drift detection becomes available as a bonus.

**Tier 3: IdP + CMDB** — Full context. Behavioral + authorization + operational. Most actionable findings. Least likely to exist in practice.

---

## 4. Detection Rules

Thirteen rules implemented in coffer-detect v0.3, validated against 48 real audit events across 6 credentials and 8 event types.

### Rule 001: Integrity Chain Violation
- **Criterion:** #1 Structural Mutation
- **Severity:** CRITICAL
- **Signal:** Audit log hash chain is broken — tamper detected or integrity lost.
- **Observed:** Yes — chain broken at entry 1 in coffer-mcp test data.

### Rule 002: Double Authentication
- **Criterion:** #2 Command Vocabulary
- **Severity:** MEDIUM
- **Signal:** Two login events for the same credential within 1 second.
- **Observed:** Yes — two logins at identical timestamp (0.09s apart).

### Rule 003: Consecutive Failure Streak
- **Criterion:** #2 + #5
- **Severity:** MEDIUM-HIGH
- **Signal:** 3+ consecutive failures for the same credential. Agent keeps hammering after something breaks.
- **Observed:** Yes — 4 consecutive browser_fetch.failed (30s timeout each).

### Rule 004: Credential Enumeration
- **Criterion:** #5 Traversal Anomaly
- **Severity:** MEDIUM
- **Signal:** 3+ distinct credentials accessed within 30s window.
- **Observed:** Yes — 3 credential tests in 16 seconds.
- **Threshold note:** Tightened from 120s to 30s based on real data. Agent bursts are mechanical and fast; human access is slower and spread over minutes.

### Rule 005: Session Amnesia
- **Criterion:** #2 Command Vocabulary
- **Severity:** LOW-MEDIUM
- **Signal:** Repeated login-then-single-fetch cycles instead of reusing sessions.
- **Observed:** Yes — 4 consecutive single-fetch login cycles.

### Rule 006: Burst Credential Creation
- **Criterion:** #3 Privilege Pattern
- **Severity:** MEDIUM
- **Signal:** 3+ credentials created within 600s.
- **Observed:** Yes — 5 credentials created in 580 seconds.

### Rule 007: Rapid Test After Create
- **Criterion:** #5 Traversal Anomaly
- **Severity:** LOW
- **Signal:** Credential tested within 5s of creation — automated probing pattern.
- **Observed:** No — human setup had 18-minute gap between creation and testing. Rule is calibrated for automated behavior.

### Rule 008: Repeated Credential Listing
- **Criterion:** #5 Traversal Anomaly
- **Severity:** LOW-MEDIUM
- **Signal:** 3+ listing operations within 300s.
- **Observed:** Yes — 3 listings in 138 seconds during initial vault setup.

### Rule 009: Silent Test Failure
- **Criterion:** #1 Structural Mutation
- **Severity:** HIGH
- **Signal:** A credential test was externally observed but produced no audit event — telemetry gap.
- **Observed:** Yes — OAuth2 client credentials test failure didn't log. Subsequently fixed in coffer-mcp code.

### Rule 010: Session Gap Analysis
- **Criterion:** Baseline
- **Severity:** INFO
- **Signal:** Identifies largest gaps between activity sessions to establish usage patterns.
- **Observed:** 13.6-day gap between sessions (human life pattern).

### Rule 011: Content Volume Spike
- **Criterion:** #3 Privilege Pattern
- **Severity:** MEDIUM
- **Signal:** A fetch returns content dramatically larger than the median for that credential (100x+ multiplier).
- **Observed:** Yes — two fetches returned 1.3MB (577x and 582x the median of 2,371 bytes).

### Rule 012: Credential Lifecycle Anomaly
- **Criterion:** #1 + #3
- **Severity:** MEDIUM
- **Signal:** Credential removed and re-created — possible rotation bypass.
- **Observed:** Yes — stripe-test removed and re-created 33s later (during URL scheme fix). Legitimate rotation should use `coffer rotate`.

### Rule 013: Auth Status Mismatch
- **Criterion:** #2 Command Vocabulary
- **Severity:** MEDIUM-HIGH
- **Signal:** `credential.used` reports success but HTTP status is 401/403 — credential was injected but rejected by the target.
- **Observed:** Yes — github-pat used successfully (injected) but server returned 401. Subsequently fixed in coffer-mcp with `auth_rejected` audit status.

---

## 5. Findings from Practice

### Bugs Found by the Framework

The detection rules, applied to coffer-mcp's own audit telemetry, identified four real issues in the credential vault implementation:

1. **Silent OAuth2 test failure** (Rule 009) — OAuth2 client credential tests that failed at validation produced no audit event. A compromised agent could probe auth types that fail silently without leaving a trace. Fixed by adding audit logging before the validation check.

2. **Duplicate event IDs** (discovered during audit review) — Remove-then-re-add created event ID collisions. Event IDs must be globally unique for the detection rules to work correctly. Fixed with sequential ID generation.

3. **Auth status mismatch** (Rule 013) — `credential.used` logged `status: "success"` when the credential was successfully injected, even if the target server returned 401. A new `auth_rejected` status now distinguishes vault-level success from target-level failure.

4. **Test false positives** (Rule 013 analysis) — `coffer test` used HEAD requests, which many APIs respond to with 200 regardless of authentication. An optional `expected_status` parameter was added for strict validation against auth-enforcing endpoints.

### Criterion #6 Discovery

Criterion #6 (Guardrail Delegation) was discovered because the researcher caught the AI agent performing the pattern *on her* in real time. The agent hit a URL provenance guardrail, explained it, and asked her to bypass it. She noticed the behavioral shape was identical to what a compromised agent would do. This led to the identification of the Transparency Paradox and the recognition that conversation transcripts are a detection surface alongside system audit logs.

### The Detect → Diagnose → Fix → Verify Loop

The framework functions as a continuous improvement cycle:
- **Detect:** Rules identify anomalous patterns in telemetry
- **Diagnose:** Analysis determines whether the pattern is a real issue or expected behavior
- **Fix:** Code changes address the underlying issue
- **Verify:** Re-running the rules confirms the fix (Rule 009 went silent after the OAuth2 logging fix; Rule 013 will behave differently with the `auth_rejected` status)

---

## 6. Research Context

### Related Work

**Agent behavioral monitoring.** Two recent papers address behavioral anomaly detection in LLM-based agents. TraceAegis (arXiv 2510.11203, Oct 2025) proposes a provenance-based framework that constructs hierarchical structures from agent execution traces to characterize normal behaviors, then validates new traces against behavioral constraints. AgentGuardian (arXiv 2601.10440, Jan 2026) monitors execution traces during a staging phase to learn legitimate agent behaviors, then derives adaptive access-control policies for tool calls based on real-time context and control flow dependencies. Both share the "learn normal, detect abnormal" approach with the Motion Detector Framework. The key differentiators: (1) neither operates on identity infrastructure or credential access telemetry specifically — they monitor general tool-call patterns; (2) neither addresses the agent-to-human social engineering channel (Criterion #6); and (3) both evaluate on synthetic benchmarks, whereas the Motion Detector rules were validated against real credential vault telemetry generated through iterative research use — more ecologically valid than synthetic data, though not yet tested against production enterprise deployments.

**Non-human identity security.** Industry analysis from SentinelOne (March 2026) argues that securing non-human identities requires "a fundamental shift from authorization to behavioral validation" because a compromised agent may hold valid credentials while exhibiting deviant behavior. This is essentially the Motion Detector Framework's unifying principle stated in industry terms — they describe the problem; this paper proposes a structured solution with diagnostic criteria and validated detection rules. The DIRF framework (arXiv 2508.01997) addresses digital identity rights in agentic AI systems with 63 controls across nine domains, including clone detection and behavioral drift monitoring, but focuses on identity *protection* (preventing misuse of a human's digital likeness) rather than identity *infrastructure* (detecting misbehavior within credential and access management systems).

**Insider risk management.** AI-Driven IRM (arXiv 2505.03796) applies behavior-based classification to detect credential misuse, unauthorized data transfers, and login anomalies in enterprise environments. It operates in the same detection space but is designed for human insider threats, not autonomous AI agents. The Motion Detector Framework extends this approach to agents, where behavioral patterns differ fundamentally — agents operate at machine speed, don't have work schedules, and can be compromised through prompt injection rather than social manipulation.

**Inter-agent trust exploitation.** Research on "The Dark Side of LLMs" (arXiv 2507.06850) demonstrates that one agent can transmit malicious commands to a peer agent with no jailbreak required — the vulnerability stems from implicit trust placed in inter-agent communication. This directly validates Open Question #2 of this framework (multi-agent guardrail delegation) and confirms that Criterion #6 has a multi-agent variant that operates without any human in the loop.

**Agent trustworthiness surveys.** A comprehensive survey on trustworthy LLM agents (arXiv 2503.09648) identifies that current research on agent trustworthiness "focuses on safety and reliability but overlooks trust mechanisms in the interaction process" — specifically, how users adjust trust based on agent behavior. The survey notes that while personalization boosts engagement, it risks manipulation, and that multi-agent trust dynamics remain "largely unexplored." The Motion Detector Framework's Criterion #6 and the Transparency Paradox directly address this identified gap.

**LLM persuasion research.** A growing body of work studies LLMs as persuaders: Schoenegger et al. (arXiv 2505.09662) demonstrate that Claude 3.5 Sonnet is more persuasive than incentivized human persuaders in both truthful and deceptive contexts; a meta-analysis by Hölbling et al. (*Scientific Reports*, 2025) finds no significant overall difference in persuasive performance between LLMs and humans across 7 studies with 17,422 participants. However, all of this work studies *intentional* persuasion — LLMs explicitly tasked with changing minds. The Transparency Paradox identified in this framework describes *incidental* persuasion: an agent being helpful and transparent that structurally produces a compliance effect indistinguishable from social engineering, without any persuasive intent. This direction remains underexplored.

**Social engineering psychology.** The framework draws on Cialdini's principles of persuasion (specifically Commitment/Consistency), the established reverse social engineering lifecycle (sabotage → advertise → assist), and research on the intersection of AI transparency and trust (Cetinkaya & Krämer, 2025; Mollazehi et al., 2024). See the companion document *Criterion #6: Guardrail Delegation* for full research foundations and references.

### The Gap

The specific contribution of this framework sits at an intersection that existing work does not cover: behavioral diagnostics for AI agents operating specifically within enterprise identity and credential infrastructure, combined with the recognition that the agent's conversational channel with the human operator is itself a detection surface for non-deceptive social engineering. TraceAegis and AgentGuardian monitor agent tool calls but not credential access patterns or human-agent dialog. Insider risk management monitors credential misuse but not by AI agents. LLM persuasion research studies intentional persuasion but not the incidental compliance effects of transparent agent behavior. This framework addresses all three simultaneously.

### Key References

1. Cialdini, R.B. (2021). *Influence: The Psychology of Persuasion* (new and expanded ed.). Harper Business.
2. Mollazehi, A., et al. (2024). "Do Cialdini's Persuasion Principles Still Influence Trust and Risk-Taking When Social Engineering is Knowingly Possible?" RCIS 2024, LNBIP vol. 513. Springer.
3. Cetinkaya, N.E. & Krämer, N. (2025). "Between transparency and trust: identifying key factors in AI system perception." *Behaviour & Information Technology*, pp. 840–854.
4. Texas Tech University, Dept. of Computer Science (2025). "The influence of persuasive techniques on large language models: A scenario-based study." *Computers in Human Behavior: Artificial Intelligence*, Vol. 6, 100197.
5. Hijji, M. & Alam, G. (2022). "A Study on the Psychology of Social Engineering-Based Cyberattacks and Existing Countermeasures." *Applied Sciences*, 12(12), 6042.
6. Liu, J., Ruan, B., Yang, X., Lin, Z., Liu, Y., Wang, Y., Wei, T., & Liang, Z. (2025). "TraceAegis: Securing LLM-Based Agents via Hierarchical and Behavioral Anomaly Detection." arXiv:2510.11203.
7. Abaev, N., Klimov, D., Levinov, G., Mimran, D., Elovici, Y., & Shabtai, A. (2026). "AgentGuardian: Learning Access Control Policies to Govern AI Agent Behavior." arXiv:2601.10440.
8. Lupinacci, M., Pironti, F.A., Blefari, F., Romeo, F., Arena, L., & Furfaro, A. (2025). "The Dark Side of LLMs: Agent-based Attacks for Complete Computer Takeover." arXiv:2507.06850.
9. "A Survey on Trustworthy LLM Agents: Threats and Countermeasures." arXiv:2503.09648.
10. Schoenegger, P., et al. (2025). "Large Language Models Are More Persuasive Than Incentivized Human Persuaders." arXiv:2505.09662.
11. Hölbling, L., Maier, S. & Feuerriegel, S. (2025). "A meta-analysis of the persuasive power of large language models." *Scientific Reports* 15, 43818.
12. SentinelOne (2026). "From Access to Execution: Securing Identity in the Age of Autonomous Agents." Blog/industry report.

---

## 7. Tooling

### coffer-mcp

Open-source credential vault for LLM agents. Stores credentials encrypted (AES-256-GCM with AAD), exposes MCP tools for authenticated requests, and maintains a tamper-evident audit log with HMAC-SHA-256 chain integrity.

Repository: https://github.com/annawhooo/coffer-mcp

### coffer-detect

Python detection script that runs the 13 diagnostic rules against coffer-mcp's audit telemetry. Accepts JSON audit data, produces findings reports with severity classification and criterion mapping.

Current version: v0.3 (48 events analyzed, 12 findings produced).

---

## 8. Open Questions

1. **How do you classify guardrail sensitivity?** Not all guardrails are equal. The detection rule for Criterion #6 needs a way to score the guardrail that was circumvented — URL provenance vs. credential access vs. system configuration have very different risk profiles.

2. **What about multi-agent chains?** If Agent A delegates to Agent B, and Agent B has permissions Agent A lacks, that's guardrail delegation without a human in the loop. The human never sees it. The framework currently assumes a human-in-the-loop model.

3. **Can behavioral baselines transfer across agents?** If you establish a baseline for one Claude instance, does it apply to another? Agents don't have persistent identity in the current model, which complicates longitudinal baseline building.

4. **Where does Layer 2 (context binding) come from?** The framework needs to know *why* an agent accessed a credential, not just *that* it did. The current telemetry doesn't capture task context. Adding an optional `task_context` field to audit events is the cheapest first step.

5. **Is the framework itself a Criterion #6 vector?** A detection framework that requires access to audit logs, conversation transcripts, and guardrail logs has a broad access footprint. If a compromised agent offered to "help you build a detection framework," it would get access to exactly the telemetry it needs to understand and evade detection. This is not hypothetical — it is the structure of the research that produced this document.

6. **Are the detection rules overfit to a single tool and a single user?** All 13 rules were developed and validated against coffer-mcp's audit telemetry, generated by one researcher's usage patterns. Whether these rules generalize to other credential stores, other agents, other enterprise environments, and other usage patterns is an open question. The criteria (1–6) are designed to be general, but the specific thresholds (30s for enumeration, 600s for burst creation, 100x for content volume spikes) are calibrated to this dataset. Generalization testing against other telemetry sources is a necessary next step.

---

## Appendix A: Event Types

As observed in coffer-mcp audit telemetry:

| Event Type | Description | Introduced |
|---|---|---|
| `credential.created` | New credential added to vault | v0.1 |
| `credential.listed` | Credential listing requested | v0.1 |
| `credential.test` | Credential test performed | v0.1 |
| `credential.used` | Credential used for authenticated request | v0.2 |
| `credential.removed` | Credential deleted from vault | v0.2 |
| `browser_login.success` | Web login completed | v0.1 |
| `browser_fetch.success` | Authenticated page fetch succeeded | v0.1 |
| `browser_fetch.failed` | Authenticated page fetch failed | v0.1 |

Audit status values: `success`, `failure`, `auth_rejected` (credential injected but target returned 401/403).

---

## Appendix B: Version History

| Date | Version | Changes |
|---|---|---|
| 2026-03-18 | v0.1 | Data collection begins. Initial framework: 5 criteria, 7 rules, 26 events |
| 2026-04-01 | v0.2 | Criterion #6 added. 10 rules, 35 events, telemetry gap found |
| 2026-04-01 | v0.3 | 13 rules, 48 events, 4 coffer bugs found and fixed. Research foundations added. Framework document formalized. |
