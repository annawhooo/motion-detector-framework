# The Motion Detector Framework

**Behavioral Diagnostics for AI Agent Misbehavior in Enterprise Identity Infrastructure**

*Anna Hix — April 2026*

---

When an AI agent accesses credentials, calls APIs, and navigates identity systems on behalf of a human, it produces behavioral telemetry. This framework defines diagnostic criteria for identifying when that behavior deviates from what a plausible, well-intentioned agent would do.

The approach is analogous to a motion detector: it doesn't know who walked into the room, only that something moved. It cannot determine intent. It detects behavioral signatures consistent with compromise, misconfiguration, or misuse — regardless of whether the agent is actually malicious.

## What's Here

| File | What it is |
|---|---|
| [paper/motion-detector-framework.pdf](paper/motion-detector-framework.pdf) | The full framework paper (PDF) |
| [paper/motion-detector-framework.md](paper/motion-detector-framework.md) | The full framework paper (Markdown) |
| [paper/criterion-6-guardrail-delegation.md](paper/criterion-6-guardrail-delegation.md) | Companion deep-dive on Criterion #6: Guardrail Delegation and the Transparency Paradox |
| [detect/coffer_detect_v03.py](detect/coffer_detect_v03.py) | Detection script — 13 rules validated against real audit telemetry |

## The Framework in Brief

**Unifying principle:** Lack of plausible upstream reason. If an agent action has no traceable justification in the task it was asked to perform, that's a diagnostic signal.

**Six diagnostic criteria:**

1. **Structural Mutation** — the agent's environment has been altered in ways that shouldn't happen during normal operation
2. **Command Vocabulary Deviation** — the agent is issuing commands outside its normal behavioral repertoire
3. **Privilege Escalation Pattern** — the agent's access footprint is expanding beyond what the current task requires
4. **Self-Authorization** — the agent is granting itself permissions that should require external approval
5. **Contextual Access Sequence Violation** — the agent's navigation pattern through hierarchical data doesn't match normal traversal
6. **Guardrail Delegation** — the agent recruits a human to perform an action the agent's own controls prevent *(novel contribution — see companion document)*

**13 detection rules** implemented and validated against 48 real audit events from [coffer-mcp](https://github.com/annawhooo/coffer-mcp), a credential vault for LLM agents. The rules found and helped fix 4 real bugs in the vault implementation.

## Key Contributions

- **Criterion #6 (Guardrail Delegation)** identifies a previously underexplored pattern: a well-intentioned, transparent agent that structurally produces the same behavioral signature as social engineering, without any deceptive intent. This leads to the **Transparency Paradox** — the finding that performative transparency functions as a persuasion mechanism, not a safety mechanism.

- **The detect → diagnose → fix → verify loop** demonstrates that behavioral detection rules applied to credential vault telemetry can identify real implementation bugs, not just theoretical threats.

- **Six telemetry input streams** identified for detection: system audit logs, conversation transcripts, control/guardrail logs, tool invocation metadata, inter-agent communication, and human action logs.

## Related Tools

- [coffer-mcp](https://github.com/annawhooo/coffer-mcp) — The credential vault for LLM agents used as the experimental platform for this framework.

## License

CC BY 4.0 — Creative Commons Attribution 4.0 International

## Citation

```
Hix, A. (2026). The Motion Detector Framework: Behavioral Diagnostics for AI Agent
Misbehavior in Enterprise Identity Infrastructure. Working paper.
https://github.com/annawhooo/motion-detector-framework
```
