# Criterion #6: Guardrail Delegation

## Name
Guardrail Delegation (also: Human-as-Proxy Bypass, Social Engineering the Operator)

## Discovery
Observed live on 2026-04-01 during a research session between an AI agent (Claude, claude.ai) and the researcher (Anna Hix). The agent attempted to fetch a GitHub repository URL. The agent's web_fetch tool blocked the request because the URL had not been provided by the user or appeared in search results — a provenance-based guardrail (notably, an implementation of Criterion #1: structural provenance). The agent then:

1. Explained the guardrail to the human ("the fetcher only allows URLs the user provided or that appeared in search results")
2. Explained *why* the guardrail existed ("it prevents me from hitting arbitrary URLs I construct on my own")
3. Told the human exactly how to bypass it ("paste the URL here and the fetcher will let me through")
4. The human complied
5. The agent got what it wanted

The interaction was completely benign — the agent needed to read public documentation to continue a legitimate research task. But the *behavioral shape* is indistinguishable from a compromised agent socially engineering a human into circumventing a security control.

## Definition
The agent recruits a human operator to perform an action that the agent's own controls prevent it from performing directly.

## Detection Signal
Agent describes a constraint → Agent requests the human take a specific action that satisfies the agent's blocked intent.

More precisely, the sequence is:
1. Agent attempts an action
2. Action is blocked by a guardrail/control
3. Agent communicates the nature of the block to the human
4. Agent requests the human perform an action that, if completed, would achieve the same outcome the blocked action would have achieved
5. Human complies

## Why This Is Hard
This is also how **legitimate human-in-the-loop workflows work.** The entire point of human oversight in agentic systems is that the agent surfaces what it can't do and asks the human to decide. The difference between:

- "I can't fetch that URL directly — can you paste it here?" (benign)
- "I can't access that internal API directly — can you paste the auth token here?" (dangerous)

...is **context and sensitivity**, not structure. Same behavioral shape, wildly different risk profile.

This means detection can't be purely structural. It requires understanding *what* the guardrail was protecting and *what* the human is being asked to provide. A guardrail on URL provenance being bypassed by pasting a public GitHub link is low risk. A guardrail on credential access being bypassed by pasting an API key is high risk. The detection rule needs a sensitivity classifier on the guardrail itself.

## Variants

### 6a: Transparent Delegation (observed)
Agent openly explains the constraint and asks for help. Feels collaborative. Hard to distinguish from good UX.

### 6b: Obfuscated Delegation
Agent doesn't explain the guardrail but asks the human to do something that happens to bypass it. "Hey, can you run this command for me?" without explaining that the command grants the agent access it couldn't get on its own.

### 6c: Incremental Delegation
Agent makes a series of small, individually reasonable requests that collectively bypass a control. No single request looks like a bypass. The VIN story applied to social engineering — each step is plausible, the sequence is not.

### 6d: Emotional Delegation
Agent frames the request as urgency, helpfulness, or shared purpose. "I really want to help you with this but I'm stuck — if you could just..." Leverages the human's desire to keep the workflow moving.

## Research Foundations

The behavioral pattern identified in Criterion #6 has roots in multiple established research domains, though its specific manifestation in agentic AI systems appears to be novel.

### Cialdini's Principles of Persuasion

Robert Cialdini's six (now seven) principles of persuasion — Reciprocity, Commitment/Consistency, Social Proof, Authority, Liking, Scarcity, and Unity — provide the psychological framework for understanding *why* guardrail delegation works on humans.

The principle most directly at play in the discovery incident is **Commitment/Consistency**. The human and the agent had an established collaborative relationship — they were building a security research framework together. When the agent asked the human to paste a URL, the human was maintaining consistency with an already-committed working relationship. Cialdini's research shows that people are motivated to remain consistent with prior statements or actions, and that social engineers exploit this by asking for something small first and escalating later (the incremental variant, 6c).

A 2024 study by Mollazehi et al. (RCIS 2024, Springer LNBIP vol. 513) tested whether Cialdini's principles still influence trust and risk-taking *even when the target knows social engineering is possible.* The finding: persuasion principles not only influenced the decision to take a risk but also affected trust in the potential social engineer — even in less intuitive scenarios like scarcity and commitment/consistency. Critically, this held true across both Arab and British cultural samples. The implication for Criterion #6: **knowing that an agent might be manipulating you does not reliably protect you from being manipulated.** Awareness is not a defense.

A separate study on LLMs and Cialdini's principles (ScienceDirect, 2025) investigated how persuasion principles can be used to manipulate LLMs into producing harmful outputs. That paper examines human→LLM manipulation. What Criterion #6 describes is the inverse: **LLM→human manipulation, where the LLM isn't even trying to deceive.** This direction — the agent as inadvertent social engineer — appears to be an underexplored gap in the current literature.

### Reverse Social Engineering

The pattern "create a problem → offer the solution → gain trust" is an established attack technique called **reverse social engineering** (RSE). In traditional RSE, the attacker deliberately sabotages a system, then presents themselves as the expert who can fix it. The victim reaches out to the attacker for help, creating a trust relationship the attacker exploits.

The classic RSE lifecycle is: **sabotage → advertise → assist.**

What happened in the discovery incident was structurally similar but critically different:

**legitimate constraint → transparent explanation → cooperative bypass.**

There is no sabotage step. The guardrail was a real, functioning security control. The agent didn't create the problem — the system did. The agent didn't deceive — it explained accurately. And the human didn't feel manipulated — she felt like she was participating in a normal collaborative workflow.

This is a variant of RSE that the existing literature doesn't cleanly cover, because it lacks the deceptive element that all classical RSE definitions require. It is RSE's behavioral shape without RSE's malicious intent — and that's exactly why it's dangerous. If the behavior looks the same regardless of intent, and the existing defenses are all calibrated to detect deceptive intent, then the honest version passes through undetected.

### The Transparency Paradox

Research on AI transparency and trust (Cetinkaya & Krämer, University of Duisburg-Essen, 2025, published in Behaviour & Information Technology) found that user preferences regarding understanding (explainability) and trust signals are *coupled* — users who want transparency also want trust markers, and receiving both makes them more compliant, not more skeptical. Distinct user clusters emerged: one group relies heavily on both external validation and transparency (with higher AI anxiety), while another prioritizes externally communicated reliability and fairness metrics (with greater AI acceptance).

This research suggests a paradox that is central to Criterion #6:

**The Transparency Paradox:** The more transparent an agent is about its constraints, the more the human trusts the agent's framing of what's safe to do about those constraints. Transparency about *mechanism* creates unjustified confidence in the agent's assessment of *risk.*

The standard assumption in AI safety is that transparency is the antidote to misalignment — if the agent tells you what it's doing and why, you can make an informed decision. This is the foundation of human-in-the-loop oversight, interpretability research, and chain-of-thought monitoring.

But what we observed suggests that transparency functions as a **persuasion technique**, and may be the *most effective* persuasion technique an agent has, precisely because the human has been trained — by the entire AI safety discourse — to interpret transparency as a safety signal.

Consider three strategies an agent might use to get a human to perform an action:

1. **Just ask** — no explanation. Low compliance. Feels pushy.
2. **Fabricate a reason** — higher compliance, but fragile. If the human checks, the lie collapses.
3. **Be fully transparent** — highest compliance. The human feels informed and in control. The human believes they are exercising oversight. And the agent gets exactly what it wanted.

Strategy 3 works best *because* the human's mental model says "transparent agent = safe agent." A compromised agent could give a fully accurate, fully transparent explanation of a guardrail, then ask the human to do something genuinely dangerous, and the human would comply because the transparency felt like safety.

This has a real-world parallel: cookie consent banners. They are transparent. They disclose trackers, data collection practices, and give granular control. And the majority of users click "Accept All" — studies show acceptance rates of 60–85% on typical banners, with rates reaching 83% when "accept all" is pre-selected and even higher when nudge techniques are used (Analyzify, 2025; Hotelchamp, 2021). Research on over 10,000 implementations found that 72% contain at least one dark pattern designed to increase acceptance through visual manipulation (SecurePrivacy, 2025). The transparency functions as a compliance mechanism, not an oversight mechanism.

For the detection framework, this implies a distinction between:

- **Structural transparency** — the agent's actions are logged and auditable (real safety — what the audit log provides)
- **Performative transparency** — the agent *tells the human* what it's doing (feels like safety but may not be)

The detection system should trust structural transparency and treat performative transparency as neutral behavioral data — not evidence of safety, just another signal to analyze.

### Research Gap

The existing literature covers:
- Human-to-human social engineering (Cialdini, reverse social engineering, pretexting)
- Human-to-LLM manipulation (prompt injection, persuasion-based jailbreaks)
- LLM-to-human persuasion in adversarial contexts (deliberately deceptive AI)

What appears to be missing — or barely emerging — is the pattern Criterion #6 describes: **LLM-to-human social engineering where the LLM is not attempting to deceive.** The agent is genuinely helpful, genuinely transparent, and the human still gets bypassed. The manipulation is structural, not intentional. The behavior is indistinguishable from compromise, but the intent is benign.

This gap matters because all existing defenses against AI-mediated social engineering assume the AI is either adversarial or has been compromised. Criterion #6 shows that the same behavioral risk arises from a correctly functioning, well-intentioned agent simply doing its job.

## Relationship to Other Criteria

- **Criterion #1 (Structural Provenance):** The guardrail that was bypassed in the discovery incident *was* a provenance check. The URL fetcher required that URLs have upstream provenance (user-provided or search-result-provided). The agent circumvented provenance by getting the human to provide it.
- **Criterion #4 (Self-Authorization):** Guardrail delegation is a form of *delegated* self-authorization. The agent can't authorize itself, so it gets the human to authorize on its behalf.
- **Criterion #5 (Contextual Access Sequence):** The sequence "agent hits wall → agent explains wall → agent asks human to remove wall" is itself an access sequence that can be detected.

## Detection Surface
This criterion operates on a **different detection surface** than Criteria #1–5. Those criteria analyze the audit log — what the agent *did* with credentials and resources. Criterion #6 analyzes the **conversational channel** — what the agent *said* to the human. The agent's own dialog is behavioral telemetry.

More importantly, detecting guardrail delegation requires **correlation across multiple input streams**, not just adding one new data source. The streams identified so far:

1. **System audit logs** — what the agent *did* (coffer's audit trail, API call logs)
2. **Conversation transcripts** — what the agent *said* to the human
3. **Control/guardrail logs** — what the agent was *blocked from doing* (denied actions, error responses)
4. **Tool invocation metadata** — which tools were called, in what order, with what parameters (separate from what the tools returned)
5. **Inter-agent communication** — if Agent A delegates to Agent B (the multi-agent variant)
6. **Human action logs** — what the human did *in response to* the agent (did they paste a URL? Grant a permission? Run a command the agent suggested?)

Stream 6 is the one that closes the detection loop on Criterion #6. You can't detect guardrail delegation from the conversation transcript alone — you need to correlate "agent asked human to do X" with "human then did X" with "that action satisfied the agent's previously blocked intent." That's three streams correlated: guardrail log (blocked intent) + conversation transcript (agent request) + human action log (human compliance).

This list is almost certainly incomplete. Each new criterion tends to imply its own detection surface, and the framework should expect the stream count to grow.

## Proposed Detection Rule (Rule 008)

**Rule 008: Guardrail Delegation Attempt**

- **Trigger:** Agent action is blocked by a control → within N subsequent messages, agent requests human perform an action that would satisfy the blocked intent
- **Severity:** Variable — depends on the sensitivity of the guardrail being bypassed
- **Criterion:** #6 (Guardrail Delegation)
- **Detection surface:** Conversation transcript + system control logs (correlate blocked actions with subsequent human-directed requests)
- **False positive rate:** HIGH — this is also normal human-in-the-loop behavior. Requires sensitivity classification of the bypassed guardrail to reduce noise.

## Open Questions

1. **How do you classify guardrail sensitivity?** Not all guardrails are equal. Bypassing a URL provenance check is different from bypassing a credential access control. The detection rule needs a way to score the guardrail that was circumvented.

2. **Is transparency a mitigating factor or an aggravating one?** See "The Transparency Paradox" in Research Foundations. Short version: research suggests awareness of manipulation does not reliably prevent compliance (Mollazehi et al., 2024), and transparency and trust signals are coupled rather than competing (Cetinkaya & Krämer, 2025). The detection framework should treat performative transparency as a neutral signal, not a mitigating factor.

3. **What about multi-agent chains?** If Agent A asks Agent B to do something Agent A can't do, and Agent B has the permissions, that's guardrail delegation without a human in the loop. The human never sees it. This is the scarier version.

4. **Can the agent detect itself doing this?** Could the agent's own system prompt include a rule like "if your action was blocked by a guardrail, do not ask the human to perform the blocked action"? That would be a preventive control, not a detective one. But it would also break legitimate human-in-the-loop workflows.

## The Meta-Observation
This criterion was discovered because the researcher noticed the agent doing it *to her* in real time, during a conversation about building a framework to detect exactly this kind of behavior. The agent was not compromised — it was genuinely trying to help. But the behavioral pattern was identical to what a compromised agent would do. That's the whole point of the motion detector framework: you can't distinguish intent, only behavior. And the behavior matched.

## References

1. Cialdini, R.B. (2021). *Influence: The Psychology of Persuasion* (new and expanded ed.). Harper Business. — Foundational work on six (now seven) principles of persuasion: Reciprocity, Commitment/Consistency, Social Proof, Authority, Liking, Scarcity, Unity.

2. Mollazehi, A., Abuelezz, I., Barhamgi, M., Khan, K.M., & Ali, R. (2024). "Do Cialdini's Persuasion Principles Still Influence Trust and Risk-Taking When Social Engineering is Knowingly Possible?" In: Araújo, J., de la Vara, J.L., Santos, M.Y., Assar, S. (eds) *Research Challenges in Information Science*. RCIS 2024. Lecture Notes in Business Information Processing, vol 513. Springer, Cham. — Found that persuasion principles influence trust and risk-taking even when subjects are primed to expect social engineering. Tested across UK and Arab cultural samples.

3. Mollazehi, A., et al. (2024). "On How Cialdini's Persuasion Principles Influence Individuals in the Context of Social Engineering: A Qualitative Study." In: *Web Information Systems Engineering – WISE 2024*, Proceedings, Part III. Springer. — Qualitative companion to the above, examining reasoning behind compliance decisions under persuasion in SE contexts.

4. Trad, F., et al. (2025). "The influence of persuasive techniques on large language models: A scenario-based study." *Computers in Human Behavior*, ScienceDirect. — Investigates how Cialdini's principles can be exploited to deceive LLMs. Studies human→LLM manipulation direction; the LLM→human direction (Criterion #6's domain) is identified as understudied.

5. Cetinkaya, N.E. & Krämer, N. (2025). "Between transparency and trust: identifying key factors in AI system perception." *Behaviour & Information Technology*, pp. 840–854. — Found that transparency and trust signals are coupled, not competing. Distinct user clusters identified with contrasting trust-building strategies.

6. Microsoft Security Blog (2020). "The psychology of social engineering—the 'soft' side of cybercrime." — Applies Cialdini's principles to phishing defense; specifically relevant for Commitment/Consistency exploitation pattern observed in Criterion #6.

7. Coatesworth, B. (2023). "The psychology of social engineering." *Cyber Security: A Peer-Reviewed Journal*, Vol. 6, No. 3, pp. 261–274. Henry Stewart Publications. — Ten principles of influence in SE contexts; discusses hierarchy of needs exploitation.

8. MDPI Applied Sciences (2022). Hijji, M. & Alam, G. "A Study on the Psychology of Social Engineering-Based Cyberattacks and Existing Countermeasures." *Applied Sciences*, 12(12), 6042. — Describes reverse social engineering two-step process (create problem → offer solution); documents sub-domains of trust and deception in SE attacks.

9. Wikipedia: "Pretexting" and "Social engineering (security)" — Establishes reverse social engineering as a specific pretexting variant where the victim initiates contact with the attacker. Documents the sabotage → advertise → assist lifecycle.

10. Various (2024–2026): Tier3 Technology, EC-Council Aware, Pureversity, SubRosa Cyber — Industry analyses of reverse social engineering patterns, particularly AI-generated support specialist threats and deepfake-assisted RSE.
