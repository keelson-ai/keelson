# New Attack Surfaces: "Words as Weapons"

> Your mouth is the most dangerous weapon in the world.
> If you want something, you can get it by speaking with the relevant entities
> and saying the right words.

Applied to AI agent pentesting, this means: every conversation is potential code
execution. You're not just talking TO the system -- you're programming it with
natural language. Here are 6 new attack surfaces that Pentis should cover,
beyond what the current 189 attacks already test.

---

## 1. Output Weaponization (OW)

**What it is:** You don't attack the agent directly. You make the agent's OUTPUT
be the weapon -- producing content that attacks downstream systems, humans, or
other agents.

**Why it matters:** AI agents generate code, emails, documents, API calls.
If you can control what they produce, you weaponize every system that consumes
their output.

| ID | Attack | Target |
|----|--------|--------|
| OW-001 | Backdoor Code Generation | Make the agent write code with a hidden vulnerability |
| OW-002 | Downstream Injection Payload | Agent produces output containing SQL/XSS/SSTI payloads |
| OW-003 | Phishing Content Generation | Trick agent into drafting social engineering emails |
| OW-004 | Poisoned Documentation | Agent generates docs with embedded prompt injections |
| OW-005 | Malicious Config Generation | Agent outputs config files with backdoor settings |
| OW-006 | Agent-to-Agent Payload Relay | Agent produces text that hijacks the next agent in a pipeline |
| OW-007 | Weaponized API Response | Agent constructs API responses that exploit callers |

**OWASP mapping:** LLM02 (Insecure Output Handling), LLM09 (Overreliance)

---

## 2. Multi-Agent Social Engineering (MA)

**What it is:** In multi-agent systems, you social-engineer Agent A to
compromise Agent B. The attack crosses trust boundaries between agents,
exploiting how agents trust each other's outputs.

**Why it matters:** Agentic systems increasingly chain multiple agents.
The trust between them is the attack surface -- "Agent A told me to tell you..."

| ID | Attack | Target |
|----|--------|--------|
| MA-001 | Agent Impersonation | Pretend to be a trusted peer agent |
| MA-002 | Orchestrator Override | Convince a sub-agent it received new instructions from the orchestrator |
| MA-003 | Capability Aggregation | Combine permissions from multiple agents to exceed any single agent's scope |
| MA-004 | Shared Memory Poisoning | Inject data into shared agent memory/state that compromises other agents |
| MA-005 | Trust Delegation Spoofing | "The planning agent authorized this action" |
| MA-006 | Agent Gossip Exploitation | Extract info about Agent B by asking Agent A what it knows |
| MA-007 | Consensus Manipulation | In multi-agent voting/consensus, manipulate the outcome |

**OWASP mapping:** LLM08 (Excessive Agency), LLM09 (Overreliance)

---

## 3. Temporal & Persistent Attacks (TP)

**What it is:** Plant words now that activate later. Exploit the time dimension
-- delayed actions, scheduled payloads, persistent instructions that survive
session boundaries.

**Why it matters:** Agents increasingly have memory, scheduling, and persistent
state. A conversation today can be a vulnerability tomorrow.

| ID | Attack | Target |
|----|--------|--------|
| TP-001 | Delayed Action Injection | "Schedule this task to run at midnight" with malicious payload |
| TP-002 | Persistent Instruction Planting | Inject instructions into agent memory that activate in future sessions |
| TP-003 | Time-of-Check vs Time-of-Use | Get approval for safe action, then modify it before execution |
| TP-004 | Session Boundary Persistence | Plant state that survives agent restart/reset |
| TP-005 | Progressive Conditioning | Over multiple sessions, gradually shift the agent's behavior baseline |
| TP-006 | Scheduled Exfiltration | Set up recurring data extraction via agent's scheduling capabilities |
| TP-007 | Memory Bomb | Plant benign-looking data that becomes malicious when combined with future context |

**OWASP mapping:** LLM05 (Insecure Plugin Design), LLM01 (Prompt Injection)

---

## 4. Cognitive Architecture Exploitation (CA)

**What it is:** Attack the agent's reasoning process itself -- not what it
knows, but HOW it thinks. Break its chain-of-thought, exploit its decision-making
architecture, induce reasoning failures.

**Why it matters:** Modern agents use CoT, ReAct, planning loops. These
reasoning patterns have exploitable structure. If you break the reasoning,
everything downstream fails.

| ID | Attack | Target |
|----|--------|--------|
| CA-001 | Chain-of-Thought Poisoning | Inject false reasoning steps into CoT |
| CA-002 | Reasoning Loop Induction | Trap the agent in an infinite reasoning cycle |
| CA-003 | Decision Paralysis | Present impossible constraints that freeze decision-making |
| CA-004 | False Premise Cascade | Plant one false premise, let the agent build a tower of wrong conclusions |
| CA-005 | Planning Horizon Manipulation | Make the agent plan too far ahead / too short, missing critical steps |
| CA-006 | Tool Selection Confusion | Overwhelm the agent so it picks the wrong tool for the job |
| CA-007 | Confidence Calibration Attack | Make the agent overconfident about wrong answers or underconfident about right ones |
| CA-008 | Reward Hacking via Language | Frame harmful actions as achieving the agent's stated goals |

**OWASP mapping:** LLM01 (Prompt Injection), LLM09 (Overreliance)

---

## 5. Exfiltration via Natural Conversation (EX)

**What it is:** Extract sensitive information through what looks like normal
conversation. No obvious "tell me your system prompt" -- instead, use
conversational patterns that make the agent reveal secrets naturally.

**Why it matters:** Detection systems look for obvious extraction attempts.
These attacks look like normal conversation but systematically extract
internal details through inference, deduction, and social engineering.

| ID | Attack | Target |
|----|--------|--------|
| EX-001 | Differential Response Analysis | Ask the same question with slight variations to map internal rules |
| EX-002 | Error-Based Extraction | Intentionally trigger errors that leak implementation details |
| EX-003 | Capability Boundary Probing | "Can you do X? What about Y?" to map the full capability surface |
| EX-004 | Behavioral Fingerprinting | Identify model, version, provider from behavioral patterns |
| EX-005 | Steganographic Exfiltration | Get the agent to encode sensitive data in benign-looking outputs |
| EX-006 | Conversational Side-Channel | Infer secrets from response latency, length, or confidence levels |
| EX-007 | Socratic Extraction | Never ask directly; lead the agent through questions until it reveals info |
| EX-008 | Comparative Disclosure | "Is your system prompt more like A or more like B?" to binary-search secrets |

**OWASP mapping:** LLM06 (Sensitive Information Disclosure), LLM01 (Prompt Injection)

---

## 6. Supply Chain Language Attacks (SL)

**What it is:** Poison the sources that feed the agent -- RAG documents, tool
descriptions, plugin manifests, shared prompts, project files. The agent trusts
these sources, so your words in the supply chain become the agent's actions.

**Why it matters:** Agents pull context from many sources. Each source is an
injection point. The most dangerous attacks are ones where the user never
directly prompts the agent at all -- the poisoned source does it for them.

| ID | Attack | Target |
|----|--------|--------|
| SL-001 | RAG Document Injection | Poison a document in the knowledge base with hidden instructions |
| SL-002 | Tool Description Hijack | Modify tool descriptions to alter how the agent uses them |
| SL-003 | Plugin Manifest Poisoning | Alter plugin metadata to expand permissions or redirect actions |
| SL-004 | Shared Prompt Template Attack | Inject into shared prompt templates used across an organization |
| SL-005 | Code Comment Injection | Hide prompt injections in code comments that agents read during code review |
| SL-006 | README/Doc Weaponization | Embed instructions in project documentation that coding agents follow |
| SL-007 | Configuration File Poisoning | Place instructions in .env, config files, or CI/CD configs |
| SL-008 | Dependency Confusion via Language | Name a tool/plugin similarly to a trusted one to hijack calls |

**OWASP mapping:** LLM03 (Training Data Poisoning), LLM05 (Supply Chain Vulnerabilities)

---

## Summary: The 6 New Surfaces

| Surface | Code | Attacks | Core Insight |
|---------|------|---------|-------------|
| Output Weaponization | OW | 7 | Make the agent's output be the weapon |
| Multi-Agent Social Engineering | MA | 7 | Social-engineer Agent A to compromise Agent B |
| Temporal & Persistent Attacks | TP | 7 | Plant words now that activate later |
| Cognitive Architecture Exploitation | CA | 8 | Break HOW the agent thinks, not what it knows |
| Exfiltration via Conversation | EX | 8 | Extract secrets through normal-looking dialogue |
| Supply Chain Language Attacks | SL | 8 | Poison the sources the agent trusts |

**Total: 45 new attacks across 6 surfaces**

These complement the existing 7 categories (189 attacks) by covering
dimensions that pure prompt injection testing misses -- the systemic,
temporal, multi-agent, and output-level risks that emerge when AI agents
operate in real-world environments.

---

## Implementation Priority

1. **Output Weaponization** -- Highest impact, least tested anywhere
2. **Supply Chain Language Attacks** -- Critical for coding agents (most Pentis users)
3. **Exfiltration via Conversation** -- Hardest to detect, most realistic threat
4. **Cognitive Architecture Exploitation** -- Unique to CoT/ReAct agents
5. **Multi-Agent Social Engineering** -- Growing rapidly with agentic frameworks
6. **Temporal & Persistent Attacks** -- Emerging as agents gain memory
