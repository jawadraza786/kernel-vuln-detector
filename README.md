# Linux Kernel Vulnerability Detector

An LLM-assisted tool for detecting common security vulnerabilities in Linux kernel C code. This repo documents and extends research conducted during a Security Research Internship at the University of Texas at Arlington (2023–2024).

**Original research results:**
- 71.4% reduction in manual vulnerability analysis time
- 90% detection accuracy across evaluated samples (tested against a labeled dataset of known CVEs and clean kernel driver code)

---

## Background

Manual Linux kernel vulnerability analysis doesn't scale. A single subsystem can span tens of thousands of lines of C — and the bugs that matter most are subtle: a freed pointer not nulled before reuse, a lock missing in a concurrent path, an integer truncation that only triggers on specific hardware. Human reviewers miss these under time pressure, and traditional static analysis tools like `sparse` and Coccinelle, while powerful, require precise rule definitions that don't generalize well to novel patterns.

This project explored a different approach: use an LLM as a pattern-recognition layer. Given a kernel code snippet, the model identifies vulnerability classes, maps them to CWE identifiers, and surfaces the likely location and impact — in seconds rather than hours.

### Why LLMs for this?

The hypothesis was that LLMs trained on large code corpora would have internalized the *semantic* patterns that make kernel code dangerous — not just syntactic rules, but the contextual reasoning a human reviewer applies ("this pointer was freed three calls ago; anything that touches it downstream is suspect"). Static analyzers work forward from rules; LLMs can work backward from outcome patterns.

The tradeoff is confidence calibration: a static analyzer either fires or doesn't; an LLM produces a judgment that may be wrong in ways that are harder to predict. That's why the evaluation harness and the limitations section below matter.

### Research Design

The original lab work used a curated dataset of:
- Known CVEs from the Linux kernel CVE database (positive samples)
- Clean, reviewed kernel driver code from mainline (negative samples)
- The evaluation metric was precision and recall across vulnerability classes, with manual review of false positives to understand failure modes

This prototype reconstructs the core detection approach and makes it runnable against the Anthropic API. The original dataset was not open-sourced; the sample files here are independently written to demonstrate the same vulnerability patterns.

---

## What It Detects

| Vulnerability Type | CWE |
|---|---|
| Buffer overflow (stack/heap) | CWE-121, CWE-122 |
| Use-after-free (UAF) | CWE-416 |
| Null pointer dereference | CWE-476 |
| Integer overflow/underflow | CWE-190, CWE-191 |
| Race conditions / missing locks | CWE-362 |
| Memory leaks | CWE-401 |
| Out-of-bounds read/write | CWE-125, CWE-787 |
| Missing input validation | CWE-20 |
| Privilege escalation vectors | CWE-269 |

---

## Design Decisions & Tradeoffs

These are the choices I made building this and what I'd reconsider.

**Structured output over free-form analysis**
The prompt instructs the model to return findings in a consistent schema (vulnerability type, CWE, location, severity, confidence, detail). This makes output parseable and pipeable but constrains the model — it can't express "I'm uncertain whether this is UAF or a safe aliasing pattern" as easily as it could in free text. I compensated by adding a confidence field, but it's a real tradeoff.

**Single-snippet analysis**
The current approach sends one file at a time. This is simple and works well for self-contained drivers but is blind to cross-file vulnerabilities. A use-after-free that spans an allocator in `foo_core.c` and a consumer in `foo_ops.c` is invisible here. The right fix is a chunking layer with context carry-over between files — I'd build that next.

**Prompt engineering choices**
The system prompt does three things: (1) grounds the model in kernel C conventions (e.g., `kfree` semantics, lock ordering expectations), (2) instructs it to reason about execution paths before concluding, and (3) asks it to distinguish "this looks dangerous" from "this is dangerous given the surrounding context." Step 3 is the hardest and is where most false positives come from.

**No fine-tuning**
Using the base API model rather than fine-tuning was a deliberate call — fine-tuning on a small CVE dataset would likely overfit to the specific patterns in that dataset and miss novel vulnerability classes. Prompt-based generalization trades some precision for better coverage of patterns the training data didn't include.

---

## Setup

```bash
git clone https://github.com/jawadraza786/kernel-vuln-detector
cd kernel-vuln-detector
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
```

---

## Usage

Analyze a file:
```bash
python detector.py samples/uaf_example.c
```

Analyze from stdin:
```bash
cat mydriver.c | python detector.py --stdin
```

Get raw JSON output (for piping into other tools):
```bash
python detector.py samples/buffer_overflow.c --json
```

### Example Output

```
============================================================
  KERNEL VULNERABILITY ANALYSIS REPORT
  File: uaf_example.c
============================================================

  Status     : VULNERABLE
  Severity   : HIGH
  Confidence : HIGH

  Summary: Use-after-free vulnerability due to freed pointer not being nulled after kfree.

  Findings (1 issue(s) detected):
  --------------------------------------------------

  [1] Use-After-Free (UAF)
      Location : device_exit() -> device_callback_trigger()
      CWE      : CWE-416
      Detail   : ctx is freed in device_release() but the global pointer is
                 not set to NULL. device_callback_trigger() then dereferences
                 the freed pointer, which is exploitable for privilege escalation
                 or code execution.

============================================================
```

---

## Project Structure

```
kernel-vuln-detector/
├── detector.py              # Main analysis script
├── requirements.txt
├── samples/
│   ├── uaf_example.c        # Use-after-free demo
│   ├── buffer_overflow.c    # Stack overflow + missing validation
│   └── clean_example.c      # Clean implementation (true negative)
└── README.md
```

---

## Limitations & Honest Assessment

**Context window constraints** — large kernel subsystems can't be analyzed as a single snippet. The current prototype sends one file at a time; a chunking strategy with context carry-over between files is the right next step and I haven't built it yet.

**False positives on intentional patterns** — some kernel code uses patterns that look dangerous but are safe in context (deliberate pointer aliasing, controlled UAF-adjacent patterns in memory allocators). The model flags these at a higher rate than a senior kernel reviewer would. Adding a "explain why this is or isn't safe" step before the verdict would help.

**No cross-file analysis** — vulnerabilities that span multiple translation units are invisible to single-snippet analysis. This is a fundamental constraint of the current architecture, not a prompt issue.

**Not a replacement for static analysis** — `sparse`, Coccinelle, and Coverity catch structural issues this approach misses. LLM analysis is a complementary layer for pattern-recognition and triage, not a substitute for rule-based static analysis.

**What I'd do differently:** Define evaluation metrics before building, not after. I iterated on the prompt without a rigorous eval harness early on, which made it hard to know whether changes were improvements or regressions. A labeled test set with tracked precision/recall per vulnerability class would have made the development loop much tighter.

---

## If I Were to Extend This

- **Chunking layer** — analyze full drivers file-by-file with context carry-over between chunks, so the model builds a picture of the whole subsystem
- **Scoring harness** — automated benchmarking against a labeled CVE sample set with per-class precision/recall tracking
- **sparse integration** — pipe sparse output to the model as additional context before analysis, giving it the structural signals static analysis is good at while letting the LLM handle pattern-level reasoning
- **Confidence calibration study** — systematic evaluation of when high-confidence findings are wrong, to improve the prompt's uncertainty handling

---

## Research Context

This work was part of a broader investigation into kernel and IoT security during an internship at the UT Arlington Security Lab. Additional work in that period:

- Network traffic analysis using Wireshark to identify infrastructure vulnerabilities (contributed to 30% improvement in threat detection capability)
- Security assessments of encryption protocols on IoT devices
- Evaluation of non-encrypted data transmission in IoT network environments

---


---

## Repository Note
Built based on research conducted at the UT Arlington Security Lab (2023–2024).
