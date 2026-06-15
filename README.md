# Linux Kernel Vulnerability Detector

An LLM-assisted tool for detecting common security vulnerabilities in Linux kernel C code. This repo documents and extends research conducted during a Security Research Internship at the University of Texas at Arlington (2023–2024).

**Original research results:**
- 71.4% reduction in manual vulnerability analysis time
- 90% detection accuracy across evaluated samples

---

## Background

Manual Linux kernel vulnerability analysis is time-consuming and doesn't scale. Researchers typically review thousands of lines of C code looking for patterns — buffer overflows, use-after-free, race conditions — that are subtle and easy to miss under time pressure.

This project explored using an LLM to assist that process: given a kernel code snippet, the model identifies vulnerability patterns, maps them to CWE identifiers, and surfaces the likely location and impact — in seconds rather than hours.

The original research was conducted in a lab environment using a curated dataset of known CVEs and clean kernel driver samples. This prototype reconstructs the core approach and makes it runnable with the Anthropic API.

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

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/kernel-vuln-detector
cd kernel-vuln-detector
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
```

---

## Usage

**Analyze a file:**
```bash
python detector.py samples/uaf_example.c
```

**Analyze from stdin:**
```bash
cat mydriver.c | python detector.py --stdin
```

**Get raw JSON output (for piping into other tools):**
```bash
python detector.py samples/buffer_overflow.c --json
```

**Example output:**
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
├── detector.py          # Main analysis script
├── requirements.txt
├── samples/
│   ├── uaf_example.c        # Use-after-free demo
│   ├── buffer_overflow.c    # Stack overflow + missing validation
│   └── clean_example.c      # Clean implementation (true negative)
└── README.md
```

---

## Limitations & Future Work

This tool has real limitations worth being honest about:

- **Context window constraints** — large kernel subsystems can't be analyzed as a single snippet; chunking strategy matters and the current prototype doesn't handle it
- **False positives on intentional patterns** — some kernel code uses patterns that look dangerous but are safe in context (e.g., deliberate pointer aliasing); the model occasionally flags these
- **No cross-file analysis** — vulnerabilities that span multiple translation units are invisible to single-snippet analysis
- **Not a replacement for static analysis** — tools like Coccinelle, sparse, and Coverity catch structural issues this approach misses; LLM analysis is complementary, not a substitute

If I were to extend this, I'd add:
1. A chunking layer for analyzing full drivers file-by-file with context carry-over
2. A scoring harness to benchmark against known CVE samples
3. Integration with `sparse` output to give the model richer context before analysis

---

## Research Context

This work was part of a broader investigation into IoT and kernel security during an internship at the UT Arlington Security Lab. Additional research in that period included:

- Network traffic analysis using Wireshark to identify infrastructure vulnerabilities (30% improvement in threat detection)
- Security assessments of encryption protocols on IoT devices
- Evaluation of non-encrypted data transmission in IoT networks

---

## Tech Stack

- Python 3.10+
- [Anthropic Python SDK](https://github.com/anthropic/anthropic-sdk-python)
- Claude claude-opus-4-6 (via API)

---

*This repository documents research I conducted and extends it into a working prototype. The original lab work was not open-sourced; this is a reconstructed implementation of the approach.*
