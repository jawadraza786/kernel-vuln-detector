"""
Linux Kernel Vulnerability Detector
Reconstructed from research conducted at UT Arlington Security Lab (2023-2024)

Original research achieved:
  - 71.4% reduction in manual analysis time
  - 90% detection accuracy across test samples

This prototype demonstrates the LLM-assisted approach for identifying
common vulnerability patterns in Linux kernel C code.
"""

import anthropic
import argparse
import json
import sys
from pathlib import Path


SYSTEM_PROMPT = """You are a Linux kernel security analyst specializing in vulnerability detection.

When given a C code snippet, analyze it for common Linux kernel vulnerabilities including:

- Buffer overflows (stack/heap)
- Use-after-free (UAF)
- Null pointer dereferences
- Integer overflows/underflows
- Race conditions (missing locks, TOCTOU)
- Memory leaks
- Improper input validation
- Privilege escalation vectors
- Out-of-bounds reads/writes

Respond ONLY with a JSON object in this exact format:
{
  "vulnerable": true or false,
  "severity": "critical" | "high" | "medium" | "low" | "none",
  "vulnerabilities": [
    {
      "type": "vulnerability type",
      "line_hint": "approximate line or function where issue occurs",
      "description": "clear explanation of the issue",
      "cwe": "CWE-XXX if applicable"
    }
  ],
  "summary": "one sentence summary of findings",
  "confidence": "high" | "medium" | "low"
}

If no vulnerabilities are found, return vulnerable: false, severity: none, and an empty vulnerabilities array.
Do not include any text outside the JSON object."""


def analyze_code(code: str, verbose: bool = False) -> dict:
    """
    Send code snippet to Claude for vulnerability analysis.
    Returns parsed JSON result.
    """
    client = anthropic.Anthropic()

    if verbose:
        print("[*] Sending code to Claude for analysis...")

    message = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze this Linux kernel code for vulnerabilities:\n\n```c\n{code}\n```"
            }
        ]
    )

    raw = message.content[0].text.strip()

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        result = {
            "vulnerable": None,
            "severity": "unknown",
            "vulnerabilities": [],
            "summary": "Parse error — raw model output returned",
            "confidence": "low",
            "raw": raw
        }

    return result


def format_report(result: dict, filename: str = "stdin") -> str:
    """Format analysis result as a human-readable report."""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"  KERNEL VULNERABILITY ANALYSIS REPORT")
    lines.append(f"  File: {filename}")
    lines.append(f"{'='*60}")

    status = "VULNERABLE" if result.get("vulnerable") else "CLEAN"
    severity = result.get("severity", "unknown").upper()
    confidence = result.get("confidence", "unknown").upper()

    lines.append(f"\n  Status     : {status}")
    lines.append(f"  Severity   : {severity}")
    lines.append(f"  Confidence : {confidence}")
    lines.append(f"\n  Summary: {result.get('summary', 'N/A')}")

    vulns = result.get("vulnerabilities", [])
    if vulns:
        lines.append(f"\n  Findings ({len(vulns)} issue(s) detected):")
        lines.append(f"  {'-'*50}")
        for i, v in enumerate(vulns, 1):
            lines.append(f"\n  [{i}] {v.get('type', 'Unknown')}")
            lines.append(f"      Location : {v.get('line_hint', 'N/A')}")
            lines.append(f"      CWE      : {v.get('cwe', 'N/A')}")
            lines.append(f"      Detail   : {v.get('description', 'N/A')}")
    else:
        lines.append("\n  No vulnerabilities detected.")

    lines.append(f"\n{'='*60}\n")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-assisted Linux kernel vulnerability detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detector.py samples/uaf_example.c
  python detector.py samples/buffer_overflow.c --json
  cat mydriver.c | python detector.py --stdin
        """
    )
    parser.add_argument("file", nargs="?", help="C source file to analyze")
    parser.add_argument("--stdin", action="store_true", help="Read code from stdin")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted report")
    parser.add_argument("--verbose", action="store_true", help="Show analysis progress")

    args = parser.parse_args()

    if args.stdin:
        code = sys.stdin.read()
        filename = "stdin"
    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        code = path.read_text()
        filename = path.name
    else:
        parser.print_help()
        sys.exit(1)

    result = analyze_code(code, verbose=args.verbose)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_report(result, filename))

    sys.exit(1 if result.get("vulnerable") else 0)


if __name__ == "__main__":
    main()
