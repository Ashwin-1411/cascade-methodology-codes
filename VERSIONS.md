# Tool and Environment Versions

This file records the exact versions of every tool, dataset, library, and runtime
component used in the study, for the replication package of manuscript jcp-4438912,
"A Controlled Experimental Methodology for Evaluating LLM-Based Vulnerability Repair
Using Cascaded Program Analysis Context." It corresponds to Table A24 of the manuscript.

Values marked with a dagger were not pinned at execution time. They were captured by
re-running the environment setup on 27 May 2026, are pinned in this package, and are
reported as reconstructed rather than as observed during the original experiments.

## Repair model

| Component | Role | Version |
|---|---|---|
| Qwen2.5-14B-Instruct | Repair generation, both arms | Qwen/Qwen2.5-14B-Instruct, revision cf98f3b3bbb457ad9e2bb7baf9a0125b6b88caa8 |
| Quantization | Model loading | 4-bit NF4, double quantization, fp16 compute |
| Inference hardware | Repair model; LLMxCPG-Q | NVIDIA A100 40 GB; NVIDIA H100 |
| transformers (dagger) | Inference stack | 5.16.1 |
| accelerate (dagger) | Inference stack | 1.14.0 |
| bitsandbytes (dagger) | Quantized loading | 0.50.2 |

## Static analysis

| Component | Role | Version |
|---|---|---|
| Semgrep | SAST and post-repair rescan, DVWA arm | 1.157.0 |
| Semgrep rulesets | p/php, p/owasp-top-ten, p/javascript | pulled 7 April 2026 |
| Flawfinder | SAST and post-repair rescan, Juliet arm | 2.0.19 |
| Enry | Language detection and routing | v1.3.0 |
| SpotBugs, Bandit | Configured for Java and Python routing | no findings used in either arm (see note) |

Note on SpotBugs and Bandit: both are part of the language-routing configuration but
contribute no findings to either evaluation. SpotBugs fires only on Java input, which
neither arm contains, so it never executes. Bandit fires on Python input; the Juliet arm
contains none, and in the DVWA arm the only Python file is a helper script outside the
vulnerability corpus (DVWA/tests/test_url.py), whose two findings are discarded by the
path filter before any repair prompt is built. No SpotBugs or Bandit finding reaches a
repair prompt.

## Dynamic analysis

| Component | Role | Version |
|---|---|---|
| OWASP ZAP | Crawling and active scanning | 2.17.0 |
| Nuclei | Template-based detection | 3.7.1, templates pulled 7 April 2026 |
| ffuf | Endpoint discovery | 2.1.0-dev |
| Dynamic scan date | DVWA arm | 8 April 2026 (prompt-input report dast_report_1775648770.json) |

Note on dynamic-scan provenance. The DAST evidence used in the repair prompts is the normalized report dast_report_1775648770.json (2026-04-08 11:46 UTC), committed in full; this is the exact, frozen DAST input to every DVWA prompt that contains DAST evidence (the L2 prompts and the nohint ablation arm; L0 and L1 prompts contain no DAST). The raw tool outputs also included (zap.json, nuclei.jsonl, ffuf.json) are from a later diagnostic re-run on 9 April 2026 (IST; 8 April 21:46–22:00 UTC) and are provided for reference only. Because active dynamic scanning is non-deterministic — crawl order, timing, and session state vary between runs — these raw outputs are not expected to match the committed report byte-for-byte; the normalized report, not any single raw run, is the reproducible artifact. Dynamic scanning was performed once per module at the low security level, so the three security-level variants of a module share the same runtime evidence.

## Target application, DVWA arm

| Component | Role | Version |
|---|---|---|
| DVWA | Application under test | ghcr.io/digininja/dvwa, digest sha256:ed35515e9111801e6e386a6fbb11165508cc7f72e0cb8da4dbb3df70182986c6 |
| PHP (container) | DVWA runtime | 8.5.10 |
| PHP (CLI) | php -l syntax gate | 8.5.10 |
| Apache | DVWA runtime | 2.4.68 |
| MySQL | DVWA database, DAST target | 8.0 |
| MariaDB | DVWA database, replay and smoke-test deployment | 10.11.18 |
| Docker | Container runtime | 29.5.1 |

## Juliet arm

| Component | Role | Version |
|---|---|---|
| Juliet Test Suite | Benchmark | 1.3 |
| GCC / G++ | Compilation and sanitizer instrumentation | 11.4.0 |
| Joern | CPG construction | v4.0.544 |
| LLMxCPG-Q | CPGQL query generation | QCRI/LLMxCPG-Q, revision 1f48ab60420d90277207394f1254d27d3375b07e |
