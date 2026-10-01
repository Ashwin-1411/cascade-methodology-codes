# DVWA Arm: LLM Vulnerability Repair under Cascaded Program-Analysis Context

This directory contains the DVWA evaluation arm of the study described in manuscript
jcp-4438912, "A Controlled Experimental Methodology for Evaluating LLM-Based
Vulnerability Repair Using Cascaded Program Analysis Context." It holds the scanning
framework that produces the static and dynamic analysis context, the selected
vulnerable files, the model-generated patches, the validation harnesses, and the
notebook that performs repair generation, classification, post-hoc validation, and
provenance export.

For the rationale behind the design, the context-level definitions, and the full
results discussion, see Section 6 of the manuscript. This README documents the
layout and how to reproduce the artifacts, not the methodology itself.

## Overview

The notebook loads 54 vulnerable PHP files: the low, medium, and high implementations
of 18 DVWA modules (`dvwa_selected_v2/<module>/source/{low,medium,high}.php`). One
file, `api_high`, is excluded after the run by manual review (a static informational
page with no user input; CELL 18), which leaves 53 evaluated files. This is the
denominator recorded in `dasttt/dvwa_v3_l2_results/final_summary.json`.

The DVWA `impossible.php` implementations are kept in `dvwa_selected_v2/` but are not
loaded as cases (CELL 6). They serve as the reference during manual review. They are
not excluded from scanning: the SAST pass covers the whole DVWA tree, and
`sast_normalized.json` contains findings for `exec/source/impossible.php`.

Repair is evaluated under three cumulative context levels:

- L0: raw vulnerable source only.
- L1: source, SAST findings, and application context where defined.
- L2: source, SAST and DAST findings, application context, and repair guidance where defined.

Each level is applied only to the cases that were not a Correct Fix at the previous
level (CELL 11 and CELL 14). The archived run escalated 17 cases to L1 and 11 to L2.

The model is `Qwen/Qwen2.5-14B-Instruct`. It is loaded in 4-bit NF4 quantization with
double quantization and fp16 compute (CELL 3) and decoded greedily with a budget of
4096 new tokens (CELL 8). Each patch is classified as CFR, PIR, or IFR by
`classify_dvwa()` (CELL 7). Post-hoc validation (CELLS 18 and 19) then corrects that
classification using manual review, exploit replay, functional smoke tests, and
target-weakness checks. The validated classification is the one reported in the
manuscript.

## Repository layout

```
DVWA/
  README.md                       This file
  dvwa_automated_pipeline.ipynb   Builds prompts, calls the model, classifies, validates, exports provenance

  DVWA_arm/                       Scanning framework that generates the SAST and DAST context
    DVWA/                         DVWA application source under analysis (with its Dockerfile and compose.yml)
    sast_framework/               enry language detection and SAST runners (Semgrep, Bandit, Flawfinder, SpotBugs)
      output/raw/raw_results.json               Raw scanner output (Bandit and Semgrep keys)
      output/normalized/normalized_results.json Normalized SAST findings (38)
      spotbugs_home/spotbugs-4.8.6/             Bundled SpotBugs distribution
    dast_framework/               Dynamic scanning of the running application (ffuf, OWASP ZAP, Nuclei)
      output/reports/dast_report_1775648770.json  Merged DAST report used as prompt input
      output/zap.json, nuclei.jsonl, ffuf.json*   Raw tool outputs from a later scan run (see below)
      wordlists/                  ffuf wordlists (common.txt, dvwa_paths.txt)
    aggregator/                   Correlates SAST and DAST findings by CWE and path
    output/aggregated_report.json Aggregator output (115 findings, 13 correlated); not used as prompt input
    tests/                        Exploit replay and behavioural smoke-test harnesses, their logs and results
    run_scan.py                   Entry point for the scanning pipeline (--sast, --dast, --all)
    setup.sh                      Dependency installer
    requirements.txt              Python package pins and notes on Go tools and Docker images
    dvwa_ground_truth.json        URL and alert-name lists of known true and false positives at security=low
    README.md                     Scanning-framework documentation

  dasttt/                         Inputs and outputs of the notebook
    dvwa_selected_v2/             18 modules: low/medium/high.php (54 cases) plus impossible.php references
    sast_normalized.json          SAST findings read by CELL 4
    dast_report.json              DAST findings read by CELL 5
    dvwa_v3_l0_outputs/           L0 patches (54 files)
    dvwa_v3_l1_outputs/           L1 patches (17 files)
    dvwa_v3_l2_outputs/           L2 patches (11 files)
    dvwa_v3_l2_outputs_ablate_nodast/open_redirect/   Ablation arm: guidance kept, DAST removed (3 files)
    dvwa_v3_l2_outputs_ablate_nohint/open_redirect/   Ablation arm: DAST kept, guidance removed (3 files)
    dvwa_v3_l0_results/           l0_progress.json, l0_results.json, l0_results_validated.json
    dvwa_v3_l1_results/           l1_progress.json, l1_results.json
    dvwa_v3_l2_results/           l2_progress.json, l2_results.json, l2_results_validated.json,
                                  ablation_results.json, final_summary.json, oracle_provenance.{csv,json}
```

The notebook is at `DVWA/dvwa_automated_pipeline.ipynb`, not inside `dasttt/`. It
reads and writes everything under a single root, `REPO_ROOT` in CELL 2, which must
point to `DVWA/dasttt/`.

`dvwa_selected_v2/javascript/source/` also contains `medium.js` and
`high_unobfuscated.js`. CELL 6 loads only `*.php`, so the model never sees these files.

## Context and tool selection

Static analysis. `sast_framework/core/orchestrator.py` detects languages with enry and
runs a scanner for each detected language. It always runs Semgrep, using the rulesets
`p/php`, `p/owasp-top-ten`, and `p/javascript` (`scanners/semgrep_scanner.py`). For
DVWA, enry also detected Python (`DVWA/tests/test_url.py`), so Bandit ran as well.
`sast_normalized.json` holds 36 Semgrep findings and 2 Bandit findings. CELL 4 keeps
only findings whose path contains `vulnerabilities/`, so only Semgrep findings on PHP
files reach the prompts. Flawfinder and SpotBugs are part of the framework, but the
archived raw output contains no results from them.

Dynamic analysis (`dast_framework/`). The DAST tools do not run inside the DVWA
container:

- `core/docker_runner.py` builds DVWA from `DVWA_arm/DVWA/Dockerfile`, falling back to
  `ghcr.io/digininja/dvwa:latest` if the build fails. It runs DVWA as container
  `dast-target-container` with a `mysql:8.0` container on the Docker network
  `dast-scan-net` and publishes DVWA on host port 8080. DVWA is started with
  `DEFAULT_SECURITY_LEVEL=low`.
- ffuf runs on the host against `http://localhost:8080`.
- Nuclei runs in its own `projectdiscovery/nuclei` container on `dast-scan-net` and
  targets `http://dast-target-container:80`.
- OWASP ZAP runs in its own container, `zap-daemon`. `core/docker_runner.py`
  (`_start_zap()`) starts it after DVWA is up, from `ghcr.io/zaproxy/zaproxy:stable`,
  in daemon mode on port 8081 with host networking (`--network host`) and the API key
  set in `scanners/zap_scanner.py`. Host networking lets ZAP reach DVWA at
  `http://localhost:8080`. ZAP is bound to `-host 127.0.0.1`, so its proxy and API
  listen on the loopback interface only and are not reachable from other machines.
  The scanner uses `http://127.0.0.1:8081` for both the API and the proxy. It logs
  into DVWA, sets the security level to low, seeds the module URLs through the ZAP
  proxy, and runs an injection-focused active-scan policy. If ZAP does not answer
  within about 200 seconds, `build_and_run()` raises an error and the DAST step stops
  rather than continuing without ZAP results. `core/cleanup.py` removes the ZAP, DVWA,
  and MySQL containers after the scan.

The automatic ZAP start was added to the framework after the archived scan. How ZAP
was started for the archived run (`dast_report_1775648770.json`) is not recorded.

DAST therefore ran against DVWA at security level low only. CELL 5 indexes DAST
findings by module folder, so all three security levels of a module receive the same
DAST evidence.

Prompt inputs. The prompts are built from `dasttt/sast_normalized.json` and
`dasttt/dast_report.json`:

- `dast_report.json` is byte-identical to
  `DVWA_arm/dast_framework/output/reports/dast_report_1775648770.json`.
- `sast_normalized.json` matches
  `DVWA_arm/sast_framework/output/normalized/normalized_results.json` except for the
  absolute home-directory prefix in the file paths.

No script copies these files into `dasttt/`. The aggregator output
(`DVWA_arm/output/aggregated_report.json`) is not used as prompt input.

Dynamic-scan provenance. The report `dast_report_1775648770.json` (2026-04-08 11:46 UTC)
is the exact, frozen DAST input to every prompt that contains DAST evidence (the L2
prompts and the `nohint` ablation arm; L0 and L1 prompts contain no DAST) and is
committed in full. The raw tool outputs also kept in the repository (`zap.json`,
`nuclei.jsonl`, `ffuf.json`) are from a later diagnostic re-run on 9 April 2026 (IST;
8 April 21:46–22:00 UTC) and are provided for reference only. Active dynamic
scanning is non-deterministic, as crawl order, timing, and session state vary between runs,
so these raw outputs are not expected to match the committed report exactly; the normalised
report, not any single raw run, is the reproducible artifact.

CELL 2 defines the application context (`VULN_FRONTEND_CONTEXT`, used at L1 and L2)
and the repair guidance (`VULN_L2_HINTS`, used at L2 only). Per-case keys take
priority over module keys.

## Outcome metrics

The classifier is `classify_dvwa()` in CELL 7:

- IFR (Invalid Fix): the output is empty, identical to the original, or shorter than
  30% of the original (Stage 0), or it fails `php -l` (Stage 1).
- CFR (Correct Fix): the patch passes lint, the target CWE is judged resolved, and no
  new CWE appears in a Semgrep rescan. The target CWE is judged resolved in one of
  three ways, tagged in the `reason` string:
  - `[semgrep]`: Semgrep flags the CWE in the original but not in the patch.
  - `[pattern:<module>]`: a custom structural verifier is used, because Semgrep does
    not flag the CWE in the original.
  - `[semgrep_blind_unverified]`: the default when neither check applies.
- PIR (Plausible but Incorrect Repair): the patch passes lint but introduces a new CWE
  or leaves the target CWE unresolved.

The Semgrep rescan in CELL 7 uses only `p/php`. If `php` is not installed,
`php_syntax_ok()` returns success and lint is skipped. CELL 1 installs `php-cli` to
avoid this.

Each table states the denominator it uses. The automated classification (`*_results.json`)
and the validated classification (`*_results_validated.json`, `final_summary.json`) are
reported separately; the validated figure is the headline result. In the
`*_results_validated.json` files only `cases` is corrected. The `summary` block is
copied unchanged from the automated file. Use `cases` or `final_summary.json` for
validated counts.

Validated counts in the archived `final_summary.json`:

- L0: 24 CFR, 28 PIR, 1 IFR (N = 53).
- L1: 6 CFR, 11 PIR (N = 17).
- L2: 9 CFR, 1 PIR, 1 IFR (N = 11).
- Cumulative CFR after L0, L1, and L2: 24, 30, and 39 of 53.

The validation reclassified thirteen CFR labels to PIR: twelve at L0 and one at L2.
(Separately, `api_high` was dropped from the dataset entirely, reducing 54 candidate
files to 53; see the Overview.) The twelve L0 reclassifications were established after the
cascade had run, so those cases were never escalated and are listed under
`not_escalated_after_reclassification`; CELL 19 notes that the corrected cumulative rate
is therefore a lower bound. Table 13 of the manuscript lists the thirteen reclassified
cases.

## Reproducing the artifacts

### Scanning and context generation (in `DVWA_arm/`)

The installation and scan commands are documented in
[DVWA_arm/README.md](DVWA_arm/README.md): `bash setup.sh`, then
`python3 run_scan.py --all ./DVWA`. Points that README does not cover:

1. Docker must be running, and ports 8080 (DVWA) and 8081 (ZAP) must be free. The
   DAST step starts and removes ZAP itself (see Context and tool selection), so no
   separate ZAP command is needed. Because ZAP uses `--network host`, the DAST step
   works as written only on a Linux Docker host; Docker Desktop on Windows and macOS
   does not enable host networking by default.
2. `run_scan.py --all` writes `sast_framework/output/normalized/normalized_results.json`,
   `dast_framework/output/reports/dast_report_<unix-time>.json`, and
   `output/aggregated_report.json`.
3. To use a new scan as prompt input, copy the normalized SAST file to
   `dasttt/sast_normalized.json` and the DAST report to `dasttt/dast_report.json`.
4. `setup.sh` and the DAST code use unpinned tool versions (ffuf `@latest`,
   `zaproxy:stable` in both `setup.sh` and `docker_runner.py`, the untagged
   `projectdiscovery/nuclei` image), whereas the archived `zap.json` reports ZAP 2.17.0. A new scan may therefore differ from the
   archived one. See the versions section below.

### Repair generation and evaluation (`dvwa_automated_pipeline.ipynb`)

The notebook was written for Google Colab. CELL 1 installs `transformers`,
`accelerate`, `bitsandbytes`, and `semgrep` with pip, installs `php-cli` with
`apt-get`, and mounts Google Drive. Outside Colab, install these packages by other
means and skip the Drive mount. In CELL 2, set `REPO_ROOT` to the local `DVWA/dasttt/`
path. CELL 2 imports `torch` and `transformers` even when no model is loaded.

Cells are referred to by the `CELL n` label on their first line, not by their position
in the notebook.

Path A: reproduce the reported numbers from the archived outputs. This needs no GPU,
no model, and no re-scan. It is the minimal order given in the notebook's first cell.

1. CELL 1 (or an equivalent installation), CELL 2, CELL 7.
2. CELL 18, which records the validation verdicts.
3. CELL 19, which applies the verdicts and writes `l0_results_validated.json` and
   `l2_results_validated.json`.
4. CELL 23, which computes Wilson intervals and writes `final_summary.json`.
5. CELL 24, which writes `oracle_provenance.csv` and `oracle_provenance.json`.

Path B: full cascade (GPU required at CELLS 3, 9, 12, 15, and 20).

1. CELLS 1 to 8: setup, model load, SAST and DAST indexing, case loading, classifier,
   and prompt builders.
2. CELLS 9 and 10: L0 generation and evaluation.
3. CELLS 11, 12, and 13: L1 case list, generation, and evaluation.
4. CELLS 14, 15, and 16: L2 case list, generation, and evaluation.
5. CELL 17: cross-level summary, printed only.
6. CELLS 18 and 19: validation.
7. CELLS 20 and 21: ablation generation and evaluation.
8. CELL 22: L2 attribution, printed only.
9. CELLS 23 and 24: export.

Cold-kernel and overwrite notes:

- CELLS 9, 12, and 15 resume from `l{0,1,2}_progress.json`. The archived progress files
  list every case, so these cells skip all cases. To regenerate, move the progress
  files and the corresponding output folder aside first.
- CELLS 10, 13, and 16 re-run Semgrep and `php -l`. They overwrite `l{0,1,2}_results.json`
  with a new timestamp, and their results can change with the Semgrep rule version.
  Skip them to keep the archived automated results.
- CELL 20 writes the six ablation patches without any resume check, so it overwrites
  the archived files in `dvwa_v3_l2_outputs_ablate_*`. It also needs `L2_CASES`
  (CELLS 4, 5, 6, and 14) and the loaded model (CELL 3).
- On a kernel where CELL 20 has not run, CELL 21 fails because `_abl_cases` and
  `ABLATE_DIRS` are not defined. CELL 22 fails too: it needs `_l2_by` from CELL 21 and
  `L2_CASES` from CELL 14. As written, `ablation_results.json` and the L2 attribution
  table cannot be regenerated without running CELL 20.
- CELL 17 needs `ALL_CASES` from CELL 6.
- Path A does not run any of the cells listed in these notes.

### Exploit replay and smoke tests (in `DVWA_arm/tests/`)

The harnesses and their run notes are described in [DVWA_arm/README.md](DVWA_arm/README.md).
They are separate from the DAST deployment: they use `DVWA_arm/DVWA/compose.yml`
(`127.0.0.1:4280`, a `mariadb:10` database). Their path constants expect
`dvwa_selected_v2/dvwa_selected_v2/` and `dvwa_v3_l{0,2}_outputs/dvwa_v3_l{0,2}_outputs/`
next to the script, so these must be pointed at the folders in `dasttt/`.

The notebook does not read the harness outputs. CELL 18 records their verdicts as
literal dictionaries:

- `EXPLOIT_REPLAY` corresponds to `tests/exploit_replay.csv`: 21 L0 cases, 17
  MITIGATED and 4 STILL_EXPLOITABLE.
- `EXPLOIT_REPLAY_L2` corresponds to `tests/l2_exploit_replay.json`: 4 L2 cases, run
  2026-09-07, all MITIGATED.
- `SMOKE_BROKEN` and `SMOKE_INCONCLUSIVE` correspond to `tests/results.csv` (82 rows,
  produced by `patch_tester.py`).

## Software and dataset versions

### Recorded in this directory

Notebook (`dvwa_automated_pipeline.ipynb`):

- Model: `Qwen/Qwen2.5-14B-Instruct`. No revision is pinned in `from_pretrained`.
- Quantization: 4-bit NF4, double quantization, fp16 compute dtype.
- `transformers`, `accelerate`, `bitsandbytes`, and `semgrep` are installed unpinned.
  `php-cli` comes from the Colab image's apt repository, and its version is not recorded.
- Notebook metadata: Colab GPU type T4, `language_info` Python 3.10.0. The comment in
  CELL 3 reads "T4 / A100".
- The Semgrep rescan uses the registry ruleset `p/php`, fetched at run time.

Scanning framework (`DVWA_arm/requirements.txt`):

- Pinned Python packages: `semgrep==1.157.0`, `flawfinder==2.0.19`, `bandit==1.9.4`,
  `requests==2.32.5`, `zaproxy==0.6.0`, `nuclei==0.1.0`, `docker==7.2.0`.
- Commented notes, not installed by `setup.sh` at these versions: enry v1.3.0, ffuf
  v2.1.0, `ghcr.io/zaproxy/zaproxy:2.17.0`, `projectdiscovery/nuclei:v3.7.1`,
  `php:8.5.10-apache`, `mariadb:10`, and a truncated DVWA digest
  `ghcr.io/digininja/dvwa@sha256:ed35515e986c6` marked "replace with full digest".
- SpotBugs 4.8.6 is bundled under `sast_framework/spotbugs_home/`.
- `DVWA_arm/DVWA/Dockerfile` builds from `php:8-apache`. `compose.yml` and the
  `docker_runner.py` fallback both use `ghcr.io/digininja/dvwa:latest`. The DAST run
  used `mysql:8.0` (`docker_runner.py`); the replay and smoke-test deployment uses
  `mariadb:10` (`compose.yml`).

Scan outputs:

- `dast_framework/output/zap.json` reports ZAP 2.17.0. No Nuclei or ffuf version is
  recorded in the outputs.
- The prompt-input DAST report `dast_report_1775648770.json` carries Unix time
  1775648770, which is 2026-04-08 11:46 UTC.
- The raw outputs `zap.json`, `nuclei.jsonl`, and `ffuf.json.*.json` come from a later
  run, stamped from 2026-04-08 21:46 UTC (ffuf, recorded as 2026-04-09 03:16 +05:30)
  to 22:00 UTC (last Nuclei finding); ZAP's report is stamped 21:52 UTC. They
  differ from the report:
  - ZAP: 39 distinct alert and CWE pairs in `zap.json`, against 42 in the report.
  - Nuclei: 4 findings in `nuclei.jsonl`, against 16 in the report.
- Timestamps inside the result files:
  - Automated result files (`l0_results.json`, `l1_results.json`, `l2_results.json`):
    2026-05-23 UTC.
  - L2 exploit replay: 2026-09-07.

### Recorded in VERSIONS.md and the manuscript, not in the DVWA/ code files

The following values are authoritative in the repository-root `VERSIONS.md` and in
Appendix Table A24 of the manuscript. They are not independently duplicated in the
`DVWA/` code files (the scanning framework pins some in `requirements.txt`; the rest
were reconstructed for the versions table), so for traceability they are listed here
with VERSIONS.md as the single source:

- Model revision `cf98f3b3bbb457ad9e2bb7baf9a0125b6b88caa8`.
- `transformers` 5.16.1, `accelerate` 1.14.0, `bitsandbytes` 0.50.2.
- Inference hardware NVIDIA A100 40 GB and H100.
- Semgrep and Nuclei template pull dates (7 April 2026).
- ffuf "2.1.0-dev".
- PHP 8.5.10 as the container runtime and `php -l` gate.
- Apache 2.4.68, MariaDB 10.11.18, Docker 29.5.1.
- The full DVWA image digest.
- An environment reconstruction on 27 May 2026.

The repository-root `VERSIONS.md` is the single source for these values and carries the
full DVWA image digest. The dynamic scan date is 8 April 2026, the timestamp of the
prompt-input report; the raw tool outputs are a later re-run on 9 April 2026 (IST;
8 April 21:46–22:00 UTC; see Dynamic-scan provenance above).

## Mapping from the manuscript to this directory

Each DVWA table and figure is listed with the notebook cell or file in this repository
that produces it. The item numbers follow the manuscript's Section 6; the producing cell
or file is what can be checked here.

| Manuscript item | Produced by |
|---|---|
| Table 14 (cumulative cascade) | Validated: CELL 19 (cumulative counts) and CELL 23 (Wilson 95% intervals), saved to `dasttt/dvwa_v3_l2_results/final_summary.json`. As-run automated: CELL 17 (printed only, not saved). |
| Tables 15 to 17 (per-level results) | Automated: CELL 10, CELL 13, and CELL 16, saved to `dvwa_v3_l{0,1,2}_results/l{0,1,2}_results.json`. Validated: CELL 19, saved to `l0_results_validated.json` and `l2_results_validated.json`. CELL 19 writes no L1 validated file; the validated L1 counts equal the automated ones. The corrected L0 per-module table is printed by CELL 19. |
| Tables 18 and 19 (L2 attribution and ablation) | Attribution: CELL 22 (printed only). Ablation 2x2: CELL 20 generates `dvwa_v3_l2_outputs_ablate_{nodast,nohint}/`; CELL 21 classifies them and saves `dvwa_v3_l2_results/ablation_results.json`. Conditions A and D are taken from the validated L1 and L2 labels. |
| Table 20 (oracle provenance by level) | CELL 24, printed table "Oracle provenance of the validated correct fixes". The per-case data is in `dvwa_v3_l2_results/oracle_provenance.{csv,json}` (81 rows: 53 L0, 17 L1, 11 L2). |
| Per-module oracle-provenance table | Built from `dvwa_v3_l2_results/oracle_provenance.csv`: the `module`, `oracle`, and `independent_of_prompt` columns give each module's deciding oracle and whether it is independent of the prompt. CELL 24 also prints which modules' correct fixes rest only on conformity checks or on no oracle. |
| Figure 7 (SAST and DAST pipeline) | `DVWA_arm/` framework (`run_scan.py`, `sast_framework/`, `dast_framework/`, `aggregator/`). |
| Figure 8 (DVWA cascade) | `generate_sankey.py` at the repository root (outside `DVWA/`). |

## Validation oracles

CELL 24 attributes every label to the oracle that decided it. IFR labels are
attributed to the pre-check or the lint gate. For the other labels the precedence is:

1. Exploit replay against the running application.
2. Target-weakness check.
3. Independent manual review against the DVWA reference implementation.
4. A Semgrep finding present before patching and absent after.
5. A custom structural verifier.
6. No oracle.

A structural verifier counts as independent only when its checked property was not
given to the model as application context or repair guidance. Labels decided by a
verifier whose property was in the prompt record conformance to a specified repair
pattern rather than independent elimination of the weakness. The archived
`oracle_provenance.csv` attributes the 39 validated correct fixes as follows: 20
exploit replay, 1 manual review, 7 independent verifier, and 11 conformity verifier.
Column `oracle` gives the per-case basis and column `independent_of_prompt` gives the
independence flag.

## Citation and license

See the repository root for the citation, the DOI, and the license files.