# Security Scanning Framework

A framework that helps identify security vulnerabilities in web applications by combining static and dynamic analysis into a single unified report.

## What This Repo Does

It scans a target web application from two angles and brings the results together:

- **Static analysis (SAST)** looks at the source code without running it
- **Dynamic analysis (DAST)** interacts with the live running application
- **Aggregation** correlates findings from both into one report

## Requirements

Before getting started, make sure you have the following installed on your machine:

- Python 3.8 or higher
- Docker
- Go (required for some scanning tools)

## Installation

Install all dependencies by running:

```bash
bash setup.sh
```

This will install the required Python packages, Go-based tools, and pull the necessary Docker images.

Note: `setup.sh` only pre-pulls the ZAP image. The dynamic scan starts ZAP itself (see Notes below).

If you prefer to install Python packages manually:

```bash
pip install -r requirements.txt
```

## Running a Scan

**Full scan (static + dynamic + aggregated report):**

```bash
python3 run_scan.py --all ./DVWA
```

**Static analysis only:**

```bash
python3 run_scan.py --sast ./DVWA
```

**Dynamic analysis only:**

```bash
python3 run_scan.py --dast ./DVWA
```

## Output

After a scan completes, results are saved under the `output/` folder:

| File | Contents |
|------|----------|
| `sast_framework/output/normalized/normalized_results.json` | Static analysis findings |
| `dast_framework/output/` | Raw dynamic analysis results |
| `output/aggregated_report.json` | Combined report with correlated findings |

## Project Structure

```
.
├── sast_framework/       Static analysis tools and scanners
├── dast_framework/       Dynamic analysis tools and scanners
├── aggregator/           Combines SAST and DAST results
├── DVWA/                 Sample target application
├── output/               Scan results
├── tests/                Exploit replay and patch smoke test tooling
├── run_scan.py           Main entry point
├── setup.sh              Dependency installer
└── requirements.txt      Pinned Python dependencies
```

## Testing

The `tests/` folder contains the exploit replay and behavioural smoke test tooling used to validate patches:

- `exploit_replay.py` / `exploit_replay_l2.py` — replay exploits against the target to confirm a vulnerability is fixed (or still present), with logs written to `exploit_replay_logs/` and `exploit_replay_logs_l2/`
- `patch_tester.py` — runs the smoke test suite described in `DVWA_Patch_Behavioural_Smoke_Test.md`, comparing baseline vs. patched behaviour (`baseline.json`, `patched.json`, `results.csv`, `patch_tester.log`)

**Note:** these scripts were originally run from the project's main folder and were moved into `tests/` afterwards purely for a cleaner file structure. To re-run them, move the relevant script(s) back out of `tests/` into the main project folder before executing — running them directly from inside `tests/` will not work as-is.

## A note on regenerating patches

The cascade cells (9, 12, 15) and the ablation cell (20) call the repair model. Decoding is greedy, so generation is deterministic in principle, but the model is loaded in 4-bit NF4 quantisation and small numerical differences between GPUs, driver versions and library versions can change a token. Regenerated patches may therefore differ from the ones archived here. The archived patches are the reference artifact: they are what produced every reported classification, and the validation records in tests/ were computed against them.

## Notes

- Docker must be running before you start a dynamic scan
- The target application directory must contain a Dockerfile for dynamic scanning to work
- ZAP is started automatically by the dynamic scan (`dast_framework/core/docker_runner.py`) in a `zap-daemon` container on port 8081 with host networking, bound to `127.0.0.1` only, and removed afterwards by `dast_framework/core/cleanup.py`. Ports 8080 and 8081 must be free. Host networking requires a Linux Docker host; see `DVWA/README.md` for details.