# patch_tester.py – DVWA Patch Regression Harness

Checks whether each LLM-generated patched PHP file preserves normal page
behaviour in the live DVWA application.

## Quick start

```bash
pip install requests          # only stdlib + requests needed
python patch_tester.py        # starts Docker, runs full test suite
python patch_tester.py --skip-docker   # if DVWA is already running
```

## What it does

### 1 – Docker startup & readiness
Runs `docker compose up -d` in `DVWA/`, then polls `GET /login.php` until HTTP
200 is returned (up to 120 s).

### 2 – Database initialisation
POSTs to `/setup.php` with `create_db=Create / Reset Database` to ensure the
schema and seed data exist.

### 3 – Login
GETs `/login.php`, extracts the CSRF `user_token`, then POSTs
`username=admin&password=password`.  The `PHPSESSID` cookie is captured and
reused for all subsequent requests.

### 4 – Baseline
For every unique `(module, level)` pair found across the three output
directories, the unmodified DVWA is probed once (see probe table below).
Results are written to **`baseline.json`**.

### 5 – Patched
For each patched file:
1. The original source file is copied **out** of the container with `docker cp`.
2. The patched file is copied **in** with `docker cp`.
3. The module is probed at the corresponding security level.
4. The original is restored unconditionally (even if the probe fails).

Results are written to **`patched.json`**.

### 6 – Results
**`results.csv`** columns:

| column | meaning |
|--------|---------|
| layer | l0 / l1 / l2 – which output directory |
| module | DVWA vulnerability module name |
| level | low / medium / high |
| baseline_status | HTTP status of baseline probe |
| patched_status | HTTP status of patched probe |
| baseline_length | response body length (bytes) |
| patched_length | response body length (bytes) |
| baseline_has_error | True if PHP error pattern found in baseline |
| patched_has_error | True if PHP error pattern found in patched |
| new_error_introduced | True only when patched has error and baseline did not |
| verdict | PASS / BROKEN / INCONCLUSIVE |

Verdict logic:
- **PASS** – same HTTP status, no new PHP error.
- **BROKEN** – patch introduced a PHP error, returned HTTP 500, or changed the
  HTTP status code.
- **INCONCLUSIVE** – the baseline itself had an error (cannot attribute fault
  to the patch).

All HTTP requests and response codes are logged to **`patch_tester.log`**.

## Module probe strategy

Each probe is designed to trigger normal rendering of the page (i.e. cause the
source file to execute) without exploiting the vulnerability.  The security
level is set via the `security` cookie.

| module | method | key parameters | rationale |
|--------|--------|---------------|-----------|
| sqli | GET | id=1, Submit=Submit | triggers the DB query |
| sqli_blind | GET | id=1, Submit=Submit | triggers boolean query |
| exec | POST | ip=127.0.0.1, Submit=Submit | runs ping command |
| xss_r | GET | name=probe | benign reflection |
| xss_s | POST | txtName=probe, mtxMessage=probe message, btnSign=Sign+Guestbook | exercises INSERT |
| xss_d | GET | default=English | factory default; avoids JS redirect |
| fi | GET | page=include.php | safe default; exercises include() |
| open_redirect | GET | redirect=/ | local path; 302 followed harmlessly |
| weak_id | GET | Generate=Generate | triggers session-ID generation |
| brute | GET | username=admin, password=password, Login=Login | exercises auth query |
| captcha | POST | step=1, password_new/conf=Passw0rd!, Change=Change | step-1 validation |
| csrf | GET | (none) | loads form |
| upload | GET | (none) | loads form |
| api | GET | id=1 | DB look-up |
| authbypass | GET | (none) | loads page |
| bac | GET | (none) | loads page |
| csp | POST | include=https://pastebin.com, Include=Include | nonce generation |
| javascript | GET | token=XXX, phrase=success, send=Submit | validation branch |

## Output files

| file | contents |
|------|---------|
| baseline.json | per module/level baseline probe results |
| patched.json | per layer/module/level patched probe results |
| results.csv | combined per-patch verdicts |
| patch_tester.log | timestamped log of every request and response code |

## Constraints honoured

- Output directories (`dvwa_v3_l*_outputs/`) are never modified.
- DVWA is restored to its original state after every single patch via `docker cp`.
- All requests and HTTP status codes are written to `patch_tester.log`.
