# External Resource Tracker

A real, no-mock-data security auditing tool that issues a single HTTP GET request to a URL you authorize, parses the **actual returned HTML** with a real HTML parser, and tracks **every real external (cross-origin) `<script>`, `<link rel="stylesheet">`, and `<iframe>`** the page loads — flagging missing Subresource Integrity (SRI), scripts loaded over plain HTTP, unsandboxed cross-origin iframes, and an unusually large third-party supply-chain surface.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from the actual HTML received from the target server at scan time.

- **Non-destructive by design.** Each scan is exactly one standard GET request, to the page itself. This tool only *reads and parses* the HTML the server already returned — it never fetches any of the discovered external scripts, stylesheets, or iframe targets.
- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a single, harmless-looking GET request.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit, or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and frontend engineers wanting a full inventory of every third-party script/style/iframe their page actually loads.
- AppSec and supply-chain-security engineers reviewing SRI coverage and third-party trust footprint on in-scope assets.
- Compliance and privacy teams tracking how many distinct external origins a page depends on.
- Students and educators studying real-world Subresource Integrity and third-party supply-chain risk with a genuine, working, non-destructive tool.

## Why use this project

Every external script or stylesheet a page loads is a trust decision: if that third-party host or CDN is ever compromised, the modified resource runs with your page's full privileges — unless Subresource Integrity is in place to detect tampering. This risk is easy to lose track of as a project accumulates analytics tags, widgets, ad scripts, and embeds over time. This tool automates a real, parser-based inventory and audit of every external resource reference on a page using a single real HTTP request, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility.

---

## Detection Rules

Every rule below is evaluated against the **actual external resource references** parsed from the real HTML returned by the one real HTTP GET request made during a scan. A single scan can produce multiple findings per rule if the page references multiple offending resources.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| ERT-001 | External Script Missing Subresource Integrity | High | A cross-origin `<script>` has no `integrity` attribute. |
| ERT-002 | External Stylesheet Missing Subresource Integrity | Medium | A cross-origin stylesheet `<link>` has no `integrity` attribute. |
| ERT-003 | External Script Loaded Over Plain HTTP | **Critical** | A cross-origin `<script>` is loaded over plain HTTP — a mixed-content/MITM risk. |
| ERT-004 | Cross-Origin iframe Missing sandbox Attribute | Medium | A cross-origin `<iframe>` has no `sandbox` attribute restricting its capabilities. |
| ERT-005 | Excessive Number of Distinct External Origins | Low (informational) | The page loads resources from more than 8 distinct external origins. |
| ERT-006 | crossorigin Attribute Set Without integrity | Low (informational) | A resource sets `crossorigin` (requesting CORS) but has no `integrity` — SRI was likely intended but not completed. |
| ERT-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a resource finding — an operational note. |

---

## Architecture

```
external-resource-tracker/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — fetches real HTML, parses real external resources
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating real parsed resources
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd external-resource-tracker
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic parsed-resource dicts, a real-HTML-parsing unit test against a hand-written HTML fixture, and a genuine end-to-end test that boots a real local HTTP server on an ephemeral `127.0.0.1` port serving real HTML with real external references, then performs an actual HTTP request + real parse against it via the real Security Engine — no third-party network calls are made during testing, and no discovered resource is ever fetched.

---

## Frequently Asked Questions

**What does the External Resource Tracker check?**
It issues a single real HTTP GET request to a URL you authorize, parses the actual returned HTML, and tracks every real external script, stylesheet, and iframe reference, flagging missing Subresource Integrity, scripts loaded over plain HTTP, unsandboxed cross-origin iframes, and an unusually high number of distinct third-party origins — never sample data, and no discovered resource is ever fetched.

**Who should use the External Resource Tracker?**
Web developers and security engineers auditing third-party script/stylesheet/iframe supply-chain risk on sites and applications they own or are explicitly authorized to test.

**Why does Subresource Integrity matter so much for external scripts specifically?**
A `<script>` tag executes with the full privileges of your page's origin. If the third-party CDN hosting that script is ever compromised (a real, repeatedly observed attack pattern), every page loading that script without SRI executes the attacker's code automatically. SRI lets the browser refuse to execute the script if its content doesn't match an expected hash.

**Does this tool actually fetch any of the external scripts/stylesheets/iframes it finds?**
No, never. It only parses the HTML markup that was already returned by the single GET request to the page itself. None of the referenced external URLs are ever requested by this tool.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.
