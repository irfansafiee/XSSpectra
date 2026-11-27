# XSSpectra — Context-Aware XSS Reflection Testing

**Category:** Web Application Attack  
**Course:** IKB31603 Ethical Hacking Tool Development  
**Purpose:** Safe, local educational testing of reflected input and HTML encoding.

## What this tool actually demonstrates

XSSpectra uses Harris's scanner to discover a GET input, sends a **harmless inert HTML probe** (`<b>unique-marker</b>`) to a local Flask site, and calls Imelia's analyzer to check reflection, context and HTML encoding. Irfan's local demo provides `/vulnerable` and `/safe` for a meaningful comparison. Huwaina's CLI enforces local scope, asks for authorization and saves JSON/TXT results.

A raw HTML reflection is classified as a **potential exposure**, not a confirmed XSS exploit. Only the optional `--verify-browser` flag attempts browser confirmation using an isolated marker. The browser option requires Playwright and a Chromium installation and is **not required for the basic demo**. Do not describe ordinary marker reflection as confirmed JavaScript execution.

## Requirements

- Python 3.12 or 3.13 recommended; Windows 10/11 or another environment that supports Python
- Packages in `requirements.txt`
- Local Flask lab running on `http://127.0.0.1:5000`
- No outside/production targets

## Install on Windows (Command Prompt)

Open the **XSSpectra presentation-ready folder** in VS Code. Use **Terminal > New Terminal**.

```cmd
py -3.13 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
```

If Python 3.13 is not available, check `py --list` and substitute an installed supported version, or use `python -m venv .venv`.

## Start the test website — Terminal 1

```cmd
python demo_app\app.py
```

Leave the terminal open. Open `http://127.0.0.1:5000/` in a browser. The lab offers vulnerable and protected pages. It binds to **127.0.0.1 only**.

## Run XSSpectra — Terminal 2

Open another terminal in the same project folder and activate `.venv` if necessary.

```cmd
python main.py --help
python main.py --dry-run
python main.py --target http://127.0.0.1:5000/vulnerable --report-format both
python main.py --target http://127.0.0.1:5000/safe --report-format both
```

Type **yes** at the authorization question only if you are authorized to test your own local lab.

Expected basic demo behavior: `/vulnerable` produces **one potential HTML injection/XSS exposure** with an unescaped probe; `/safe` produces **zero potential findings** and shows an escaped reflection indicator. Reports are written to the local `output/` folder; generated reports are not for GitHub commits.

If an HTTP connection fails, check that Terminal 1 is still running and that port 5000 is available. If zero test cases are found, check that the website contains a GET text form or a URL query parameter such as `?q=hello`.

## Optional browser verification (lab only)

```cmd
python -m pip install playwright
python -m playwright install chromium
python main.py --target http://127.0.0.1:5000/vulnerable --verify-browser
```

Playwright is not required for normal reflection analysis. The optional check sends a benign JavaScript assignment to the local test field, refuses non-local subrequests and checks the browser variable. If Playwright is missing or Chromium cannot launch, it reports an unverified status instead of claiming success. **This optional mode was not end-to-end tested in the provided integration bundle.**

## Test the code

With the Flask server stopped or running (most tests use Flask's test client):

```cmd
python -m pytest -q
```

These tests cover response reflection, HTML context classification, encoding, local URL restrictions, marker checks, and lab routes. The shipped integration tests also check discovery of safe input cases without accessing any external site.

## File map

| Component | Role |
|---|---|
| `scanner.py` | Harris: local HTTP scanner, form/parameter discovery, bounded GET requests |
| `analyzer.py` | Imelia: response reflection, encoding and context classification |
| `demo_app/app.py`, `verifier.py` | Irfan: local vulnerable/protected website, localhost and marker helpers |
| `scope.py`, `reporter.py` | Huwaina: scope checks, disclaimer, authorization, JSON and TXT reporting |
| `main.py` | Huwaina's CLI, completed with scan/report orchestration |
| `integration.py` | Small adapter connecting the modules; uses existing teammates' functions |
| `browser_verify.py` | Optional isolated Playwright check for local script execution |
| `tests/` | Unit tests and local app tests |

## Ethical controls and Rules of Engagement (RoE)

**Legal disclaimer:** XSSpectra is for authorized education and controlled testing only. Unauthorized access or testing may violate the **Computer Crimes Act 1997 (Act 563)** in Malaysia. A user confirmation is required before the scanner sends requests. Confirmation alone is not authorization; actual permission is required.

- **Authorized scope:** only the group's own Flask demo at `http://127.0.0.1:5000` and its `/vulnerable` and `/safe` pages. No third-party targets.
- **Time windows:** run during an agreed supervised/local development or presentation session; stop immediately when instructed by the system owner.
- **Permitted techniques:** harmless GET reflection probes, local response/context analysis, optional benign browser marker on the local demo, capped test count, bounded response size.
- **Prohibited techniques:** testing without consent, external hosts, credentials collection, authentication bypass, exfiltration, denial of service, persistence, and aggressive traffic.
- **Emergency stop:** press **Ctrl+C**; the CLI cancels and HTTP sessions are closed. The `--max-tests` option caps test cases at 10; `--dry-run` makes no network request.
- **Data handling:** reports stay in `output/`, excluded by `.gitignore`. No sensitive data or full HTML response bodies are stored in the new report summaries. Do not publish reports that may contain sensitive URL fields; inspect any logs before sharing.
- **Responsible disclosure:** if a flaw is discovered in an authorized system, first verify it within scope, document limited evidence, privately notify its designated owner promptly, agree on a fix timeline, and avoid public disclosure of sensitive findings before authorization.

## Ethical hacking lifecycle mapping

1. **Preparation and authorization:** legal banner, scope check, opt-in confirmation and test limits.
2. **Reconnaissance:** discover GET query parameters and local text form fields.
3. **Controlled testing:** inject an inert HTML tag containing a unique marker, with redirects disabled.
4. **Analysis:** inspect reflection, HTML context and output encoding.
5. **Verification:** optional, local-only browser execution check (requires Playwright).
6. **Reporting:** JSON and TXT reports stored locally with clear finding status and limitations.

## Limitations and future improvements

- Only local port 5000 is supported; GET text inputs only. POST and JavaScript-generated inputs are not automatically tested.
- The HTMLParser-based context detector is heuristic and can miss some contexts. It is not a browser security oracle.
- A reflected marker or HTML tag can indicate unsafe handling but **does not establish exploitable XSS**.
- The basic demo may report low-risk encoded reflection; low risk is not a universal security guarantee.
- The optional browser mode requires Chromium and should be tested on the presentation laptop before claiming confirmation.
- Future improvements: more controlled contexts, POST form support, a stronger HTML/JS parser, systematic test coverage, and structured integration with verification results.

## Development note

This presentation package preserves the teams' existing source modules and adds an integration adapter, optional browser check, tests and documentation. Everyone must review their own work and explain the code during the assessment. The ZIP is an integration **working copy**, not an automatically merged GitHub branch.

## Sources for further reading

- OWASP Web Security Testing Guide — Testing for Reflected Cross-Site Scripting
- OWASP Cross-Site Scripting Prevention Cheat Sheet
- Python `argparse`, `html`, and `urllib.parse` documentation
- Flask testing documentation and Playwright Python documentation
