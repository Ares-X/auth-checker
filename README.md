# Auth Checker

`check_ai_auth.py` checks Codex and Claude auth files without printing token values, refresh tokens, API keys, or OAuth secrets.

It supports:

- Codex ChatGPT auth files: `auth.json`, `auth.json.*`, `auth1.json`
- Claude credentials files: `credentials.json`, `credentials.json.*`, `credentials1.json`, `.credentials.json`, `.credentials.json.*`, `.credentials1.json`
- Single-file checks
- Directory scans up to two subdirectory levels
- URL list checks for remote JSON auth files
- Default local save for usable auth JSON files downloaded from URL lists
- Optional concurrent checks with worker threads
- Auto provider detection
- Rolling terminal output during scans
- JSON output for automation

## Quick Start

Check the default Codex auth file:

```bash
python3 auth-checker/check_ai_auth.py -k codex
```

Check the default Claude credentials file:

```bash
python3 auth-checker/check_ai_auth.py -k claude
```

Scan a directory containing multiple account folders:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts
```

Check auth JSON files from a URL list:

```bash
python3 auth-checker/check_ai_auth.py -k auto -l ./auth-urls.txt
```

When `-l/--url-list` is used, usable downloaded auth JSON files are saved by default under:

```text
saved-url-auths/YYYYMMDD-HHMMSS/
```

Disable URL auth saving:

```bash
python3 auth-checker/check_ai_auth.py -k auto -l ./auth-urls.txt -ns
```

Scan faster with concurrent workers:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --workers 8
```

Force color output:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --color always
```

Use machine-readable JSON:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --json
```

## Provider Selection

Use `-k/--kind`:

```text
auto      Infer provider from file name and JSON shape
codex     Treat files as Codex auth.json files
claude    Treat files as Claude credentials files
```

Defaults:

- `auto` and `codex`: `~/.codex/auth.json`
- `claude`: `~/.claude/.credentials.json`

## Directory Scan Rules

`-d DIR` checks matching files directly under:

```text
DIR/
DIR/*/
DIR/*/*/
```

It does not recurse deeper than two subdirectory levels.

Recognized file names:

```text
Codex:
  auth.json
  auth.json.1
  auth.json.2
  auth.json.*
  auth1.json
  auth2.json

Claude:
  credentials.json
  credentials.json.1
  credentials.json.*
  credentials1.json
  credentials2.json
  .credentials.json
  .credentials.json.1
  .credentials.json.*
  .credentials1.json
  .credentials2.json
```

## URL List Rules

`-l FILE` reads one HTTP or HTTPS URL per line and downloads each URL as a JSON object.

```text
https://example.com/account-a/auth.json
https://example.com/account-b/.credentials.json
# blank lines and full-line comments are ignored
```

URL checks support the same provider detection, expiry checks, network probes, color output, JSON output, and usable summary as directory scans.

Use `--workers N` to check several files or URLs concurrently. Values greater than `1` enable concurrency. Rolling output is printed as each check finishes, so concurrent output is completion order, not input order.

Usable URL auth files are saved by default. Each script run creates a folder named from the script start time:

```text
saved-url-auths/20260703-231530/
001-codex-auth.json
002-claude-.credentials.json
```

Options:

```text
-ns, --no-save-successful-url-auths   Do not save usable downloaded auth files
--url-auth-save-dir DIR               Parent directory for saved auth files
```

## Output

Human output is a table:

```text
RESULT          PROVIDER PLAN           STATUS                   HTTP  EXPIRES_IN   EXPIRES_AT                   PATH
OK              codex    plus           valid                    200   123456s      2026-07-11T10:02:06+00:00    /path/auth.json
```

Result labels:

```text
OK        usable
FAIL      expired, rejected, malformed, or missing token
UNKNOWN   local token is not expired, but network verification was inconclusive
```

`PLAN` is inferred from local non-secret metadata:

- Codex: `chatgpt_plan_type` inside the access-token or id-token JWT claim.
- Claude: `subscriptionType` / `rateLimitTier` inside `credentials.json`, `.credentials.json`, `oauthToken`, or `claudeAiOauth`.
- Claude fallback: `.claude.json.oauthAccount.organizationRateLimitTier` found on the checked credentials file's parent path.

Examples:

```text
plus                         -> plus
default_claude_max_5x        -> max_5x
default_claude_max_20x       -> max_20x
```

If no reliable local plan metadata exists, `PLAN` is `unknown`.

Directory scans and URL-list checks print results as each file or URL completes. At the end they print:

```text
summary: usable=2/3 status=attention_required provider=auto scan_dir=/path
saved_auths=2 dir=saved-url-auths/20260703-231530
==== usable auth files ====
...
===========================
```

## Exit Codes

```text
0  all checked files are usable
1  at least one file is expired, rejected, or expiring too soon
2  file, directory, JSON, or format error
3  network result was inconclusive
```

For directory scans, the exit code summarizes the whole scan.

## Network Checks

Codex:

- Decodes local JWT metadata.
- Calls the Codex models endpoint with the access token.
- Treats HTTP 200 with a model list as dynamically valid.

Claude:

- Reads OAuth token or API key credentials.
- Sends a minimal invalid-model request to the Anthropic Messages API.
- Treats authentication success followed by an expected invalid-model response as dynamically valid.

Use local-only mode when you only want expiry checks:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --no-network
```

## Safety

- The script is read-only.
- It does not refresh credentials.
- It does not call `codex login status`.
- It does not call Claude CLI.
- It does not write back to any auth file.
- It never prints token, refresh token, API key, or OAuth secret values.
- URL-list mode downloads credential JSON from the listed URLs. Only use trusted URLs, prefer HTTPS, and do not publish auth files publicly.
- URL-list mode saves usable downloaded auth files by default under `saved-url-auths/`. That directory is ignored by this repository's `.gitignore`.
- Use `-ns` when you want URL checks without local credential copies.

## Useful Examples

Watch a directory every five minutes:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --watch 300
```

Quiet output for shell scripts:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --quiet --color never
```

Concurrent URL-list check:

```bash
python3 auth-checker/check_ai_auth.py -k auto -l ./auth-urls.txt --workers 8
```

Concurrent URL-list check without saving downloaded auth files:

```bash
python3 auth-checker/check_ai_auth.py -k auto -l ./auth-urls.txt --workers 8 -ns
```

Check a copied Codex auth file:

```bash
python3 auth-checker/check_ai_auth.py -k codex --auth-file ./account-a/auth.json.1
```

Check a copied Claude credentials file:

```bash
python3 auth-checker/check_ai_auth.py -k claude --auth-file ./account-b/.credentials.json.2
```
