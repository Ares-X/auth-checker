# Auth Checker

`check_ai_auth.py` checks Codex and Claude auth files without printing token values, refresh tokens, API keys, or OAuth secrets.

It supports:

- Codex ChatGPT auth files: `auth.json`, `auth.json.*`
- Claude credentials files: `credentials.json`, `credentials.json.*`, `.credentials.json`, `.credentials.json.*`
- Single-file checks
- Directory scans up to two subdirectory levels
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

Claude:
  credentials.json
  credentials.json.1
  credentials.json.*
  .credentials.json
  .credentials.json.1
  .credentials.json.*
```

## Output

Human output is a table:

```text
RESULT          PROVIDER STATUS                   HTTP  EXPIRES_IN   EXPIRES_AT                   PATH
OK              codex    valid                    200   123456s      2026-07-11T10:02:06+00:00    /path/auth.json
```

Result labels:

```text
OK        usable
FAIL      expired, rejected, malformed, or missing token
UNKNOWN   local token is not expired, but network verification was inconclusive
```

Directory scans print results as each file completes. At the end they print:

```text
summary: usable=2/3 status=attention_required provider=auto scan_dir=/path
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

## Useful Examples

Watch a directory every five minutes:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --watch 300
```

Quiet output for shell scripts:

```bash
python3 auth-checker/check_ai_auth.py -k auto -d /path/to/accounts --quiet --color never
```

Check a copied Codex auth file:

```bash
python3 auth-checker/check_ai_auth.py -k codex --auth-file ./account-a/auth.json.1
```

Check a copied Claude credentials file:

```bash
python3 auth-checker/check_ai_auth.py -k claude --auth-file ./account-b/.credentials.json.2
```
