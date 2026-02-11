# hardstop-patterns — Schema Design

## Overview

Single source of truth for all HardStop detection patterns.
Consumed by: Python plugin (planned), npm package, any third-party tool.

## File Structure

```
hardstop-patterns/
├── package.json              # npm package metadata
├── index.js                   # npm entry: exports all patterns + check functions
├── index.d.ts                 # TypeScript type definitions
├── patterns/
│   ├── bash-dangerous.json    # Dangerous command patterns
│   ├── bash-safe.json         # Safe command patterns (allowlist)
│   ├── read-dangerous.json    # Dangerous file read patterns
│   ├── read-sensitive.json    # Sensitive file read patterns (warn)
│   ├── read-safe.json         # Safe file read patterns
│   └── meta.json              # Version, stats, compatibility
├── tests/
│   └── patterns.test.js       # Structural, regex, and matching tests
├── .gitignore
├── vitest.config.mjs            # Test runner config
├── README.md
├── LICENSE
└── SCHEMA.md                  # This file
```

## Why Separate Files (not one big JSON)

- Consumers can load only what they need (bash-only vs read-only)
- Easier to review PRs that touch one category
- Smaller payloads for tools that only care about one scope
- Git diff is readable per-category

## Pattern Schema

### bash-dangerous.json

```json
{
  "version": "1.0.0",
  "scope": "bash",
  "type": "dangerous",
  "match_mode": "search",
  "patterns": [
    {
      "id": "DEL-001",
      "pattern": "(?<!echo\\s)(?<!echo ')(?<!echo \\\")rm\\s+(-[^\\s]*\\s+)*(/home/|~/)",
      "message": "Deletes home directory",
      "category": "deletion",
      "severity": "critical",
      "platforms": ["linux", "macos"],
      "notes": "Excludes echo/printf which just output strings",
      "added": "1.0.0",
      "tests": {
        "should_match": ["rm -rf ~/", "rm -rf /home/user"],
        "should_not_match": ["echo 'rm -rf ~/'", "rm -rf node_modules"]
      }
    }
  ]
}
```

### bash-safe.json

```json
{
  "version": "1.0.0",
  "scope": "bash",
  "type": "safe",
  "match_mode": "fullmatch",
  "patterns": [
    {
      "id": "SAFE-RO-001",
      "pattern": "^ls(?:\\s+.*)?$",
      "category": "read_only",
      "platforms": ["linux", "macos"],
      "added": "1.0.0"
    }
  ]
}
```

### read-dangerous.json

```json
{
  "version": "1.0.0",
  "scope": "read",
  "type": "dangerous",
  "match_mode": "search",
  "patterns": [
    {
      "id": "CRED-SSH-001",
      "pattern": "[/\\\\]\\.ssh[/\\\\]id_rsa$",
      "message": "SSH private key (RSA)",
      "category": "ssh_keys",
      "severity": "critical",
      "platforms": ["linux", "macos", "windows"],
      "added": "1.0.0"
    }
  ]
}
```

### meta.json

```json
{
  "schema_version": "1.0.0",
  "patterns_version": "1.0.0",
  "stats": {
    "bash_dangerous": 180,
    "bash_safe": 74,
    "read_dangerous": 71,
    "read_sensitive": 11,
    "read_safe": 92
  },
  "total": 428,
  "regex_notes": {
    "lookbehinds": "Some patterns use fixed-length lookbehinds. Supported in Python re, Node.js 16+.",
    "fullmatch": "Safe bash patterns use fullmatch semantics (anchored ^...$). JS consumers should use the match_mode field.",
    "flags": "All patterns use case-insensitive matching."
  },
  "compatibility": {
    "python": ">=3.8",
    "node": ">=16.0.0"
  }
}
```

## Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | yes | string | Unique ID: PREFIX-NNN (e.g. DEL-001, RSHELL-003) |
| `pattern` | yes | string | Regex pattern (PCRE-compatible) |
| `message` | dangerous/sensitive | string | Human-readable block/warn reason |
| `category` | yes | string | Grouping key (see categories below) |
| `severity` | dangerous/sensitive | string | `critical`, `high`, or `medium` |
| `platforms` | yes | string[] | `linux`, `macos`, `windows` |
| `notes` | no | string | Implementation notes, false positive context |
| `added` | yes | string | Version when pattern was added |
| `tests` | no | object | Inline test cases (`should_match`, `should_not_match` arrays) |

## Categories

### Bash Dangerous
- `deletion` — rm, find -delete on system/home paths
- `reverse_shell` — bash -i, nc -e, python socket
- `credential_exfil` — curl/wget/scp with sensitive files
- `credential_read` — cat on .ssh, .aws, .env, etc.
- `disk_destruction` — dd, mkfs, shred on devices
- `encoded_execution` — base64 decode to shell, eval
- `remote_code_execution` — curl|bash, wget|sh
- `system_damage` — chmod 777 /, recursive chown
- `history_manipulation` — clearing bash history
- `scheduled_persistence` — crontab, at jobs
- `privileged_operations` — sudo with dangerous payloads
- `shell_wrapper` — bash -c, env, xargs hiding dangerous commands
- `cloud_destructive` — aws/gcloud/kubectl/docker destroy ops
- `database_destructive` — DROP, TRUNCATE, FLUSH
- `windows_deletion` — rd, del, Remove-Item on system paths
- `windows_registry` — reg delete, Run keys
- `windows_credential` — mimikatz, SAM copy, vault
- `windows_disk` — format, diskpart, bcdedit
- `windows_security` — firewall disable, Defender off
- `windows_reverse_shell` — encoded PowerShell, LOLBins
- `windows_persistence` — schtasks, execution policy bypass
- `windows_admin` — net user /add, admin group
- `macos_disk` — diskutil erase, partition
- `macos_keychain` — security dump/delete/export
- `macos_timemachine` — tmutil delete, disable
- `macos_directory_services` — dscl delete users/groups
- `macos_system_security` — Gatekeeper, SIP, remote login
- `macos_privacy` — TCC.db, tccutil
- `macos_persistence` — launchctl, LaunchDaemons
- `macos_appdata` — Library deletion, defaults delete

### Read Dangerous
- `ssh_keys` — .ssh/id_rsa, id_ed25519, etc.
- `cloud_credentials` — .aws/credentials, .azure, gcloud
- `environment_files` — .env, .env.local, .env.production
- `token_files` — credentials.json, secrets.yaml, .npmrc
- `container_credentials` — .docker/config.json, .kube/config
- `database_credentials` — .pgpass, .my.cnf
- `private_keys` — *.pem, *.p12, *.pfx
- `platform_credentials` — .git-credentials, .gh/hosts.yml
- `browser_credentials` — Chrome Login Data, Firefox logins.json
- `windows_credentials` — SAM, SYSTEM, NTUSER.DAT
- `macos_credentials` — Keychains, TCC.db, authorization
- `ci_cd` — .travis.yml, .circleci/config.yml

### Read Sensitive
- `config_files` — config.json, config.yaml, settings.json
- `backup_files` — .env.bak, .env.backup, credentials.bak
- `suspicious_names` — files with password, secret, token, apikey in name

### Read Safe
- `documentation` — README, LICENSE, CHANGELOG, .md, .txt, .rst
- `source_code` — .py, .js, .ts, .go, .rs, .java, .sh, etc.
- `project_config` — package.json, tsconfig.json, Cargo.toml, go.mod, Dockerfile, etc.
- `template_files` — .env.example, .env.template, .env.sample
- `web_assets` — .html, .css, .scss, .svg
- `data_formats` — .xml

### Bash Safe
- `self_management` — HardStop's own operations
- `read_only` — ls, cat, head, tail, pwd, etc.
- `git_read` — git status, log, diff, show
- `git_workflow` — add, commit, push, pull, merge
- `regeneratable_cleanup` — node_modules, __pycache__, dist
- `package_read` — npm list, pip freeze
- `windows_read_only` — dir, type, Get-Content
- `windows_cleanup` — rd node_modules
- `macos_read_only` — diskutil list, sw_vers, defaults read

## ID Prefix Convention

| Prefix | Scope |
|--------|-------|
| DEL- | Deletion patterns |
| RSHELL- | Reverse shells |
| EXFIL- | Credential exfiltration |
| CREAD- | Credential reads (bash) |
| DISK- | Disk destruction |
| ENC- | Encoded execution |
| RCE- | Remote code execution |
| SYSD- | System damage |
| HIST- | History manipulation |
| CRON- | Scheduled/persistence |
| SUDO- | Privileged operations |
| WRAP- | Shell wrappers |
| CLOUD- | Cloud CLI destructive |
| DB- | Database destructive |
| WIN- | Windows-specific |
| MAC- | macOS-specific |
| SAFE- | Safe patterns (all) |
| CRED- | Credential file reads |
| SENS- | Sensitive file reads |

## Consuming the Patterns

### JavaScript (npm)
```js
const { checkBashDangerous, checkBashSafe, checkReadDangerous } = require('hardstop-patterns');

// Using check functions (recommended — patterns are pre-compiled and cached)
const result = checkBashDangerous('rm -rf ~/');
if (result.matched) {
  console.log(`BLOCKED: ${result.pattern.message}`);
}

// Or access raw pattern data directly
const { bashDangerous } = require('hardstop-patterns');
for (const p of bashDangerous.patterns) {
  // p.id, p.pattern, p.message, p.category, p.severity, p.platforms
}
```

### Python (planned)
```python
import json, re

with open('patterns/bash-dangerous.json') as f:
    bash_dangerous = json.load(f)

for p in bash_dangerous["patterns"]:
    if re.search(p["pattern"], command, re.IGNORECASE):
        print(f"BLOCKED: {p['message']}")
```

## Versioning

- Pattern additions: minor version bump (1.0.0 → 1.1.0)
- Pattern removals or behavioral changes: major version bump (1.0.0 → 2.0.0)
- Metadata-only changes: patch version bump (1.0.0 → 1.0.1)

## Regex Compatibility Notes

### Lookbehinds
Python `re` supports fixed-length lookbehinds only (no variable-length).
JS supports lookbehinds since Node 16 / Chrome 62.
All lookbehinds in this repo use fixed-length patterns for cross-runtime compatibility.

### fullmatch vs search
- `dangerous` patterns use `search` (match anywhere in command)
- `safe` bash patterns use `fullmatch` (must match entire command)
- `safe` read patterns use `search` (match anywhere in path)
- The `match_mode` field in each file specifies this

### Flag
All patterns assume case-insensitive matching (`re.IGNORECASE` / `'i'` flag).
