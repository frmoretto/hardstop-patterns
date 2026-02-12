# hardstop-patterns

> 428 regex patterns for detecting dangerous shell commands and credential file access. Use as a standalone library or as part of the HardStop plugin.

## OBJECTIVE

Install hardstop-patterns as an npm dependency and verify pattern matching works for both dangerous command detection and safe command recognition.

## DONE WHEN

- `checkBashDangerous('rm -rf /')` returns `{ matched: true }` with pattern details
- `checkBashSafe('git status')` returns `{ matched: true }`
- Import/require works without errors

## TODO

- [ ] Install via npm
- [ ] Import the library
- [ ] Verify dangerous command detection
- [ ] Verify safe command passthrough

## Installation

```bash
npm install hardstop-patterns
```

## Verification

```js
const {
  checkBashDangerous,
  checkBashSafe,
  checkReadDangerous,
  checkReadSafe
} = require('hardstop-patterns');

// Should detect as dangerous
const dangerous = checkBashDangerous('rm -rf /');
console.assert(dangerous.matched === true, 'FAIL: rm -rf / not detected');
console.log('Dangerous:', dangerous);

// Should recognize as safe
const safe = checkBashSafe('git status');
console.assert(safe.matched === true, 'FAIL: git status not recognized');
console.log('Safe:', safe);

// Should detect credential file as dangerous
const cred = checkReadDangerous('/home/user/.ssh/id_rsa');
console.assert(cred.matched === true, 'FAIL: SSH key not detected');
console.log('Credential:', cred);

// Should recognize source code as safe to read
const src = checkReadSafe('src/index.js');
console.assert(src.matched === true, 'FAIL: source file not recognized');
console.log('Source:', src);

console.log('hardstop-patterns verified');
```

## API

Main functions:
- `checkBashDangerous(command)` — returns `{ matched, pattern }` if command matches a dangerous pattern
- `checkBashSafe(command)` — returns `{ matched, pattern }` if command matches a known-safe pattern
- `checkReadDangerous(filePath)` — returns `{ matched, pattern }` if filepath is a sensitive credential file
- `checkReadSensitive(filePath)` — returns `{ matched, pattern }` if filepath is suspicious (warrants warning)
- `checkReadSafe(filePath)` — returns `{ matched, pattern }` if filepath is known-safe to read

All functions return `{ matched: false }` if no pattern matches. All accept an optional `{ platform }` option (`'auto'` | `'linux'` | `'macos'` | `'windows'` | `null`).

## Evaluation Order

Consumers MUST check dangerous patterns before safe patterns:

```
1. checkBashDangerous(command)  → if matched, BLOCK
2. checkBashSafe(command)       → if matched, ALLOW
3. (unknown)                    → escalate to human or LLM review
```

## More information

- Repository: https://github.com/frmoretto/hardstop-patterns
- Full documentation: https://github.com/frmoretto/hardstop-patterns#readme
- Schema specification: https://github.com/frmoretto/hardstop-patterns/blob/main/SCHEMA.md
- Parent project: https://github.com/frmoretto/hardstop
