# Changelog

All notable changes to hardstop-patterns will be documented in this file.

## [1.0.2] - 2026-02-14

### Ecosystem Cross-Links

Adds discoverability links to the parent hardstop project.

### Added
- **README.md, package.json**: Ecosystem cross-links to hardstop package
- **install.md**: Enhanced parent project reference with both npm and GitHub links

### Changed
- **Git tags**: Corrected v1.0.1 tag to point to actual npm 1.0.1 publish (69ad7b7)
  - Previously pointed to ecosystem cross-links commit (6e8f077)
  - Aligns git history with published npm package

---

## [1.0.1] - 2026-02-12

### Agent Discovery Optimization

Adds install.md for agent discovery and improves package metadata.

### Added
- **install.md**: Agent discovery file with installation instructions, features, and links
- **package.json**: Added `install.md` to npm package files

### Changed
- **README.md**: Added npm, license, Node.js version, and platform support badges

---

## [1.0.0] - 2026-02-11

### Initial Release

First stable release of hardstop-patterns as a standalone package.

### Features
- **428 security patterns** for command validation
- **679 test cases** with 100% pass rate
- **Pattern categories**:
  - Dangerous command patterns (rm -rf, curl | bash, etc.)
  - Safe command patterns (ls, git status, etc.)
  - Credential file patterns (.ssh/, .aws/, .env, etc.)
  - Package manager force operations (dpkg --force-*, rpm --nodeps)
  - Cloud CLI destructive operations (AWS, GCP, Azure, etc.)
  - Platform-specific patterns (Windows, macOS, Linux)
- **YAML-based pattern storage** for easy maintenance
- **Pattern loader** with validation and duplicate detection
- **Cross-platform support**: Windows, macOS, Linux

### Technical Details
- Node.js 18+ required
- CommonJS module format
- Zero runtime dependencies (patterns are data files)
- Comprehensive test suite with 679 tests

---

**Version:** 1.0.2
**Repository:** https://github.com/frmoretto/hardstop-patterns
**License:** MIT
