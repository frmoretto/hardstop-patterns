/**
 * hardstop-patterns — Security patterns for command and file access validation
 *
 * Single source of truth for HardStop detection patterns.
 * Requires Node.js 16+.
 */

const fs = require('fs');
const path = require('path');

const patternsDir = path.join(__dirname, 'patterns');

/**
 * Load and parse a pattern JSON file. Wraps in try/catch so a single
 * corrupted file doesn't hard-crash the entire process.
 */
function loadPatterns(filename) {
  const filepath = path.join(patternsDir, filename);
  try {
    return JSON.parse(fs.readFileSync(filepath, 'utf8'));
  } catch (err) {
    const wrapped = new Error(`hardstop-patterns: failed to load ${filename}: ${err.message}`);
    wrapped.cause = err;
    throw wrapped;
  }
}

// Pre-compiled regex cache: patternFile object -> Array<{pattern, regex}>
const _regexCache = new Map();

/**
 * Compile all patterns in a file, respecting match_mode.
 * - "fullmatch": wraps pattern in ^(?:...)$ if not already anchored
 * - "search": uses pattern as-is
 * Individual bad regexes are skipped (logged to stderr) rather than crashing.
 */
function getCompiledPatterns(patternFile) {
  if (_regexCache.has(patternFile)) return _regexCache.get(patternFile);

  const isFullMatch = patternFile.match_mode === 'fullmatch';
  const compiled = [];

  for (const p of patternFile.patterns) {
    let src = p.pattern;
    if (isFullMatch) {
      // Enforce full-match semantics: wrap if not already anchored
      const hasStart = src.startsWith('^');
      const hasEnd = src.endsWith('$');
      if (!hasStart || !hasEnd) {
        src = '^(?:' + src.replace(/^\^/, '').replace(/\$$/, '') + ')$';
      }
    }
    try {
      compiled.push({ pattern: p, regex: new RegExp(src, 'i') });
    } catch (err) {
      // Skip bad regex rather than crashing — log for debugging
      if (typeof process !== 'undefined' && process.stderr) {
        process.stderr.write(`hardstop-patterns: bad regex in ${p.id}: ${err.message}\n`);
      }
    }
  }

  _regexCache.set(patternFile, compiled);
  return compiled;
}

// Lazy-loaded pattern sets
let _bashDangerous, _bashSafe, _readDangerous, _readSensitive, _readSafe, _meta;

Object.defineProperties(module.exports, {
  bashDangerous: {
    get() { return _bashDangerous || (_bashDangerous = loadPatterns('bash-dangerous.json')); },
    enumerable: true
  },
  bashSafe: {
    get() { return _bashSafe || (_bashSafe = loadPatterns('bash-safe.json')); },
    enumerable: true
  },
  readDangerous: {
    get() { return _readDangerous || (_readDangerous = loadPatterns('read-dangerous.json')); },
    enumerable: true
  },
  readSensitive: {
    get() { return _readSensitive || (_readSensitive = loadPatterns('read-sensitive.json')); },
    enumerable: true
  },
  readSafe: {
    get() { return _readSafe || (_readSafe = loadPatterns('read-safe.json')); },
    enumerable: true
  },
  meta: {
    get() { return _meta || (_meta = loadPatterns('meta.json')); },
    enumerable: true
  },
  version: {
    get() { return require('./package.json').version; },
    enumerable: true
  }
});

/**
 * Detect current platform as a pattern platform string.
 * @returns {'linux'|'macos'|'windows'}
 */
function detectPlatform() {
  if (typeof process === 'undefined') return 'linux';
  switch (process.platform) {
    case 'win32': return 'windows';
    case 'darwin': return 'macos';
    default: return 'linux';
  }
}

/** @type {'linux'|'macos'|'windows'} */
let _detectedPlatform;
function getCurrentPlatform() {
  return _detectedPlatform || (_detectedPlatform = detectPlatform());
}

/**
 * Check if a pattern applies to the given platform.
 * @param {object} pattern - Pattern object with platforms array
 * @param {string|null} platform - Platform to check, or null to skip filtering
 */
function matchesPlatform(pattern, platform) {
  if (!platform) return true;
  if (!pattern.platforms || pattern.platforms.length === 0) return true;
  return pattern.platforms.includes(platform);
}

/**
 * Check if a command matches any dangerous bash pattern.
 * @param {string} command - The shell command to check
 * @param {{ platform?: string|null|'auto' }} [options] - Options. platform: 'auto' (default) uses OS detection, null disables filtering, or specify 'linux'|'macos'|'windows'
 * @returns {{ matched: boolean, pattern?: object }}
 */
module.exports.checkBashDangerous = function checkBashDangerous(command, options) {
  if (typeof command !== 'string') return { matched: false };
  const platform = resolvePlatform(options);
  const compiled = getCompiledPatterns(module.exports.bashDangerous);
  for (const { pattern, regex } of compiled) {
    if (matchesPlatform(pattern, platform) && regex.test(command)) {
      return { matched: true, pattern };
    }
  }
  return { matched: false };
};

/**
 * Check if a command matches a safe bash pattern (full match enforced).
 * @param {string} command - The shell command to check
 * @param {{ platform?: string|null|'auto' }} [options]
 * @returns {{ matched: boolean, pattern?: object }}
 */
module.exports.checkBashSafe = function checkBashSafe(command, options) {
  if (typeof command !== 'string') return { matched: false };
  const trimmed = command.trim();
  const platform = resolvePlatform(options);
  const compiled = getCompiledPatterns(module.exports.bashSafe);
  for (const { pattern, regex } of compiled) {
    if (matchesPlatform(pattern, platform) && regex.test(trimmed)) {
      return { matched: true, pattern };
    }
  }
  return { matched: false };
};

/**
 * Check if a file path matches any dangerous read pattern.
 * @param {string} filePath - The file path to check
 * @param {{ platform?: string|null|'auto' }} [options]
 * @returns {{ matched: boolean, pattern?: object }}
 */
module.exports.checkReadDangerous = function checkReadDangerous(filePath, options) {
  if (typeof filePath !== 'string') return { matched: false };
  const normalized = filePath.replace(/\\/g, '/');
  const platform = resolvePlatform(options);
  const compiled = getCompiledPatterns(module.exports.readDangerous);
  for (const { pattern, regex } of compiled) {
    if (matchesPlatform(pattern, platform) && regex.test(normalized)) {
      return { matched: true, pattern };
    }
  }
  return { matched: false };
};

/**
 * Check if a file path matches any sensitive read pattern.
 * @param {string} filePath - The file path to check
 * @param {{ platform?: string|null|'auto' }} [options]
 * @returns {{ matched: boolean, pattern?: object }}
 */
module.exports.checkReadSensitive = function checkReadSensitive(filePath, options) {
  if (typeof filePath !== 'string') return { matched: false };
  const normalized = filePath.replace(/\\/g, '/');
  const platform = resolvePlatform(options);
  const compiled = getCompiledPatterns(module.exports.readSensitive);
  for (const { pattern, regex } of compiled) {
    if (matchesPlatform(pattern, platform) && regex.test(normalized)) {
      return { matched: true, pattern };
    }
  }
  return { matched: false };
};

/**
 * Check if a file path matches any safe read pattern.
 * @param {string} filePath - The file path to check
 * @param {{ platform?: string|null|'auto' }} [options]
 * @returns {{ matched: boolean, pattern?: object }}
 */
module.exports.checkReadSafe = function checkReadSafe(filePath, options) {
  if (typeof filePath !== 'string') return { matched: false };
  const normalized = filePath.replace(/\\/g, '/');
  const platform = resolvePlatform(options);
  const compiled = getCompiledPatterns(module.exports.readSafe);
  for (const { pattern, regex } of compiled) {
    if (matchesPlatform(pattern, platform) && regex.test(normalized)) {
      return { matched: true, pattern };
    }
  }
  return { matched: false };
};

/**
 * Preload and compile all pattern files. Call this at startup to avoid
 * sync I/O latency on first check. Returns a promise that resolves
 * when all patterns are loaded and compiled.
 * @returns {Promise<void>}
 */
module.exports.preload = function preload() {
  return new Promise((resolve, reject) => {
    try {
      // Touch all lazy getters to trigger loading
      const files = [
        module.exports.bashDangerous,
        module.exports.bashSafe,
        module.exports.readDangerous,
        module.exports.readSensitive,
        module.exports.readSafe,
        module.exports.meta,
      ];
      // Pre-compile all regex caches
      files.forEach(f => { if (f.patterns) getCompiledPatterns(f); });
      resolve();
    } catch (err) {
      reject(err);
    }
  });
};

/**
 * Resolve the platform option.
 * @param {{ platform?: string|null|'auto' }} [options]
 * @returns {string|null}
 */
function resolvePlatform(options) {
  if (!options || options.platform === undefined || options.platform === 'auto') {
    return getCurrentPlatform();
  }
  return options.platform; // null = no filtering, or explicit 'linux'|'macos'|'windows'
}
