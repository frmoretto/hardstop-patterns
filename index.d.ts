export interface Pattern {
  id: string;
  pattern: string;
  message?: string;
  category: string;
  severity?: 'critical' | 'high' | 'medium';
  platforms: ('linux' | 'macos' | 'windows')[];
  notes?: string;
  added: string;
  tests?: {
    should_match?: string[];
    should_not_match?: string[];
  };
}

export interface PatternFile {
  version: string;
  scope: 'bash' | 'read';
  type: 'dangerous' | 'safe' | 'sensitive';
  match_mode: 'search' | 'fullmatch';
  patterns: Pattern[];
}

export interface Meta {
  schema_version: string;
  patterns_version: string;
  stats: Record<string, number>;
  total: number;
  regex_notes: Record<string, string>;
  compatibility: { python: string; node: string };
}

export interface MatchResult {
  matched: boolean;
  pattern?: Pattern;
}

export interface CheckOptions {
  /**
   * Platform filtering. 
   * - 'auto' (default): detect from process.platform
   * - 'linux' | 'macos' | 'windows': explicit platform
   * - null: disable filtering (check all patterns regardless of platform)
   */
  platform?: 'auto' | 'linux' | 'macos' | 'windows' | null;
}

export const bashDangerous: PatternFile;
export const bashSafe: PatternFile;
export const readDangerous: PatternFile;
export const readSensitive: PatternFile;
export const readSafe: PatternFile;
export const meta: Meta;
export const version: string;

export function checkBashDangerous(command: string, options?: CheckOptions): MatchResult;
export function checkBashSafe(command: string, options?: CheckOptions): MatchResult;
export function checkReadDangerous(filePath: string, options?: CheckOptions): MatchResult;
export function checkReadSensitive(filePath: string, options?: CheckOptions): MatchResult;
export function checkReadSafe(filePath: string, options?: CheckOptions): MatchResult;

/**
 * Preload and compile all pattern files. Call at startup to avoid
 * sync I/O latency on first check call.
 */
export function preload(): Promise<void>;
