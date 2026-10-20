export interface GuardViolation {
  readonly ruleId: string;
  readonly message: string;
  readonly line: number;
}

export function scanSourceText(sourceText: string, filePath?: string): GuardViolation[];

export function runGuardLint(rootDir: string): {
  readonly checkedFiles: number;
  readonly violations: GuardViolation[];
};
