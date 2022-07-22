import { TestResult } from './TestStatus'

export enum SeverityLevel {
  INFORMATIONAL = "INFORMATIONAL",
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}

export type SeverityLevelStrings = keyof typeof SeverityLevel
export const allSeverityLevels = [SeverityLevel.INFORMATIONAL, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]

export function resolveSeverityLevel(level: string) {
  switch(level) {
    case SeverityLevel.INFORMATIONAL:
      return '⚪️'
    case SeverityLevel.LOW:
      return '🟡'
    case SeverityLevel.MEDIUM:
      return '🟠'
    case SeverityLevel.HIGH:
      return '🔴'
    case SeverityLevel.CRITICAL:
      return '🟣'
    default:
      return 'U'
  }
}


function scoreForStatus(status: TestResult, total: number): number {
  switch (status) {
    case TestResult.STRICTLY_SUCCEEDED:
      return 1.0 * total
    case TestResult.CONCEPTUALLY_SUCCEEDED:
      return 0.8 * total
    case TestResult.PARTIALLY_FAILED:
      return 0.2 * total
    default:
      return 0
  }
}

export function score(severityLevel: SeverityLevel, status: TestResult): number {
  switch (severityLevel) {
    case SeverityLevel.INFORMATIONAL:
      return scoreForStatus(status, 20)
    case SeverityLevel.LOW:
      return scoreForStatus(status, 40)
    case SeverityLevel.MEDIUM:
      return scoreForStatus(status, 60)
    case SeverityLevel.HIGH:
      return scoreForStatus(status, 80)
    case SeverityLevel.CRITICAL:
      return scoreForStatus(status, 100)
  }
}