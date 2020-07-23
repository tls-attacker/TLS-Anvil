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