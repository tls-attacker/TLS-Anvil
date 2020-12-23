export enum TestResult {
  SUCCEEDED = "SUCCEEDED",
  FAILED = "FAILED",
  PARTIALLY_FAILED = "PARTIALLY_FAILED",
  PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED",
  DISABLED = "DISABLED",
  PARSER_ERROR = "PARSER_ERROR",
  NOT_SPECIFIED = "NOT_SPECIFIED"
}

export type TestResultStrings = keyof typeof TestResult
export const allResults = [TestResult.SUCCEEDED, TestResult.PARTIALLY_SUCCEEDED, TestResult.FAILED, TestResult.PARTIALLY_FAILED]

export function resolveStatus(status: string) {
  switch (status) {
    case TestResult.SUCCEEDED:
      return "✅";
    case TestResult.FAILED:
      return "❌"
    case TestResult.PARTIALLY_FAILED:
      return "⚠️❌"
    case TestResult.PARTIALLY_SUCCEEDED:
      return "⚠️✅"
    case TestResult.DISABLED:
      return ""
    case TestResult.PARSER_ERROR:
      return '☢️'
    default:
      return "UNKNOWN"
  }
}