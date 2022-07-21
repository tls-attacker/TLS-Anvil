export enum TestResult {
  STRICTLY_SUCCEEDED = "STRICTLY_SUCCEEDED",
  FULLY_FAILED = "FULLY_FAILED",
  PARTIALLY_FAILED = "PARTIALLY_FAILED",
  CONCEPTUALLY_SUCCEEDED = "CONCEPTUALLY_SUCCEEDED",
  DISABLED = "DISABLED",
  PARSER_ERROR = "PARSER_ERROR",
  NOT_SPECIFIED = "NOT_SPECIFIED"
}

export type TestResultStrings = keyof typeof TestResult
export const allResults = [TestResult.STRICTLY_SUCCEEDED, TestResult.CONCEPTUALLY_SUCCEEDED, TestResult.FULLY_FAILED, TestResult.PARTIALLY_FAILED]

export function resolveStatus(status: string) {
  switch (status) {
    case TestResult.STRICTLY_SUCCEEDED:
      return "✅";
    case TestResult.FULLY_FAILED:
      return "❌"
    case TestResult.PARTIALLY_FAILED:
      return "⚠️❌"
    case TestResult.CONCEPTUALLY_SUCCEEDED:
      return "⚠️✅"
    case TestResult.DISABLED:
      return ""
    case TestResult.PARSER_ERROR:
      return '☢️'
    default:
      return "UNKNOWN"
  }
}