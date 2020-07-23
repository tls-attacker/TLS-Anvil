export enum TestStatus {
  SUCCEEDED = "SUCCEEDED",
  FAILED = "FAILED",
  PARTIALLY_FAILED = "PARTIALLY_FAILED",
  PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED",
  DISABLED = "DISABLED",
  PARSER_ERROR = "PARSER_ERROR"
}

export type TestStatusStrings = keyof typeof TestStatus
export const allStatus = [TestStatus.SUCCEEDED, TestStatus.PARTIALLY_SUCCEEDED, TestStatus.FAILED, TestStatus.PARTIALLY_FAILED]

export function resolveStatus(status: string) {
  switch (status) {
    case TestStatus.SUCCEEDED:
      return "✅";
    case TestStatus.FAILED:
      return "❌"
    case TestStatus.PARTIALLY_FAILED:
      return "⚠️❌"
    case TestStatus.PARTIALLY_SUCCEEDED:
      return "⚠️✅"
    case TestStatus.DISABLED:
      return ""
    case TestStatus.PARSER_ERROR:
      return '☢️'
    default:
      return "UNKNOWN"
  }
}