import { TestResult } from './TestStatus';

export interface IStatusFilter {
  status: TestResult[]
}

export const statusFilterOptions = [
  TestResult.STRICTLY_SUCCEEDED,
  TestResult.CONCEPTUALLY_SUCCEEDED,
  TestResult.FULLY_FAILED,
  TestResult.PARTIALLY_FAILED
]