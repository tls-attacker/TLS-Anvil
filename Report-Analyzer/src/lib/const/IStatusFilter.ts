import { TestResult } from './TestStatus';

export interface IStatusFilter {
  status: TestResult[]
}

export const statusFilterOptions = [
  TestResult.SUCCEEDED,
  TestResult.PARTIALLY_SUCCEEDED,
  TestResult.FAILED,
  TestResult.PARTIALLY_FAILED
]