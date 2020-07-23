import { TestStatus } from './TestStatus';

export interface IStatusFilter {
  status: TestStatus[]
}

export const statusFilterOptions = [
  TestStatus.SUCCEEDED,
  TestStatus.PARTIALLY_SUCCEEDED,
  TestStatus.FAILED,
  TestStatus.PARTIALLY_FAILED
]