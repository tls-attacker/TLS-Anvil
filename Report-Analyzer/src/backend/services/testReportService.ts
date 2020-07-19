import { ITestResultContainer, ITestResult } from '../database/models';
import { UploadReportEndpoint } from '../endpoints';

function stringSort(a: string, b: string): number {
  if (a < b) {
    return -1;
  }
  if (a > b) {
    return 1;
  }
  return 0;
}

export class TestReportService {
  private testReport: ITestResultContainer

  constructor(report: ITestResultContainer) {
    this.testReport = JSON.parse(JSON.stringify(report))
  }

  private static getTestResults(a?: ITestResultContainer): ITestResult[] {
    let n: ITestResult[] = []
    if (a.TestResults) {
      n = n.concat(a.TestResults)
    }

    if (a.TestClasses) {
      for (let i of a.TestClasses) {
        n = n.concat(this.getTestResults(i))
      }
    }

    return n
  }

  private sort() {
    const testResults = this.testReport.TestResults
    testResults.sort((a, b) => {
      const aU = a.TestMethod.ClassName.toUpperCase()
      const bU = b.TestMethod.ClassName.toUpperCase()
      return stringSort(aU, bU)
    })

    for (let result of testResults) {
      result.States.sort((a, b) => {
        const aU = a.uuid.toUpperCase()
        const bU = b.uuid.toUpperCase()
        return stringSort(aU, bU)
      })
    }
  }

  prepareTestReport(): ITestResultContainer {
    const results: ITestResult[] = TestReportService.getTestResults(this.testReport)
    this.testReport.TestResults = results
    this.testReport.TestClasses = null
    this.sort()

    return this.testReport
  }
}

