import { ITestResultContainer, ITestResult, ITestMethod, IState, TestResultSchema } from '@/backend/database/models';


interface ITestMethodTable extends ITestMethod {
  testCaseName: string,
}

interface ITestResultTable extends ITestResult {
  TestMethod: ITestMethodTable,
  statusIcons: string
}

interface IItemProviderContext {
  currentPage: number,
  perPage: number,
  filter: IFilter,
  sortBy: string,
  sortDesc: boolean,
  apiUrl: string
}

function timeConversion(millisec: number) {
  var seconds = parseFloat((millisec / 1000).toFixed(1));
  var minutes = parseFloat((millisec / (1000 * 60)).toFixed(1));
  var hours = parseFloat((millisec / (1000 * 60 * 60)).toFixed(1));
  var days = parseFloat((millisec / (1000 * 60 * 60 * 24)).toFixed(1));
  if (seconds < 60) {
      return `${seconds}sec`;
  } else if (minutes < 60) {
      return `${minutes}min`;
  } else if (hours < 24) {
      return `${hours}h`;
  } else {
      return `${days}d`
  }
}

enum SeverityLevel {
  INFORMATIONAL = "INFORMATIONAL",
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL"
}
type SeverityLevelStrings = keyof typeof SeverityLevel


enum TestStatus {
  SUCCEEDED = "SUCCEEDED",
  FAILED = "FAILED",
  PARTIALLY_FAILED = "PARTIALLY_FAILED",
  PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED",
  DISABLED = "DISABLED"
}



function resolveStatus(status: string) {
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
    default:
      return "UNKNOWN"
  }
}

function resolveSeverityLevel(level: string) {
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

function resolveSeverity(method: ITestMethodTable) {
  return `[S: ${resolveSeverityLevel(method.SecuritySeverity)}, I: ${resolveSeverityLevel(method.InteroperabilitySeverity)}]`
}

export function itemProvider(ctx: IItemProviderContext, reports: ITestResultContainer[]) {
  if (reports.length == 0) {
    return []
  }
  const items: any[] = [{
    testcase: "Succeeded tests"
  }, {
    testcase: "Failed tests"
  },{
    testcase: "Disabled tests"
  },{
    testcase: "Execution time"
  }]
  // build test case column first
  const descriptions = new Set<string>()
  const mapTestcaseNameToTestResultIndexes: { [className: string]: number[] } = {}
  const mapTestMethod: { [className: string]: ITestMethodTable } = {}

  for (let i = 0; i < reports.length; i++) {
    const report = reports[i]
    items[0][report.Identifier] = {statusIcons: report.SucceededTests}
    items[1][report.Identifier] = {statusIcons: report.FailedTests}
    items[2][report.Identifier] = {statusIcons: report.DisabledTests}
    items[3][report.Identifier] = {statusIcons: timeConversion(report.ElapsedTime)}

    for (let j = 0; j < report.TestResults.length; j++) {
      const result = <ITestResultTable>report.TestResults[j]
      let testCaseName = `${result.TestMethod.ClassName}.${result.TestMethod.MethodName}`.replace("de.rub.nds.tlstest.suite.tests.", "")
      result.TestMethod.testCaseName = testCaseName
      result.statusIcons = resolveStatus(result.Status)
      
      descriptions.add(testCaseName)
      if (!mapTestMethod[testCaseName]) {
        mapTestMethod[testCaseName] = result.TestMethod
      }

      let positions = mapTestcaseNameToTestResultIndexes[testCaseName]
      if (!positions) {
        positions = []
        mapTestcaseNameToTestResultIndexes[testCaseName] = positions;
      }
        
      while (positions.length < i) {
        positions.push(-1)
      }
      positions.push(j)
    }
  }

  const descriptionsArr = new Array(...descriptions)
  descriptionsArr.sort((a, b) => {
    if (mapTestcaseNameToTestResultIndexes[mapTestMethod[a].testCaseName].indexOf(-1) > 0 && mapTestcaseNameToTestResultIndexes[mapTestMethod[b].testCaseName].indexOf(-1) == -1) {
      // a is bigger -> sort to bottom
      return 1
    }
    if (mapTestcaseNameToTestResultIndexes[mapTestMethod[b].testCaseName].indexOf(-1) > 0 && mapTestcaseNameToTestResultIndexes[mapTestMethod[a].testCaseName].indexOf(-1) == -1) {
      // a is smaller -> sort to top
      return -1
    }

    if (mapTestMethod[a].testCaseName < mapTestMethod[b].testCaseName) {
      return -1
    } else if (mapTestMethod[b].testCaseName < mapTestMethod[a].testCaseName) {
      return 1
    }

    return 0
  })


  let oldTestClass = ""
  for (let testCase of descriptionsArr) {
    const testResultIndexes = mapTestcaseNameToTestResultIndexes[testCase]
    const testMethod = mapTestMethod[testCase]
    if (!filterTestMethod(testMethod, ctx.filter)) {
      continue
    }
    
    const item: any = {
      testcase: `&nbsp;&nbsp;&nbsp;&nbsp;${resolveSeverity(testMethod)} ${testMethod.MethodName}`
    }
    for (let i=0; i < reports.length; i++) {
      const report = reports[i]
      const testResultIndex = testResultIndexes[i]
      if (testResultIndex == -1 || report.TestResults[testResultIndex].Status == "DISABLED") {
        item[report.Identifier] = null
      } else {
        item[report.Identifier] = report.TestResults[testResultIndex]
      }
    }

    let onlyNull = true
    for (let i in item) {
      if (i === "testcase") continue
      if (item[i] != null) {
        onlyNull = false
        break
      }
    }

    if (onlyNull) {
      continue
    }

    if (testMethod.ClassName != oldTestClass) {
      oldTestClass = testMethod.ClassName
      items.push({
        testcase: oldTestClass.replace("de.rub.nds.tlstest.suite.tests.", ""),
      })
    }

    items.push(item)
  }

  return items
}


export function getRowClass(item: any[], options: {highlightDifferentStatus: boolean}) {
  let identical = true
  let hasStates = false
  let lastStatus = null
  const retClasses = []

  for (const i in item) {
    let result : ITestResult = item[i] 
    if (!result || !result.Status) continue

    if (result.States && result.States.length > 0) {
      hasStates = true
    }
      
    if (lastStatus == null) {
      lastStatus = result.Status
    }

    if (result.Status !== lastStatus) {
      identical = false
      break
    }

    lastStatus = result.Status
  }

  if (!identical && options.highlightDifferentStatus) {
    retClasses.push("differentStatus")
  }

  if (!hasStates) {
    retClasses.push("notSelectable")
  }

  return retClasses
}


export const allSeverityLevels = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.INFORMATIONAL, SeverityLevel.LOW, SeverityLevel.MEDIUM]
export const filterObj: IFilter = {
  security: [...allSeverityLevels],
  interoperability: [...allSeverityLevels],
}

export interface IFilter {
    security: SeverityLevelStrings[],
    interoperability: SeverityLevelStrings[]
}

export function filterTestMethod(testMethod: ITestMethodTable, filter: IFilter) {
  if (!filter)
    return true
  
  if (filter.interoperability.indexOf(<SeverityLevelStrings>testMethod.InteroperabilitySeverity) == -1) {
    return false
  }

  if (filter.security.indexOf(<SeverityLevelStrings>testMethod.SecuritySeverity) == -1) {
    return false
  }

  return true
}

