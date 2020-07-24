import { ITestMethod, ITestResult, ITestResultContainer } from '@/backend/database/models';
import { HighlightOptions, HighlightOptionsStrings, resolveSeverityLevel, IItemProviderContext, Optional, resolveStatus, ISeverityFilter, allSeverityLevels, SeverityLevelStrings, allStatus, TestStatus, TestStatusStrings } from './const';
import { filter } from 'vue/types/umd';

interface ITestResultTable extends ITestResult {
  statusIcons: string
}

//@ts-ignore
interface ITestResultContainerBrowser extends ITestResultContainer {
  TestResultClassMethodIndexMap: {[key: string]: number}
}

export const differenceFilterOptions = [
  { text: "Different test results", value: HighlightOptions.differentStatus },
  { text: "Different states", value: HighlightOptions.differentStates }
]

export const hightlightOptions = [
  { text: "None", value: null },
  ...differenceFilterOptions
]

interface IFilter {
  severity: ISeverityFilter,
  status: TestStatus[],
  properties: any[]
}

export const filterObj: IFilter = {
  severity: {
    security: [...allSeverityLevels],
    interoperability: [...allSeverityLevels],
  },
  status: [...allStatus],
  properties: [HighlightOptions.differentStatus, HighlightOptions.differentStates]
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


function resolveSeverity(method: ITestMethod) {
  return `[S: ${resolveSeverityLevel(method.SecuritySeverity)}, I: ${resolveSeverityLevel(method.InteroperabilitySeverity)}]`
}

export function itemProvider(ctx: IItemProviderContext, reports: ITestResultContainerBrowser[]) {
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
  const resultIndexReportMap = new Map<string, number[]>()

  for (let i = 0; i < reports.length; i++) {
    const report = reports[i]
    items[0][report.Identifier] = {statusIcons: report.SucceededTests}
    items[1][report.Identifier] = {statusIcons: report.FailedTests}
    items[2][report.Identifier] = {statusIcons: report.DisabledTests}
    items[3][report.Identifier] = {statusIcons: timeConversion(report.ElapsedTime)}

    for (let testMethod of Object.keys(report.TestResultClassMethodIndexMap)) {
      descriptions.add(testMethod)
      let positions = resultIndexReportMap.get(testMethod)
      if (!positions) {
        positions = []
        resultIndexReportMap.set(testMethod, positions)
      }

      while (positions.length < i) {
        positions.push(-1)
      }
      positions.push(report.TestResultClassMethodIndexMap[testMethod])
    }
  }

  const descriptionsArr = new Array(...descriptions)
  descriptionsArr.sort((a, b) => {
    if (resultIndexReportMap.get(a)!.includes(-1) && !resultIndexReportMap.get(b)!.includes(-1)) {
      // a is bigger -> sort to bottom
      return 1
    }
    if (resultIndexReportMap.get(b)!.includes(-1) && !resultIndexReportMap.get(a)!.includes(-1)) {
      // a is smaller -> sort to top
      return -1
    }

    if (a < b) {
      return -1
    } else if (b < a) {
      return 1
    }

    return 0
  })


  let oldTestClass = ""
  for (let testCase of descriptionsArr) {
    const testResultIndexes = resultIndexReportMap.get(testCase)!
    let testMethod : Optional<ITestMethod> = null
    for (let idx in testResultIndexes) {
      let elem = testResultIndexes[idx]
      if (elem != -1) {
        testMethod = reports[idx].TestResults[elem].TestMethod
        break
      }
    }

    if (!testMethod || !filterTestMethod(testMethod, ctx.filter)) {
      continue
    }
    
    const item: any = {
      testcase: {
        value: `&nbsp;&nbsp;&nbsp;&nbsp;${resolveSeverity(testMethod)} ${testMethod.MethodName}`,
        TestMethod: testMethod
      }
    }
    for (let i=0; i < reports.length; i++) {
      const report = reports[i]
      const testResultIndex = testResultIndexes[i]
      if (testResultIndex == -1 || report.TestResults[testResultIndex].Status == "DISABLED") {
        item[report.Identifier] = null
      } else {
        const result = <ITestResultTable>report.TestResults[testResultIndex]
        result.statusIcons = resolveStatus(result.Status)
        item[report.Identifier] = result
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
        testcase: {
          value: oldTestClass.replace("de.rub.nds.tlstest.suite.tests.", "")
        }
      })
    }

    if (filterRowItem(item, ctx.filter)) {
      items.push(item)
    }
  }

  return items
}


export function getRowClass(item: any[], highlightOption: HighlightOptionsStrings) {
  let identical = true
  let hasStates = false
  let lastStatus = null
  const retClasses = []
  const states: {[key: string]: string} = {}
  let differentStates = false

  for (const i in item) {
    let result : ITestResult = item[i] 
    if (!result || !result.Status || i == 'testcase') continue

    for (const state of result.States) {
      if (states[state.uuid] && states[state.uuid] != state.Status) {
        differentStates = true
        break
      } else if (!states[state.uuid]) {
        states[state.uuid] = state.Status
      }
    }

    if (result.States.length > 0) {
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

  if (!identical && highlightOption == HighlightOptions.differentStatus) {
    retClasses.push("highlight")
  }

  if (differentStates && highlightOption == HighlightOptions.differentStates) {
    retClasses.push("highlight")
  }

  if (!hasStates) {
    retClasses.push("notSelectable")
  }

  return retClasses
}



function filterTestMethod(testMethod: ITestMethod, filter: IFilter): boolean {
  if (!filter)
    return true
  
  if (filter.severity.interoperability.indexOf(<SeverityLevelStrings>testMethod.InteroperabilitySeverity) == -1) {
    return false
  }

  if (filter.severity.security.indexOf(<SeverityLevelStrings>testMethod.SecuritySeverity) == -1) {
    return false
  }

  return true
}

function filterRowItem(item: any, filter: IFilter): boolean {
  let ret = false
  for (const key in item) {
    if (key == 'testcase' || !item[key]) continue

    const result : ITestResultTable = item[key]
    if (filter.status.length == allStatus.length) {
      ret = true
      break
    } else if (filter.status.length < allStatus.length && filter.status.includes(<TestStatus>result.Status)) {
      ret = true
      break
    }
  }

  if (!filter.properties.includes(HighlightOptions.differentStates)) {
    ret = ret && getRowClass(item, HighlightOptions.differentStatus).includes('highlight')
  }
  
  if (!filter.properties.includes(HighlightOptions.differentStatus)) {
    ret = ret && getRowClass(item, HighlightOptions.differentStates).includes('highlight')
  }

  return ret
}

