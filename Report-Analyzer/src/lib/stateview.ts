import { IState, ITestResult, ITestResultContainer } from '@/backend/database/models';
import { allStatus, HighlightOptions, HighlightOptionsStrings, IItemProviderContext, Optional, resolveStatus, TestStatus } from './const';

//@ts-ignore
interface ITestResultContainerBrowser extends ITestResultContainer {
  TestResultClassMethodIndexMap: {[key: string]: number}
}

//@ts-ignore
interface ITestResultTable extends ITestResult {
  Identifier: string
  StateIndexMap: {[key: string]: number}
}

interface IStateTable extends IState {
  statusIcons: string
}

interface IFilter {
  status: TestStatus[]
  properties: string[]
}

export const hightlightOptions = [
  {text: "None", value: null},
  {text: "Different status", value: HighlightOptions.differentStates}
]

const additionalInformationFilter = "ADDITIONAL_INFORMATION"

export const differenceFilterOptions = [
  {text: "Different status", value: HighlightOptions.differentStates},
  {text: "Additional information", value: additionalInformationFilter}
]

export const filterObj: IFilter = {
  status: [...allStatus],
  properties: []
}


export function itemProvider(ctx: IItemProviderContext, results: ITestResultTable[]): any[] {
  if (results.length == 0) {
    return []
  }

  const items: any[] = [{
    uuid: "Succeeded"
  }, {
    uuid: "Partially Succeeded"
  }, {
    uuid: "Failed"
  }, {
    uuid: "Partially Failed"
  }]


  const uuidSet = new Set<string>()
  const restultStateIndexMap = new Map<string, number[]>()

  for (let i = 0; i < results.length; i++) {
    const result = results[i]
    items[0][result.Identifier] = {statusIcons: result.States.filter((j) => j.Status == TestStatus.SUCCEEDED).length}
    items[1][result.Identifier] = {statusIcons: result.States.filter((j) => j.Status == TestStatus.PARTIALLY_SUCCEEDED).length}
    items[2][result.Identifier] = {statusIcons: result.States.filter((j) => j.Status == TestStatus.FAILED).length}
    items[3][result.Identifier] = {statusIcons: result.States.filter((j) => j.Status == TestStatus.PARTIALLY_FAILED).length}

    for (const state of result.States) {
      uuidSet.add(state.uuid)

      let positions = restultStateIndexMap.get(state.uuid)
      if (!positions) {
        positions = []
        restultStateIndexMap.set(state.uuid, positions)
      }

      while (positions.length < i) {
        positions.push(-1)
      }
      positions.push(result.StateIndexMap[state.uuid])
    }
  }

  items.push({uuid: ""})

  const uuidArr = [...uuidSet]

  uuidArr.sort((a, b) => {
    const positionsA = restultStateIndexMap.get(a)
    const positionsB = restultStateIndexMap.get(b)
    if ((!positionsA && positionsB) || (restultStateIndexMap.get(a)?.includes(-1) && !restultStateIndexMap.get(b)?.includes(-1))) {
      return 1
    }

    if ((positionsA && !positionsB) || (restultStateIndexMap.get(b)?.includes(-1) && !restultStateIndexMap.get(a)?.includes(-1))) {
      return -1
    }

    if ((!positionsA && !positionsB) || (restultStateIndexMap.get(b)?.includes(-1) && restultStateIndexMap.get(a)?.includes(-1)))
      return 0

    let resultA = null
    for (const a of positionsA!) {
      if (a != -1) {
        resultA = results[positionsA!.indexOf(a)].States[a]
        break
      }
    }

    let resultB = null
    for (const b of positionsB!) {
      if (b != -1) {
        resultB = results[positionsB!.indexOf(b)].States[b]
        break
      }
    }

    if (resultA?.TransformationDescription && resultB?.TransformationDescription) {
      if (resultA.TransformationDescription == resultB.TransformationDescription) {
        return 0
      } else if (resultA.TransformationDescription < resultB.TransformationDescription) {
        return -1
      } else {
        return 1
      }
    }
    if (resultA?.TransformationDescription && !resultB?.TransformationDescription) {
      return 1
    }
    if (!resultA?.TransformationDescription && resultB?.TransformationDescription) {
      return -1
    }

    if (a < b) {
      return -1
    } else if (b < a) {
      return 1
    }

    return 0
  })


  for (const uuid of uuidArr) {
    const positions = restultStateIndexMap.get(uuid)!

    const item: any = {
      uuid: {
        value: uuid,
        state: null
      }
    }

    for (let i3 = 0; i3 < positions.length; i3++) {
      const position = positions[i3]

      if (position != -1) {
        const column = <IStateTable>results[i3].States[position]

        column.statusIcons = resolveStatus(column.Status)
        if (column.AdditionalResultInformation) {
          column.statusIcons += "❗️"
        }
        item[results[i3].Identifier] = column
        if (!item.uuid.state) {
          item.uuid.state = column
        }
      } else {
        item[results[i3].Identifier] = null
      }
    }

    if (filterRowItem(item, ctx.filter)) {
      items.push(item)
    }
  }
  
  return items
}


export function getRowClass(item: any[], highlightOption: HighlightOptionsStrings) {
  if (!item) return []

  const classes = []

  if (Object.keys(item).length == 1) {
    classes.push("newClass", "stickyColumn")
  }

  let lastStatus = null
  for (const key in item) {
    if (key == "uuid") continue
    const state : Optional<IStateTable> = item[key]

    if (state && !state.Status) {
      // if the state does not exists for the target, it is null
      classes.push("notSelectable")
      break 
    }

    if (state && state.Status != lastStatus) {
      if (!lastStatus) {
        lastStatus = state.Status
      } else if (highlightOption == HighlightOptions.differentStates) {
        classes.push("highlight")
        break
      }
    }
  }

  return classes
}


function filterRowItem(item: any, filter: IFilter): boolean {
  let ret = true
  for (const key in item) {
    if (key == "uuid" || !item[key]) continue

    const result : IStateTable = item[key]
    if (filter.status.includes(<TestStatus>result.Status)) {
      ret = ret && true
    }

    if (filter.properties.includes(additionalInformationFilter) && !result.AdditionalResultInformation) {
      return false
    }
  }

  if (filter.properties.includes(HighlightOptions.differentStates)) {
    ret = ret && getRowClass(item, HighlightOptions.differentStates).includes('highlight')
  }

  return ret
}