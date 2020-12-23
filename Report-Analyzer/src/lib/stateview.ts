import { IState, ITestResult, ITestResultContainer } from '../backend/database/models';
import { allResults, IItemProviderContext, Optional, resolveStatus, TestResult } from './const';

//@ts-ignore
interface ITestResultContainerBrowser extends ITestResultContainer {
  TestResultClassMethodIndexMap: {[key: string]: number}
}

//@ts-ignore
interface ITestResultTable extends ITestResult {
  Identifier: string
  StateIndexMap: {[key: string]: number}
}

export interface IStateTable extends IState {
  statusIcons: string
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
    items[0][result.Identifier] = {statusIcons: result.States.filter((j) => j.Result == TestResult.SUCCEEDED).length}
    items[1][result.Identifier] = {statusIcons: result.States.filter((j) => j.Result == TestResult.PARTIALLY_SUCCEEDED).length}
    items[2][result.Identifier] = {statusIcons: result.States.filter((j) => j.Result == TestResult.FAILED).length}
    items[3][result.Identifier] = {statusIcons: result.States.filter((j) => j.Result == TestResult.PARTIALLY_FAILED).length}

    for (const state of result.States) {
      uuidSet.add(state.uuid)

      let positions = restultStateIndexMap.get(state.uuid)
      if (!positions) {
        positions = Array.apply(null, Array(results.length)).map(() => -1)
        restultStateIndexMap.set(state.uuid, positions)
      }

      positions[i] = result.StateIndexMap[state.uuid]
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

    if ((!positionsA && !positionsB) || (restultStateIndexMap.get(b)?.includes(-1) && restultStateIndexMap.get(a)?.includes(-1))) {
      if (positionsA && positionsB) {
        const lA = positionsA.filter(i => i == -1).length
        const lB = positionsB.filter(i => i == -1).length
        if (lA < lB) return -1
        if (lB < lA) return 1
      }
    }
      

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

        column.statusIcons = resolveStatus(column.Result)
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

    items.push(item)
  }
  
  return items
}


export function getRowClass(item: any[]) {
  if (!item) return []

  const classes = []

  if (Object.keys(item).length == 1) {
    classes.push("newClass", "stickyColumn")
  }

  for (const key in item) {
    if (key == "uuid") continue
    const state : Optional<IStateTable> = item[key]

    if (state && !state.Result) {
      // if the state does not exists for the target, it is null
      classes.push("notSelectable")
      break 
    }
  }

  return classes
}
