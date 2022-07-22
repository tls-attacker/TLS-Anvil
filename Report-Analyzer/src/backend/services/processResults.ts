import { IState, ITestResult, ITestResultContainer } from '../database/models';
import { allResults, IItemProviderContext, Optional, resolveStatus, TestResult } from '../../lib/const';


export interface TableRow {
  [identifier: string] : {
    value: string,
    isHead: boolean,
    data: any
  }
}

export interface Result {
  filterData: {
    additionalResultInformationSet: string[]
    additionalTestInformationSet: string[]
    derivationsSet: string[]
    derivationValues: {[derivation: string]: string[]}
  }
  tableData: TableRow[]
  resultData: {[identifier: string]: ITestResult}
}


export function process(results: ITestResult[], identifiers: {_id: string, Identifier: string}[]): Result {
  if (results.length == 0) {
    throw new Error("no results...")
  }

  const items: TableRow[] = [{
    rowHead: {
      value: "Strictly Succeeded",
      isHead: true,
      data: null,
    }
  }, {
    rowHead: {
      value: "Conceptually Succeeded",
      isHead: true,
      data: null,
    }
  }, {
    rowHead: {
      value: "Fully Failed",
      isHead: true,
      data: null,
    }
  }, {
    rowHead: {
      value: "Partially Failed",
      isHead: true,
      data: null
    }
  }, {
    rowHead: {
      value: "Overall Result",
      isHead: true,
      data: null
    }
  }, {
    rowHead: {
      value: "Edited",
      isHead: true,
      data: null
    }
  }
]


  const uuidSet = new Set<string>()
  const derivationsSet = new Set<string>()
  const derivationValues: {[derivation: string]: Set<string>} = {}
  const additionalResultInfformationSet = new Set<string>()
  const additionalTestInformationSet = new Set<string>()
  const restultStateIndexMap = new Map<string, number[]>()
  const resultData: {[identfier: string]: ITestResult} = {}

  for (let i = 0; i < results.length; i++) {
    const result = results[i]
    const r_copy = JSON.parse(JSON.stringify(result))
    delete r_copy.States
    delete r_copy.StateIndexMap

    const identifier = identifiers.filter(d => d._id.toString() == result.ContainerId.toString())[0].Identifier
    resultData[identifier] = r_copy

    items[0][identifier] = {isHead: true, data: null, value: result.States.filter((j) => j.Result == TestResult.STRICTLY_SUCCEEDED).length.toString()}
    items[1][identifier] = {isHead: true, data: null, value: result.States.filter((j) => j.Result == TestResult.CONCEPTUALLY_SUCCEEDED).length.toString()}
    items[2][identifier] = {isHead: true, data: null, value: result.States.filter((j) => j.Result == TestResult.FULLY_FAILED).length.toString()}
    items[3][identifier] = {isHead: true, data: null, value: result.States.filter((j) => j.Result == TestResult.PARTIALLY_FAILED).length.toString()}
    items[4][identifier] = {isHead: true, data: null, value: resolveStatus(result.Result)}
    items[5][identifier] = {isHead: true, data: result.appliedEdit, value: result.edited ? '✅' : ''}

    for (const state of result.States) {
      for (const derivation in state.DerivationContainer) {
        derivationsSet.add(derivation)
        if (!derivationValues[derivation]) {
          derivationValues[derivation] = new Set<string>()
        }
        derivationValues[derivation].add(state.DerivationContainer[derivation])
      }

      state.AdditionalResultInformation.split(/;|\n/).filter(i => i !== "").forEach(i => additionalResultInfformationSet.add(i))
      state.AdditionalTestInformation.split(/;|\n/).filter(i => i !== "").forEach(i => additionalTestInformationSet.add(i))

      uuidSet.add(state.uuid)
      let positions = restultStateIndexMap.get(state.uuid)
      if (!positions) {
        positions = Array.apply(null, Array(results.length)).map(() => -1)
        restultStateIndexMap.set(state.uuid, positions)
      }

      positions[i] = result.StateIndexMap[state.uuid]
    }
  }

  items.push({rowHead: {value: "", isHead: true, data: null}})

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

    const item: TableRow = {
      rowHead: {
        value: uuid,
        isHead: false,
        data: null
      }
    }

    for (let i3 = 0; i3 < positions.length; i3++) {
      const position = positions[i3]
      const identifier = identifiers[i3].Identifier

      item[identifier] = {
        value: "",
        data: null,
        isHead: false
      }

      if (position != -1) {
        const state = results[i3].States[position]

        item[identifier].value = resolveStatus(state.Result)
        item[identifier].data = state
        if (state.AdditionalResultInformation) {
          item[identifier].value += "❗️"
        }
      }
    }

    items.push(item)
  }
  
  Object.keys(derivationValues).forEach(element => {
    const a = Array.from(derivationValues[element])
    a.sort((a: any, b: any) => {
      const an = parseInt(a)
      const bn = parseInt(b)
      if (!isNaN(an) && !isNaN(bn)) return an-bn
      if (an == bn) return 0
      if (an > bn) return 1
      return -1
    })
    
    derivationValues[element] = <any>a
  });

  return {
    filterData: {
      additionalResultInformationSet: Array.from(additionalResultInfformationSet).sort(),
      additionalTestInformationSet: Array.from(additionalTestInformationSet).sort(),
      derivationsSet: Array.from(derivationsSet).sort(),
      derivationValues: <any>derivationValues
    },
    tableData: items,
    resultData: resultData
  }
}
