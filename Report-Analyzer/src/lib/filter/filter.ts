import { IState } from '../../backend/database/models';
import { ITestResultTable } from '../analyzer';
import { allResults, allSeverityLevels, CategoriesStrings, Optional, TestResult } from '../const';
import { Derivation, DerivationStrings } from '../const/Derivations';
import { FilterDataModels } from './filterDataModels';
import { FilterInputModels } from './filterInputModels';


export interface IStateTable extends IState {
  statusIcons: string
}


function isResultTableRow(a : Optional<any>): a is ResultTableRow {
  return a && a.testcase
}

function isStateTableRow(a : Optional<any>): a is StateTableRow {
  return a && a.uuid
}

function resolveOperator(op: FilterDataModels.Operator) {
  switch(op) {
    case "AND":
      return "&&"
    case "OR":
      return "||"
  }
  return ""
}

type ResultTableRow = {[identifier: string]: Optional<ITestResultTable>};
type StateTableRow = {[identifier: string]: Optional<IStateTable>};
type TableRow = ResultTableRow | StateTableRow



function filterRow<T>(evalTemplateString: string, valueExtractor: (i: T) => any, row: TableRow) : any[] {
  const results = []
  for (let column of Object.keys(row)) {
    const cell = row[column]
    if (column == 'testcase' || column == 'uuid' || !cell || Object.keys(cell).length < 2) continue
    let value = valueExtractor(<any>cell)
    if (value == null) {
      results.push(false)
      continue
    }

    let evalString = evalTemplateString.replace('{value}', JSON.stringify(value))
    results.push(eval(evalString))
  }

  if (results.length == 0) {
    results.push(true)
  }
  return results
}

export function filter(inputModel: FilterInputModels.ComposedModel, dataModel: FilterDataModels.Container[], row: TableRow) {

  const cleanedModel = FilterDataModels.cleanup(dataModel)
  if (cleanedModel.length == 0) {
    return true
  }

  if (Object.keys(row).length == 1 && (Object.keys(row)[0] == 'testcase' || Object.keys(row)[0] == 'uuid')) {
    return true
  }

  let show = true
  for (let key of Object.keys(row)) {
    const tmp = row[key]
    if (tmp && typeof tmp != "string") {
      show = show && Object.keys(tmp).length == 1
    }
  }

  if (show) {
    return true
  }

  const containerEvalString: string[] = [];

  for (const container of cleanedModel) {
    let conditionEvalString = []
    let conditionLength = 0

    for (const condition of container.conditions) {
      switch (condition.key!.type) {
        case "category": {
          if (isResultTableRow(row)) {
            let evalString = `{value}.indexOf('${condition.value}') > -1`
            let result = filterRow<ITestResultTable>(evalString, i => {
              if (!i.Score) return null;
              return Object.keys(i.Score)
            }, row).reduce((i, j) => i || j)
            if (condition.comparator == "!=") {
              result = !result
            }
            conditionEvalString.push(result.toString())
          }
        }
        break;

        case "property": {
          let evalString = "(() => {return {value}})()"
          if (condition.value === FilterInputModels.PropertyKeys.diffResults) {
            const results = filterRow<IStateTable | ITestResultTable>(evalString, i => {
              return i.Result
            }, row)
            const firstElem = results[0]
            let result = (results.filter(i => firstElem !== i).length > 0)
            if (condition.comparator == "!fullfills") {
              result = !result
            }
            conditionEvalString.push(result.toString())

          } else if (condition.value === FilterInputModels.PropertyKeys.diffStates && isResultTableRow(row)) {
            const uuids = new Set<string>()
            const results: {states: IState[], stateIndexMap: { [id: string] : number }}[] = filterRow<ITestResultTable>(evalString, i => {
              Object.keys(i.StateIndexMap).forEach(u => uuids.add(u))
              return {
                states: i.States,
                stateIndexMap: i.StateIndexMap
              }
            }, row)
            let result = true
            for (let uuid of uuids) {
              let v = null
              for (let r of results) {
                if (!r.stateIndexMap[uuid]) continue;
                let tr = r.states[r.stateIndexMap[uuid]].Result
                if (v == null) {
                  v = tr
                  continue
                }

                if (tr != v) {
                  result = false
                  break
                }
              }
              if (!result) {
                break
              }
            }
            if (condition.comparator == "!fullfills") {
              result = !result
            }
            conditionEvalString.push(result.toString())


          } else if (condition.value === FilterInputModels.PropertyKeys.hasAdditionalInfo && isStateTableRow(row)) {
            let result = filterRow<IStateTable>(`{value}.length > 0`, i => {
              return i.AdditionalResultInformation
            }, row).reduce((i, j) => i || j)
            if (condition.comparator == "!fullfills") {
              result = !result
            }
            conditionEvalString.push(result.toString())

          }
        }
        break;

        case "testResult": {
          let result = filterRow<IStateTable | ITestResultTable>(`{value} ${condition.comparator} ${condition.value}`, i => {
            let idx = allResults.indexOf(<TestResult>i.Result)
            if (idx == -1) {
              console.error(`${i.Result} is not a valid test result`)
              return null
            }
            return idx
          }, row).reduce((i,j) => i || j)
          conditionEvalString.push(result.toString())
        } 
        break;

        case "severity": {
          let category = <CategoriesStrings>condition.key!.mode!
          let result = filterRow<ITestResultTable>(`{value} ${condition.comparator} ${condition.value}`, i => {
            if (!i.Score) return null
            let severity = i.Score[category]?.SeverityLevel
            if (!severity) return null

            return allSeverityLevels.indexOf(severity)
          }, row).reduce((i,j) => i || j)
          conditionEvalString.push(result.toString())
        }
        break;

        case "derivation": {
          let derivationType = <DerivationStrings>condition.key!.mode!
          let evalString = `{value} ${condition.comparator} '${condition.value}'`
          if (condition.comparator == "contains") {
            evalString = `{value}.indexOf('${condition.value}') > -1`
          } else if (condition.comparator == "!contains") {
            evalString = `{value}.indexOf('${condition.value}') == -1`
          }

          let result = filterRow<IStateTable>(evalString, i => {
            return i.TlsParameterCombination[derivationType]
          }, row).reduce((i, j) => i || j)
          conditionEvalString.push(result.toString())
        }  
        break;
        
        case "additionalResultInformation": {
          let evalString = ``
          if (condition.comparator == "==") {
            evalString = `{value}.indexOf('${condition.value}') > -1`
          } else if (condition.comparator == "!=") {
            evalString = `{value}.indexOf('${condition.value}') == -1`
          }

          let result = filterRow<IStateTable>(evalString, i => {
            return i.AdditionalResultInformation.split(";").map((j) => j.trim())
          }, row).reduce((i, j) => i || j)
          conditionEvalString.push(result.toString())
        }
        break;

        case "additionalTestInformation": {
          let evalString = ``
          if (condition.comparator == "==") {
            evalString = `{value}.indexOf('${condition.value}') > -1`
          } else if (condition.comparator == "!=") {
            evalString = `{value}.indexOf('${condition.value}') == -1`
          }

          let result = filterRow<IStateTable>(evalString, i => {
            return i.AdditionalTestInformation.split(";").map((j) => j.trim())
          }, row).reduce((i, j) => i || j)
          conditionEvalString.push(result.toString())
        }
        break;
      }

      if (conditionEvalString.length > conditionLength) {
        conditionEvalString.push(resolveOperator(condition.operator))
      }
    }

    let conditionResult = eval(conditionEvalString.join(''))
    containerEvalString.push(conditionResult.toString())
    containerEvalString.push(resolveOperator(container.operator))
  }

  return eval(containerEvalString.join(''))
}


