import { CategoriesStrings } from '../const';
import { DerivationStrings } from '../const/Derivations';
import { FilterInputModels } from './filterInputModels';


export namespace FilterDataModels {
  export type Operator = "AND" | "OR" | "ADD"

  export interface Container {
    operator: Operator
    conditions: Condition[]
    addBtnStyle: any
  }

  export interface Condition {
    key?: {
      type: FilterInputModels.ModelName
      mode?: FilterInputModels.ModeName
    }
    value: string
    comparator: FilterInputModels.Comparator
    operator: Operator
    addBtnStyle: any
  }


  export function cleanup(containers: Container[]): Container[] {
    const copy: Container[] = <Container[]>JSON.parse(JSON.stringify(containers))

    const clean1 = copy.map((container) => {
      container.conditions = container.conditions.filter((condition) => {
        return !!condition.key
      })
      return container
    }).filter((container: Container) => {
      return container.conditions.length > 0
    })

    if (clean1.length > 0) {
      clean1[clean1.length - 1].operator = "ADD"
      for (let c of clean1) {
        c.conditions[c.conditions.length - 1].operator = "ADD"
      }
    }

    return clean1
  }
}

