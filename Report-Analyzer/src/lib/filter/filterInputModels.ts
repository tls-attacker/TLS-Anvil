import { allResults, allSeverityLevels } from '../const'
import { Derivation, DerivationStrings } from '../const/Derivations'
import { allScoreCategories, CategoriesStrings, ScoreCategories } from '../const/ScoreCategories'



export namespace FilterInputModels {
  export type Comparator = "==" | "!=" | "<" | "<=" | ">" | ">=" | "fullfills" | "!fullfills" | "contains" | "!contains"
  export type ComposedModel = Model[]
  export type ModelName = "category" | "testResult" | "property" | "derivation" | "severity" | "additionalResultInformation" | "additionalTestInformation"
  export type ModeName = DerivationStrings | CategoriesStrings
  export enum PropertyKeys {
    diffResults = "diffResults",
    diffStates = "diffStates",
    hasAdditionalInfo = "hasAdditionalInfo"
  }
  
  export namespace Comparator {
    export const eq: Comparator = "=="
    export const neq: Comparator = "!="
    export const lt: Comparator = "<"
    export const lte: Comparator = "<="
    export const gt: Comparator = ">"
    export const gte: Comparator = ">="
    export const fullfills: Comparator = "fullfills"
    export const contains: Comparator = "contains"
    export const all: Comparator[] = [eq, neq, lt, lte, gt, gte]
    export const constants: Comparator[] = [eq, neq]
  }

  export interface Model {
    key: {
      type: ModelName,
      mode?: ModeName
    }
    displayName: string,
    type: 'selector' | 'text'
    values: string[] | {value: any, text: string}[]
    comparators: Comparator[] | Comparator
  }

  const category: Model = {
    key: {type: "category"},
    displayName: "Category",
    type: "selector",
    values: allScoreCategories,
    comparators: Comparator.constants
  }

  const testResult: Model = {
    key: {type: "testResult"},
    displayName: "Test Result",
    type: "selector",
    values: allResults.map((i, idx) => {
      return {text: i, value: idx}
    }),
    comparators: Comparator.all
  }

  const propertyAnalyzer: Model = {
    key: {type: "property"},
    displayName: "Property",
    type: "selector",
    values: [
      { text: "Different results", value: PropertyKeys.diffResults },
      { text: "Different states", value: PropertyKeys.diffStates }
    ],
    comparators: [
      "fullfills",
      "!fullfills"
    ]
  }

  const propertyState: Model = {
    key: {type: "property"},
    displayName: "Property",
    type: "selector",
    values: [
      { text: "Different results", value: PropertyKeys.diffResults },
      { text: "Has additional information", value: PropertyKeys.hasAdditionalInfo },
    ],
    comparators: [
      "fullfills",
      "!fullfills"
    ]
  }

  const severities: Model[] = []
  for (let cat of allScoreCategories) {
    severities.push({
      key: {type: "severity", mode: cat},
      displayName: cat,
      type: "selector",
      values: allSeverityLevels.map((i, idx) => {
        return {text: i, value: idx}  
      }),
      comparators: Comparator.all
    })
  }


  export const analyzer: ComposedModel = [
    category,
    testResult,
    propertyAnalyzer,
    ...severities
  ]

  export const states: ComposedModel = [
    testResult,
    propertyState
    // missing, is added in StateView.vue: 
    //  * Derivation container values
    //  * Additional test information values
    //  * Additional result information values
  ]

}

