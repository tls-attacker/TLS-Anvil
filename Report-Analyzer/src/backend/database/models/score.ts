import { SeverityLevel, CategoriesStrings, TestResult, score, ScoreCategories } from '../../../lib/const';


export interface IScore {
  Total: number,
  Reached: number,
  Percentage: number,
  SeverityLevel: SeverityLevel
}

export type IScoreMap = {
  [identifier in CategoriesStrings]: IScore;
};

export type IScoreDeltaMap = {
  [i in CategoriesStrings]?: {
    TotalDelta: number;
    ReachedDelta: number;
  };
};


export const ScoreSchemaObject = {
  Total: Number,
  Reached: Number,
  Percentage: Number,
  SeverityLevel: String
}


export const ScoreMapSchmaObject = {
  ALERT: ScoreSchemaObject,
  CVE: ScoreSchemaObject,
  CERTIFICATE: ScoreSchemaObject,
  CRYPTO: ScoreSchemaObject,
  DEPRECATED: ScoreSchemaObject,
  HANDSHAKE: ScoreSchemaObject,
  MESSAGESTRUCTURE: ScoreSchemaObject,
  RECORDLAYER: ScoreSchemaObject,
  INTEROPERABILITY: ScoreSchemaObject,
  SECURITY: ScoreSchemaObject,
  COMPLIANCE: ScoreSchemaObject
}


export function calculateScoreDelta(scoreMap: IScoreMap, newResult: TestResult): IScoreDeltaMap {
  const r: IScoreDeltaMap = {}

  for (const [key, value] of Object.entries(scoreMap)) {
    const newReached = score(value.SeverityLevel, newResult)
    const reachedDelta = newReached - value.Reached
    
    const newTotal = newResult === TestResult.DISABLED ? 0 : score(value.SeverityLevel, TestResult.STRICTLY_SUCCEEDED)
    const totalDelta =  newTotal - value.Total

    r[<CategoriesStrings>key] = {
      TotalDelta: totalDelta,
      ReachedDelta: reachedDelta
    }

    const tmp = scoreMap[<CategoriesStrings>key]
    tmp.Reached += reachedDelta
    tmp.Total += totalDelta
    tmp.Percentage = tmp.Reached / tmp.Total * 100
  }

  return r
}

