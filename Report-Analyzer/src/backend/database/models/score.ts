import { SeverityLevel } from '../../../lib/const';


export interface IScore {
  Total: number,
  Reached: number,
  Percentage: number,
  SeverityLevel: SeverityLevel
}

export interface IScoreMap {
  INTEROPERABILITY: IScore,
  SECURITY: IScore,
  COMPLIANCE: IScore
}


export const ScoreSchemaObject = {
  Total: Number,
  Reached: Number,
  Percentage: Number,
  SeverityLevel: String
}


export const ScoreMapSchmaObject = {
  INTEROPERABILITY: ScoreSchemaObject,
  SECURITY: ScoreSchemaObject,
  COMPLIANCE: ScoreSchemaObject
}

