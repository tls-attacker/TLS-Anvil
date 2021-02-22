import { Schema, Document } from "mongoose";
import { ITestResult } from './testResult';
import { ITestResultContainer } from './testResultContainer';
export interface IState extends Document {
  TestResultId: ITestResult['_id']
  ContainerId: ITestResultContainer['_id']
  DerivationContainer: {[identifier: string] : string}
  DisplayName: string
  Result: string
  AdditionalResultInformation: string
  AdditionalTestInformation: string
  SrcPort: number
  DstPort: number
  StartTimestamp: string
  EndTimestamp: string
  uuid: string
  Stacktrace?: string
}

export const StateSchema = new Schema({
  TestResultId: {
    type: Schema.Types.ObjectId,
    ref: 'TestResult',
    required: true,
  },
  ContainerId: {
    type: Schema.Types.ObjectId,
    ref: 'TestContainer',
    required: true,
  },
  DerivationContainer: {
    type: Schema.Types.Map,
    of: String,
    default: new Map()
  },
  DisplayName: String,
  Result: String,
  AdditionalResultInformation: String,
  AdditionalTestInformation: String,
  SrcPort: Number,
  DstPort: Number,
  StartTimestamp: String,
  EndTimestamp: String,
  uuid: String,
  Stacktrace: String
})

StateSchema.index({TestResultId: 1})
StateSchema.index({ContainerId: 1})
StateSchema.index({Result: 1})
StateSchema.index({AdditionalResultInformation: 1})
StateSchema.index({Stacktrace: 1})
