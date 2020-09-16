import { Schema, Document } from "mongoose";
import { ITestResult } from './testResult';
import { ITestResultContainer } from './testResultContainer';
export interface IState extends Document {
  TestResultId: ITestResult['_id']
  ContainerId: ITestResultContainer['_id']
  TransformationDescription: string,
  Status: string,
  InspectedCiphersuite: string,
  TransformationParentUuid?: string,
  AdditionalResultInformation: string,
  AdditionalTestInformation: string,
  SrcPort: number,
  DstPort: number,
  StartTimestamp: string,
  EndTimestamp: string,
  uuid: string,
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
  TransformationDescription: String,
  Status: String,
  InspectedCiphersuite: String,
  TransformationParentUuid: String,
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
StateSchema.index({Status: 1})
StateSchema.index({AdditionalResultInformation: 1})
StateSchema.index({Stacktrace: 1})
