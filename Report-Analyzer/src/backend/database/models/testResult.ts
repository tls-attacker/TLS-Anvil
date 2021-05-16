import { IState, StateSchema } from "./state";
import { ITestMethod, TestMethodSchemaObject } from "./testMethod";
import { Schema, Document } from 'mongoose';
import { ITestResultContainer } from './testResultContainer';
import { IScoreMap, ScoreMapSchmaObject } from './score';
import { ITestResultEdit } from './testResultEdit';

export interface ITestResult extends Document {
  ContainerId: ITestResultContainer['_id'],
  TestMethod: ITestMethod,
  Result: string,
  HasStateWithAdditionalResultInformation: boolean,
  HasVaryingAdditionalResultInformation: boolean,
  DisabledReason?: string,
  FailedReason?: string,
  FailedStacktrace?: string,
  ElapsedTime: number,
  States: IState[],
  StatesCount: number,
  StateIndexMap: {[key: string] : number},
  Score: IScoreMap,
  FailureInducingCombinations: {[key: string] : string}[],

  // not persisted in the database,
  edited: boolean
  appliedEdit: ITestResultEdit
  matchingEdits: ITestResultEdit[]
}

export const TestResultSchema = new Schema({
  ContainerId: {
    type: Schema.Types.ObjectId,
    ref: 'TestContainer',
    required: true
  },
  TestMethod: TestMethodSchemaObject,
  Result: String,
  HasStateWithAdditionalResultInformation: Boolean,
  HasVaryingAdditionalResultInformation: Boolean,
  DisabledReason: String,
  FailedReason: String,
  FailedStacktrace: String,
  ElapsedTime: Number,
  States: [{
    type: Schema.Types.ObjectId,
    ref: 'TestResultState',
  }],
  StatesCount: Number,
  StateIndexMap: {
    type: Schema.Types.Map,
    of: Number,
    default: new Map()
  },
  Score: ScoreMapSchmaObject,
  FailureInducingCombinations: [{
    type: Schema.Types.Map,
    of: String,
    default: new Map()
  }]
})


TestResultSchema.index({Result: 1})

// This index also helps with searches just for ContainerId
// https://docs.mongodb.com/manual/core/index-compound/
TestResultSchema.index({ContainerId: 1, "TestMethod.ClassName": 1, "TestMethod.MethodName": 1})
