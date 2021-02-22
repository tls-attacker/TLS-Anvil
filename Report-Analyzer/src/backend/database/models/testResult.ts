import { IState, StateSchema } from "./state";
import { ITestMethod, TestMethodSchemaObject } from "./testMethod";
import { Schema, Document } from 'mongoose';
import { ITestResultContainer } from './testResultContainer';
import { IScoreMap, ScoreMapSchmaObject } from './score';

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
  StateIndexMap: Map<string, number>,
  Score: IScoreMap,
  FailureInducingCombinations: Map<string, string>[]
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

TestResultSchema.index({ContainerId: 1})
TestResultSchema.index({Result: 1})
